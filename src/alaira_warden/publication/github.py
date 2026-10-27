"""Host-side publication: no credential enters the project or execution container."""

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import quote, urlencode

from alaira_warden.intelligence.http import UrllibTransport, WorkBudget, request_json
from alaira_warden.publication.review import assert_approved, binding


def push_commit(
    repository: Path, artifact: dict, destination: str, token: str, *, authorized_repository: Path
):
    """Push an existing immutable commit via a clean bare staging repository.

    The destination and artifact must already have passed publication approval.
    A lease only permits creation, never replacement, of the Warden branch.
    """
    repository = repository.resolve(strict=True)
    if repository != authorized_repository.resolve(strict=True):
        raise PermissionError("Repository is outside the authorized application")
    binding(artifact, destination, "main")  # also validates branch, SHA and destination syntax
    from alaira_warden.remediation.pipeline import verify_artifact

    verify_artifact(artifact, repository)
    with tempfile.TemporaryDirectory(prefix="warden-publish-") as temporary:
        root = Path(temporary)
        env = {
            k: v
            for k, v in os.environ.items()
            if k.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
        }
        env.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
            }
        )

        def git(*args):
            result = subprocess.run(
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "credential.helper=",
                    "-c",
                    "http.followRedirects=false",
                    *args,
                ],
                cwd=root,
                env=env,
                capture_output=True,
                timeout=90,
            )
            if result.returncode:
                # Git output may contain provider details; never expose it or the environment.
                raise RuntimeError("Git publication failed; retry must reconcile the remote ref")

        git("init", "--bare", "objects.git")
        git(
            "--git-dir=objects.git",
            "-c",
            "protocol.file.allow=always",
            "fetch",
            "--no-tags",
            str(repository),
            artifact["proposed_sha"],
        )
        script = root / "askpass.py"
        script.write_text(
            "import os\nprint(os.environ['WARDEN_PUBLISH_TOKEN'])\n", encoding="utf-8"
        )
        wrapper = root / ("askpass.cmd" if os.name == "nt" else "askpass.sh")
        wrapper.write_text(
            (
                f'@echo off\n@"{sys.executable}" "{script}"\n'
                if os.name == "nt"
                else f'#!/bin/sh\nexec "{sys.executable}" "{script}"\n'
            ),
            encoding="utf-8",
        )
        wrapper.chmod(0o700)
        env.update({"GIT_ASKPASS": str(wrapper), "WARDEN_PUBLISH_TOKEN": token})
        ref = f"refs/heads/{artifact['branch']}"
        git(
            "--git-dir=objects.git",
            "push",
            "--no-verify",
            f"--force-with-lease={ref}:",
            f"https://x-access-token@github.com/{destination}.git",
            f"{artifact['proposed_sha']}:{ref}",
        )


class GitHubPublisher:
    def __init__(self, token: str, transport=None):
        if not token.strip():
            raise ValueError("GitHub publication credential is required")
        self.token = token
        self.transport = transport or UrllibTransport()

    def _call(self, repository, suffix, *, body=None):
        path = f"/repos/{repository}/{suffix}"
        result = request_json(
            source="github",
            operation="publish_pr",
            method="POST" if body else "GET",
            url=f"https://api.github.com{path}",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            body=body,
            transport=self.transport,
            budget=WorkBudget(max_requests=1, max_retries=0, timeout_seconds=15),
            sleeper=time.sleep,
            hosts=frozenset({"api.github.com"}),
            path_allowed=lambda p: p == path.split("?", 1)[0],
        )
        return result.payload

    def publish(
        self,
        artifact: dict,
        approval: dict,
        *,
        repository: str,
        base: str,
        approver,
        publisher,
        local_repository: Path,
        authorized_repository: Path,
        audit,
        uploader=push_commit,
    ) -> dict:
        """Caller serializes this operation and persists audit in independent transactions.

        Load artifact, approval and principals from trusted storage, never request JSON.
        Existing closed PRs are returned rather than opening a replacement.
        """
        assert_approved(
            approval, artifact, repository, base, approver=approver, publisher=publisher
        )
        if local_repository.resolve(strict=True) != authorized_repository.resolve(strict=True):
            raise PermissionError("Repository is outside the authorized application")
        from alaira_warden.remediation.pipeline import verify_artifact

        verify_artifact(artifact, local_repository)
        owner = repository.split("/", 1)[0]
        query = urlencode(
            {"state": "all", "head": f"{owner}:{artifact['branch']}", "base": base, "per_page": 100}
        )

        def existing():
            pulls = self._call(repository, f"pulls?{query}")
            if not isinstance(pulls, list):
                raise ValueError("Invalid pull request response")
            for pr in pulls:
                if (
                    pr.get("head", {}).get("ref") == artifact["branch"]
                    and pr.get("base", {}).get("ref") == base
                ):
                    if (
                        pr["head"].get("sha") != artifact["proposed_sha"]
                        or pr["head"].get("repo", {}).get("full_name") != repository
                        or pr["base"].get("repo", {}).get("full_name") != repository
                        or pr["base"].get("sha") != artifact["base_sha"]
                    ):
                        raise PermissionError("Existing pull request does not match approval")
                    return pr
            return None

        found = existing()
        if found:
            audit("publication.reconciled", {"artifact_id": artifact["id"], "pr": found["number"]})
            return {"number": found["number"], "url": found["html_url"], "reconciled": True}
        base_ref = self._call(repository, "git/ref/heads/" + quote(base, safe=""))
        if (
            not isinstance(base_ref, dict)
            or base_ref.get("object", {}).get("sha") != artifact["base_sha"]
        ):
            raise PermissionError("Destination changed; regenerate and reapprove")
        head_ref = self._call(repository, "git/ref/heads/" + quote(artifact["branch"], safe=""))
        if head_ref is None:
            audit("publication.push_started", {"artifact_id": artifact["id"]})
            uploader(
                local_repository,
                artifact,
                repository,
                self.token,
                authorized_repository=authorized_repository,
            )
            head_ref = self._call(repository, "git/ref/heads/" + quote(artifact["branch"], safe=""))
        if (
            not isinstance(head_ref, dict)
            or head_ref.get("object", {}).get("sha") != artifact["proposed_sha"]
        ):
            raise PermissionError("Published branch does not match the validated commit")
        assert_approved(
            approval, artifact, repository, base, approver=approver, publisher=publisher
        )
        base_ref = self._call(repository, "git/ref/heads/" + quote(base, safe=""))
        if base_ref.get("object", {}).get("sha") != artifact["base_sha"]:
            raise PermissionError("Destination changed; regenerate and reapprove")
        audit("publication.pr_started", {"artifact_id": artifact["id"]})
        try:
            pr = self._call(
                repository,
                "pulls",
                body={
                    "title": f"Warden: validated dependency correction {artifact['id']}",
                    "head": artifact["branch"],
                    "base": base,
                    "body": f"Validated artifact `{artifact['id']}`\n\n"
                    f"Commit: `{artifact['proposed_sha']}`\n"
                    f"Diff SHA256: `{artifact['diff_sha256']}`\n\n"
                    "Human approval covers this commit and destination. No merge or deployment.",
                },
            )
        except Exception:
            # An accepted POST can lose its response. Reconcile before allowing a retry.
            pr = existing()
            if pr is None:
                raise
        if not isinstance(pr, dict) or not isinstance(pr.get("number"), int):
            raise ValueError("Invalid pull request response")
        if (
            pr.get("head", {}).get("sha") != artifact["proposed_sha"]
            or pr.get("base", {}).get("sha") != artifact["base_sha"]
        ):
            audit(
                "publication.pr_requires_review",
                {"artifact_id": artifact["id"], "pr": pr["number"]},
            )
            raise PermissionError("Pull request changed during publication; review is required")
        audit("publication.pr_created", {"artifact_id": artifact["id"], "pr": pr["number"]})
        return {"number": pr["number"], "url": pr["html_url"], "reconciled": False}
