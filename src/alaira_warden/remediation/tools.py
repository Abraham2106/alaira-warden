"""Trusted bindings for images with shell/tar/sleep plus the stated executables.

Images are preprovisioned by the operator with npm cache and scanner databases.
DockerRunner keeps --network=none; these commands never fetch missing cache data.
"""

from alaira_warden.execution import Tool

NPM_LOCKFILE_SCRIPT = r"""
const fs = require('node:fs');
const cp = require('node:child_process');
const [name, version] = process.argv.slice(1);
const manifest = JSON.parse(fs.readFileSync('package.json', 'utf8'));
fs.cpSync('/opt/npm-cache', '/tmp/npm-cache', {recursive:true});
let direct = false;
for (const key of ['dependencies','devDependencies','optionalDependencies']) {
  if (Object.hasOwn(manifest[key] || {}, name)) {
    manifest[key][name] = version; direct = true;
  }
}
if (!direct) {
  manifest.overrides ||= {};
  manifest.overrides[name] = version;
}
fs.writeFileSync('package.json', JSON.stringify(manifest, null, 2) + '\n');
const result = cp.spawnSync('/usr/local/bin/npm', ['install','--package-lock-only',
  '--ignore-scripts','--offline','--no-audit','--no-fund','--cache=/tmp/npm-cache'],
  {stdio:'inherit', env:{PATH:process.env.PATH, HOME:'/tmp', NPM_CONFIG_UPDATE_NOTIFIER:'false'}});
if (result.status !== 0) process.exit(result.status || 1);
for (const file of ['package.json','package-lock.json']) fs.copyFileSync(file, 'artifacts/'+file);
"""


def npm_tools(image_id: str) -> dict[str, Tool]:
    return {
        "npm_lockfile": Tool(image_id, "/usr/local/bin/node", ("-e", NPM_LOCKFILE_SCRIPT)),
        "project_tests": Tool(
            image_id,
            "/bin/sh",
            (
                "-c",
                "cp -r /opt/npm-cache /tmp/npm-cache && "
                "npm ci --ignore-scripts --offline --no-audit --no-fund --cache=/tmp/npm-cache "
                "&& npm test",
            ),
        ),
    }


def scanner_tools(*, syft_image: str, trivy_image: str, osv_image: str) -> dict[str, Tool]:
    return {
        "syft": Tool(
            syft_image,
            "/bin/sh",
            (
                "-c",
                "cd /tmp && syft version > /workspace/artifacts/syft-version.txt && "
                "SYFT_CHECK_FOR_APP_UPDATE=false syft dir:/workspace "
                "-o syft-json=/workspace/artifacts/syft.json",
            ),
        ),
        "trivy": Tool(
            trivy_image,
            "/bin/sh",
            (
                "-c",
                "cd /tmp && printf '{}\\n' > trivy.yaml && "
                "trivy --version > /workspace/artifacts/trivy-version.txt && "
                "trivy fs --config /tmp/trivy.yaml --ignorefile /dev/null "
                "--offline-scan --skip-db-update --skip-java-db-update "
                "--scanners vuln --severity HIGH,CRITICAL --exit-code 1 "
                "--cache-dir /opt/trivy-cache --format json "
                "--output /workspace/artifacts/trivy.json /workspace",
            ),
        ),
        "osv_scanner": Tool(
            osv_image,
            "/bin/sh",
            (
                "-c",
                "cd /tmp && printf '' > osv.toml && "
                "osv-scanner --version > /workspace/artifacts/osv-version.txt && "
                "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/osv-cache "
                "osv-scanner scan source --offline --config /tmp/osv.toml "
                "--format json -L /workspace/package-lock.json "
                "--output-file /workspace/artifacts/osv.json",
            ),
        ),
    }
