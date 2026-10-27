"""Offline GitHub/OSV/NVD/KEV replies for the guided demo. Not live probes."""

import json
from urllib.parse import urlsplit

from alaira_warden.intelligence.http import HttpResponse

DEMO_GHSA = "GHSA-35jh-r3h4-6jhm"
DEMO_CVE = "CVE-2020-8203"
DEMO_SHA = "a" * 40


class DemoTransport:
    """Controlled source responses; never opens a socket."""

    def __init__(self):
        self.calls = []
        self.package = {
            "name": "synthetic",
            "version": "1.0.0",
            "dependencies": {"lodash": "^4.17.0"},
        }
        self.lock = {
            "name": "synthetic",
            "lockfileVersion": 3,
            "packages": {
                "": self.package,
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                    "integrity": "sha512-fixture",
                },
            },
        }

    def send(self, request):
        self.calls.append(request.url)
        path = urlsplit(request.url).path
        if "/commits/" in path:
            payload = {"sha": DEMO_SHA}
        elif "/git/trees/" in path:
            payload = {
                "truncated": False,
                "tree": [
                    {"path": "package.json", "type": "blob", "mode": "100644", "sha": "b" * 40},
                    {
                        "path": "package-lock.json",
                        "type": "blob",
                        "mode": "100644",
                        "sha": "c" * 40,
                    },
                ],
            }
        elif path.endswith("b" * 40):
            payload = self.package
        elif path.endswith("c" * 40):
            payload = self.lock
        elif path == f"/advisories/{DEMO_GHSA}":
            payload = {
                "ghsa_id": DEMO_GHSA,
                "cve_id": DEMO_CVE,
                "type": "reviewed",
                "summary": "Synthetic fixture",
                "description": "Controlled evidence",
                "html_url": f"https://github.com/advisories/{DEMO_GHSA}",
                "published_at": "2020-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "npm", "name": "lodash"},
                        "vulnerable_version_range": "<4.17.21",
                    }
                ],
            }
        elif "api.osv.dev" in request.url:
            payload = {
                "id": DEMO_GHSA,
                "modified": "2026-01-01T00:00:00Z",
                "aliases": [DEMO_CVE],
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "lodash"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                            }
                        ],
                    }
                ],
            }
        elif "services.nvd.nist.gov" in request.url:
            payload = {
                "totalResults": 1,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": DEMO_CVE,
                            "vulnStatus": "Analyzed",
                            "descriptions": [{"lang": "en", "value": "Fixture"}],
                        }
                    }
                ],
            }
        elif "cisa.gov" in request.url:
            payload = {
                "catalogVersion": "2026.10.27",
                "dateReleased": "2026-10-27T00:00:00Z",
                "count": 0,
                "vulnerabilities": [],
            }
        else:
            raise ValueError(f"Demo transport has no fixture for {request.url}")
        return HttpResponse(200, {}, json.dumps(payload).encode())
