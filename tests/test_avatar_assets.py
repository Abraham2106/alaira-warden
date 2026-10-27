import base64
import hashlib
import xml.etree.ElementTree as ET

from fastapi.testclient import TestClient

from alaira_warden.config import Settings
from alaira_warden.main import STATIC, create_app


def test_local_avatars_have_scoped_csp_and_no_active_content():
    client = TestClient(create_app(Settings(_env_file=None)))
    page_policy = client.get("/").headers["content-security-policy"]
    assert "'unsafe-inline'" not in page_policy
    assert "sha256-" not in page_policy
    for path in (STATIC / "assets" / "agents").glob("*.svg"):
        response = client.get(f"/static/assets/agents/{path.name}")
        assert response.status_code == 200
        root = ET.fromstring(response.content)
        for node in root.iter():
            assert node.tag.split("}")[-1] not in {"script", "foreignObject"}
            assert not any(key.lower().startswith("on") for key in node.attrib)
            if node.tag.endswith("}style"):
                digest = base64.b64encode(hashlib.sha256(node.text.encode()).digest()).decode()
                assert f"'sha256-{digest}'" in response.headers["content-security-policy"]
        if not path.stem.endswith("-still"):
            assert "prefers-reduced-motion" in response.text
