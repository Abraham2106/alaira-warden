from pathlib import Path

ROOT = Path(__file__).parents[2] / "src" / "alaira_warden" / "inventory"


def test_inventory_package_does_not_reach_for_network_docker_or_settings():
    source = "\n".join(path.read_text(encoding="utf-8") for path in ROOT.glob("*.py"))
    for banned in (
        "alaira_warden.config",
        "alaira_warden.db",
        "alaira_warden.repository",
        "subprocess",
        "urllib.request",
        "httpx",
        "socket.socket",
        "docker.sock",
        "os.environ",
    ):
        assert banned not in source
