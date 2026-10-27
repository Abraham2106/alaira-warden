from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("bootstrap", ROOT / "scripts" / "bootstrap.py")
bootstrap = module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def test_setup_does_not_overwrite_or_print_secrets(tmp_path, capsys):
    template = (ROOT / ".env.example").read_text(encoding="utf-8")
    (tmp_path / ".env.example").write_text(template, encoding="utf-8")
    assert bootstrap.bootstrap(tmp_path)
    original = (tmp_path / ".env").read_text(encoding="utf-8")
    values = dict(
        line.split("=", 1) for line in original.splitlines() if line and not line.startswith("#")
    )
    output = capsys.readouterr().out
    for key in ("WARDEN_API_TOKEN", "POSTGRES_PASSWORD", "WARDEN_DB_APP_PASSWORD"):
        assert len(values[key]) >= 32
        assert values[key] not in output
    assert not bootstrap.bootstrap(tmp_path)
    assert (tmp_path / ".env").read_text(encoding="utf-8") == original
