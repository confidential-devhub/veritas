"""Unit tests for TDX collateral (no cluster, network or pcsclient needed)."""

import json
from pathlib import Path

import pytest

from veritas import collaterals
from veritas.collaterals import tdx

# pcsclient fetch -p E5 -t all, trimmed to one FMSPC.
COLLATERAL = json.loads((Path(__file__).parent / "data" / "tdx-collateral.json").read_text())


def collateral(next_update: str) -> bytes:
    col = json.loads(json.dumps(COLLATERAL))
    for e in col["collaterals"]["tcbinfos"]:
        for k in ("tdx_tcbinfo", "tdx_tcbinfo_early"):
            e[k]["tcbInfo"]["nextUpdate"] = next_update
    for k in ("tdqeidentity", "tdqeidentity_early"):
        col["collaterals"][k]["enclaveIdentity"]["nextUpdate"] = next_update
    return json.dumps(col).encode()


@pytest.fixture
def pcsclient(monkeypatch):
    data = {"value": collateral("2099-01-01T00:00:00Z")}
    monkeypatch.setattr(tdx, "fetch", lambda: data["value"])
    return data


def render(tmp_path, *extra):
    req = tmp_path / "request.json"
    req.write_text(json.dumps({"version": 1, "nodes": [{"name": "t0", "tee": "tdx"}]}))
    out = tmp_path / "manifests"
    collaterals.main(["render", str(req), "-o", str(out), *extra])
    return str(req), out


class TestRender:
    def test_writes_secret_and_patch(self, tmp_path, pcsclient, caplog):
        _, out = render(tmp_path)
        assert f"name: {tdx.SECRET_NAME}" in (out / "secrets.yaml").read_text()
        assert f"mountPath: {tdx.MOUNT_DIR}" in (out / "kbsconfig.patch").read_text()
        assert tdx.COLLATERAL_SERVICE in caplog.text

    def test_verify_ok(self, tmp_path, pcsclient, capsys):
        render(tmp_path, "--verify")
        assert "t0\ttdx\tok\tcollateral expires 2099-01-01" in capsys.readouterr().out

    def test_verify_expired(self, tmp_path, pcsclient, capsys):
        pcsclient["value"] = collateral("2020-01-01T00:00:00Z")
        req, out = render(tmp_path)
        with pytest.raises(SystemExit):
            collaterals.main(["verify", req, str(out)])
        assert "collateral expired on 2020-01-01" in capsys.readouterr().out
