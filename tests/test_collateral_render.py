"""Unit tests for `veritas collateral render` (no cluster or network needed)."""

import base64
from datetime import datetime, timezone
import json
import shutil
import tarfile
from pathlib import Path

import pytest

from veritas import collaterals
from veritas.collaterals import snp

DATA = Path(__file__).parent / "data"
# Real Milan VCEK from Trustee test data (deps/verifier/test_data/snp).
MILAN_VCEK = (DATA / "milan-vcek.der").read_bytes()
# https://kdsintf.amd.com/vcek/v1/Milan/cert_chain
MILAN_CHAIN = (DATA / "milan-cert-chain.pem").read_bytes()
HWID = "ab" * 64
NODE = {"name": "w0", "tee": "snp", "product": "Milan", "hwid": HWID,
        "tcb": {"blSPL": 3, "teeSPL": 0, "snpSPL": 8, "ucodeSPL": 115}}
VCEK_FILE = "bl03_tee00_snp08_ucode115_vcek.der"

needs_snpguest = pytest.mark.skipif(not shutil.which("snpguest"), reason="snpguest not installed")


@needs_snpguest
class TestVerifyCerts:
    def test_wrong_chain(self):
        chain = snp.split_cert_chain(MILAN_CHAIN)
        with pytest.raises(RuntimeError, match="verification failed"):
            snp.verify_certs(chain["ark.pem"], chain["ark.pem"], MILAN_VCEK)


@pytest.fixture
def offline(monkeypatch):
    urls = []

    def fetch(url):
        urls.append(url)
        return MILAN_CHAIN if url.endswith("/cert_chain") else MILAN_VCEK

    monkeypatch.setattr(snp, "fetch", fetch)
    if not shutil.which("snpguest"):
        monkeypatch.setattr(snp, "verify_certs", lambda ark, ask, vcek: None)
    return urls


def write_request(tmp_path, nodes):
    p = tmp_path / "request.json"
    p.write_text(json.dumps({"version": 1, "nodes": nodes}))
    return str(p)


class TestRender:
    def test_writes_manifests_and_bundle(self, tmp_path, offline):
        req = write_request(tmp_path, [NODE, {**NODE, "name": "w1"}])
        kbsconfig = tmp_path / "kbsconfig.json"
        kbsconfig.write_text(json.dumps({
            "metadata": {"name": "trustee-kbsconfig"},
            "spec": {"kbsLocalCertCacheSpec": {"secrets": [
                {"secretName": "tdx-collateral", "mountPath": "/tdx"}]}}}))
        out = tmp_path / "manifests"
        bundle = tmp_path / "bundle.tar"

        collaterals.main(["render", req, "--kbsconfig", str(kbsconfig),
                          "-o", str(out), "-b", str(bundle)])

        assert len(offline) == 2  # cert chain + one VCEK, same chip on two nodes
        secrets = (out / "secrets.yaml").read_text()
        assert f"name: vcek-{HWID[:16]}" in secrets
        assert f"{VCEK_FILE}: {base64.b64encode(MILAN_VCEK).decode()}" in secrets
        patch = (out / "kbsconfig.patch").read_text()
        assert "secretName: tdx-collateral" in patch
        assert f"kds-store/vcek/{HWID}" in patch
        with tarfile.open(bundle) as tar:
            assert sorted(tar.getnames()) == sorted(
                f"vcek-{HWID[:16]}/{n}" for n in ("ark.pem", "ask.pem", VCEK_FILE))


class TestVerify:
    def render_to(self, tmp_path, node):
        req = write_request(tmp_path, [node])
        out = tmp_path / "manifests"
        collaterals.main(["render", req, "-o", str(out)])
        return req, out

    def test_ok_shows_expiry(self, tmp_path, offline, capsys):
        req, out = self.render_to(tmp_path, NODE)
        collaterals.main(["verify", req, str(out)])
        assert "ok\tVCEK expires 2030-01-24" in capsys.readouterr().out

    def test_firmware_update_detected(self, tmp_path, offline, capsys):
        req, out = self.render_to(tmp_path, NODE)
        updated = {**NODE, "tcb": {**NODE["tcb"], "snpSPL": 23}}
        write_request(tmp_path, [updated])
        with pytest.raises(SystemExit):
            collaterals.main(["verify", req, str(out)])
        assert "firmware changed? re-run render" in capsys.readouterr().out

    def test_missing_node(self, tmp_path, offline, capsys):
        req, out = self.render_to(tmp_path, NODE)
        write_request(tmp_path, [NODE, {**NODE, "name": "new", "hwid": "cd" * 64}])
        with pytest.raises(SystemExit):
            collaterals.main(["verify", req, str(out)])
        assert "missing Secret" in capsys.readouterr().out

    def test_expired(self, tmp_path, offline, capsys, monkeypatch):
        req, out = self.render_to(tmp_path, NODE)
        monkeypatch.setattr(snp, "not_after", lambda der: datetime(2020, 1, 1, tzinfo=timezone.utc))
        with pytest.raises(SystemExit):
            collaterals.main(["verify", req, str(out)])
        assert "VCEK expired on 2020-01-01" in capsys.readouterr().out
