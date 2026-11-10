"""Unit tests for `veritas collateral collect` (no cluster needed)."""


import pytest

from veritas import collaterals
from veritas.collaterals.snp import parse_vcek_url

HWID = "ab" * 64
GENOA_URL = (f"https://kdsintf.amd.com/vcek/v1/Genoa/{HWID}"
             "?blSPL=9&teeSPL=0&snpSPL=23&ucodeSPL=72")


class TestParseVcekUrl:
    def test_hwid_is_lowercased(self):
        assert parse_vcek_url(GENOA_URL.replace(HWID, HWID.upper()))["hwid"] == HWID

    @pytest.mark.parametrize("url", [
        GENOA_URL.replace("kdsintf.amd.com", "evil.example.com"),
        GENOA_URL.replace("https://", "http://"),
        GENOA_URL.replace("Genoa", "Venice"),
        GENOA_URL.replace(HWID, "../../etc"),
        GENOA_URL.replace(HWID, HWID[:-2]),
        GENOA_URL + "&extra=1",
        GENOA_URL.replace("blSPL=9", "blSPL=256"),
        GENOA_URL.replace("blSPL=9", "blSPL=-1"),
        GENOA_URL.replace("blSPL=9&", "blSPL=9&blSPL=1&"),
    ])
    def test_rejects_untrusted_input(self, url):
        with pytest.raises(ValueError):
            parse_vcek_url(url)


def fake_oc(outputs, provider=""):
    """Return an `oc` replacement that answers per node from `outputs`."""
    calls = []

    def oc(*args):
        calls.append(args)
        if args[0] == "whoami":
            return "https://api.test:6443\n"
        if args[:2] == ("get", "node"):
            return provider
        if args[:2] == ("get", "nodes"):
            return "".join(f"node/{n}\n" for n in outputs)
        node = args[1].removeprefix("node/")
        return outputs[node]

    oc.calls = calls
    return oc


class TestCollect:
    def test_mixed_cluster(self, monkeypatch):
        monkeypatch.setattr(collaterals, "oc", fake_oc({
            "snp-0": f"tee=snp\n{GENOA_URL}\n",
            "tdx-0": "tee=tdx\n",
            "plain-0": "tee=none\n",
        }))
        req = collaterals.collect(["snp-0", "tdx-0", "plain-0"], "img")
        assert req["version"] == 1
        assert [(n["name"], n["tee"]) for n in req["nodes"]] == [
            ("snp-0", "snp"), ("tdx-0", "tdx")]
        assert req["nodes"][0]["hwid"] == HWID

    def test_azure_recorded_as_tdx(self, monkeypatch):
        oc = fake_oc({"az-0": "tee=none\n"}, provider="azure:///subscriptions/x")
        monkeypatch.setattr(collaterals, "oc", oc)
        assert collaterals.collect(["az-0"], "img")["nodes"] == [{"name": "az-0", "tee": "tdx"}]
        assert not any(c[0] == "debug" for c in oc.calls)

    def test_image_is_shell_quoted(self, monkeypatch):
        oc = fake_oc({"n": "tee=none\n"})
        monkeypatch.setattr(collaterals, "oc", oc)
        collaterals.collect(["n"], "img; rm -rf /")
        assert "'img; rm -rf /'" in oc.calls[-1][-1]

    def test_cli_asks_and_aborts(self, monkeypatch, tmp_path, capsys):
        oc = fake_oc({"n": "tee=none\n"})
        monkeypatch.setattr(collaterals, "oc", oc)
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda _: "n")
        out = tmp_path / "request.json"
        with pytest.raises(SystemExit):
            collaterals.main(["collect", "--node", "n", "-o", str(out)])
        assert "https://api.test:6443" in capsys.readouterr().err
        assert not out.exists()
        assert not any(c[0] == "debug" for c in oc.calls)
