"""Validate Veritas RVPS key names against the Trustee attestation policy.

Downloads the latest attestation policy from the downstream Trustee operator
repo (openshift/trustee-operator), parses its Rego AST via `opa parse`, and
cross-references the reference keys the policy checks against the keys
Veritas produces.

Also runs OPA eval with synthetic input to confirm the policy passes when
all Veritas-produced keys are present with matching values.
"""

import json
import os
import platform as platform_mod
import stat
import subprocess
import tempfile
import urllib.request
from pathlib import Path

import pytest

from veritas.platforms.azure import AzureExtractor
from veritas.platforms.baremetal import BaremetalExtractor

# ---- Configuration ----

OPA_VERSION = "1.4.2"
CACHE_DIR = Path(__file__).parent / ".cache"

POLICY_URL = os.environ.get(
    "VERITAS_POLICY_URL",
    "https://raw.githubusercontent.com/openshift/"
    "trustee-operator/main/config/templates/"
    "ear_default_attestation_policy_cpu.rego",
)

# The policy uses query_reference_value(), a native extension function
# registered by the Trustee AS in regorus. When running OPA standalone,
# we provide this stub that reads from data.reference instead.
REFERENCE_VALUE_STUB = """\
package policy

query_reference_value(name) := data.reference[name]
"""

# Map (platform, tee) to the input.* TEE block name in the policy.
# Updated from the current downstream policy (hyphens for Azure vTPM).
TEE_BLOCKS = {
    ("baremetal", "tdx"): "tdx",
    ("baremetal", "snp"): "snp",
    ("azure", "tdx"): "az-tdx-vtpm",
    ("azure", "snp"): "az-snp-vtpm",
}


# ---- OPA binary ----

def _opa_url():
    system = platform_mod.system().lower()
    machine = platform_mod.machine()
    urls = {
        ("linux", "x86_64"): f"https://openpolicyagent.org/downloads/v{OPA_VERSION}/opa_linux_amd64_static",
        ("linux", "aarch64"): f"https://openpolicyagent.org/downloads/v{OPA_VERSION}/opa_linux_arm64_static",
        ("darwin", "x86_64"): f"https://openpolicyagent.org/downloads/v{OPA_VERSION}/opa_darwin_amd64",
        ("darwin", "arm64"): f"https://openpolicyagent.org/downloads/v{OPA_VERSION}/opa_darwin_arm64",
    }
    url = urls.get((system, machine))
    if not url:
        pytest.skip(f"No OPA binary available for {system}/{machine}")
    return url


@pytest.fixture(scope="session")
def opa(tmp_path_factory):
    opa_path = CACHE_DIR / f"opa-{OPA_VERSION}"
    if not opa_path.exists():
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(_opa_url(), opa_path)
        opa_path.chmod(opa_path.stat().st_mode | stat.S_IEXEC)
    return str(opa_path)


# ---- Policy download ----

@pytest.fixture(scope="session")
def policy_rego(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("policy")
    policy_file = tmp / "policy.rego"
    stub_file = tmp / "stub.rego"

    urllib.request.urlretrieve(POLICY_URL, policy_file)
    stub_file.write_text(REFERENCE_VALUE_STUB)

    return str(policy_file), str(stub_file), str(tmp)


# ---- AST parsing ----

def _ref_path(value_list):
    """Convert an AST ref value list to a dotted path string."""
    return ".".join(str(t.get("value", "")) for t in value_list)


def parse_policy_reference_keys(opa_binary, policy_path):
    """Parse the policy and extract all query_reference_value("key") calls.

    Returns a dict: {tee_block_name: {reference_key: info_dict}}
    where info_dict has input_path, operator, claim, and claim_value.
    """
    result = subprocess.run(
        [opa_binary, "parse", "--format", "json", policy_path],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"opa parse failed: {result.stderr}")

    ast = json.loads(result.stdout)
    by_tee = {}

    for rule in ast.get("rules", []):
        if rule.get("default"):
            continue

        head = rule.get("head", {})
        claim = head.get("name", "")
        claim_value = head.get("value", {}).get("value")

        # Collect input.* refs and query_reference_value calls from rule body
        input_refs = []
        qrv_calls = []
        hardcoded = []

        for expr in rule.get("body", []):
            terms = expr.get("terms")
            if not isinstance(terms, list):
                continue

            for term in terms:
                _collect_input_refs(term, input_refs)

            if len(terms) == 3:
                op = _ref_path(terms[0].get("value", []))
                left, right = terms[1], terms[2]

                left_call = _extract_qrv_call(left)
                right_call = _extract_qrv_call(right)

                if left_call is not None:
                    other = _term_to_path(right)
                    qrv_calls.append((left_call, other, op))
                elif right_call is not None:
                    other = _term_to_path(left)
                    qrv_calls.append((right_call, other, op))
                else:
                    # Hardcoded check (no query_reference_value)
                    left_path = _term_to_path(left)
                    right_path = _term_to_path(right)
                    if left_path and left_path.startswith("input."):
                        hardcoded.append({
                            "input_path": left_path,
                            "op": op,
                            "value": right.get("value"),
                            "type": right.get("type"),
                        })
                    elif right_path and right_path.startswith("input."):
                        hardcoded.append({
                            "input_path": right_path,
                            "op": op,
                            "value": left.get("value"),
                            "type": left.get("type"),
                        })

            elif len(terms) == 2:
                left_call = _extract_qrv_call(terms[0])
                right_call = _extract_qrv_call(terms[1])
                if left_call is not None:
                    other = _term_to_path(terms[1])
                    qrv_calls.append((left_call, other, "internal.member_2"))
                elif right_call is not None:
                    other = _term_to_path(terms[0])
                    qrv_calls.append((right_call, other, "internal.member_2"))

        # Determine TEE block from input refs
        tee_blocks = set()
        for ref in input_refs:
            path = ref.removeprefix("input.")
            block = path.split(".")[0]
            if block and block not in ("init_data_claims",):
                tee_blocks.add(block)

        for key, input_path, op in qrv_calls:
            for tee in tee_blocks:
                if tee not in by_tee:
                    by_tee[tee] = {}
                by_tee[tee][key] = {
                    "input_path": input_path,
                    "op": op,
                    "claim": claim,
                    "claim_value": claim_value,
                    "hardcoded": hardcoded,
                }

    return by_tee


def _collect_input_refs(node, refs):
    """Recursively collect input.* ref paths from an AST node."""
    if isinstance(node, dict):
        if node.get("type") == "ref":
            path = _ref_path(node.get("value", []))
            if path.startswith("input."):
                refs.append(path)
        for v in node.values():
            _collect_input_refs(v, refs)
    elif isinstance(node, list):
        for item in node:
            _collect_input_refs(item, refs)


def _extract_qrv_call(term):
    """If term is a query_reference_value("key") call, return the key."""
    if term.get("type") != "call":
        return None
    args = term.get("value", [])
    if len(args) < 2:
        return None
    func_ref = _ref_path(args[0].get("value", []))
    if func_ref != "query_reference_value":
        return None
    return args[1].get("value")


def _term_to_path(term):
    """Convert a term to a dotted path string, or None."""
    if term.get("type") == "ref":
        return _ref_path(term.get("value", []))
    return None


# ---- Veritas key extraction ----

def _veritas_keys(platform, tee):
    """Get the set of RVPS key names Veritas produces for a platform/tee."""
    if platform == "azure":
        return AzureExtractor(tee=tee).reference_key_names()
    elif platform == "baremetal":
        return BaremetalExtractor(tee=tee, ocp_versions=["4.21.0"]).reference_key_names()
    raise ValueError(f"Unknown platform: {platform}")


# ---- OPA eval helpers ----

def _build_data_reference(keys):
    """Build data.reference JSON with sentinel values for each key."""
    ref = {}
    for key in keys:
        ref[key] = [f"sentinel_{key}"]
    return {"reference": ref}


def _set_nested(d, path_parts, value):
    """Set a value in a nested dict by path parts."""
    for part in path_parts[:-1]:
        if part not in d:
            d[part] = {}
        d = d[part]
    d[path_parts[-1]] = value


def _build_input_for_tee(tee_block, policy_refs, data_ref):
    """Build synthetic input that satisfies all policy checks for a TEE block.

    For each query_reference_value("key") check, puts the same sentinel
    value from data_ref into the corresponding input path. For hardcoded
    checks (like debug == false), uses the expected literal value.
    """
    inp = {}

    for key, info in policy_refs.items():
        input_path = info.get("input_path")
        op = info.get("op", "")
        sentinel = data_ref["reference"].get(key, [f"sentinel_{key}"])

        if op in ("internal.member_2",):
            value = sentinel[0] if isinstance(sentinel, list) else sentinel
        else:
            value = sentinel

        if input_path and input_path.startswith("input."):
            parts = input_path.removeprefix("input.").split(".")
            _set_nested(inp, parts, value)

        # Handle hardcoded checks from the same rule
        for hc in info.get("hardcoded", []):
            hc_path = hc["input_path"]
            if hc_path.startswith("input."):
                parts = hc_path.removeprefix("input.").split(".")
                _set_nested(inp, parts, hc["value"])

    # Handle TDX UEFI event logs (tdvfkernel / tdvfkernelparams)
    if tee_block == "tdx":
        _add_tdx_uefi_events(inp, data_ref)

    # Add TEE block existence marker for short-circuit checks
    # (the policy checks `input.<tee>` as a guard)
    if tee_block not in inp:
        inp[tee_block] = {}

    return inp


def _add_tdx_uefi_events(inp, data_ref):
    """Add UEFI event log entries for tdvfkernel and tdvfkernelparams."""
    tdx = inp.setdefault("tdx", {})
    events = []

    kernel_ref = data_ref["reference"].get("tdvfkernel")
    if kernel_ref:
        val = kernel_ref[0] if isinstance(kernel_ref, list) else kernel_ref
        events.append({
            "type_name": "EV_EFI_BOOT_SERVICES_APPLICATION",
            "details": {"device_paths": ["File(kernel)"]},
            "digests": [{"digest": val}],
        })

    params_ref = data_ref["reference"].get("tdvfkernelparams")
    if params_ref:
        val = params_ref[0] if isinstance(params_ref, list) else params_ref
        events.append({
            "type_name": "EV_EVENT_TAG",
            "details": {"string": "LOADED_IMAGE::LoadOptions"},
            "digests": [{"digest": val}],
        })

    if events:
        tdx["uefi_event_logs"] = events


def _run_opa_eval(opa_binary, policy_dir, data, inp, rule):
    """Run opa eval and return the result value."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as df:
        json.dump(data, df)
        data_path = df.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as inf:
        json.dump(inp, inf)
        input_path = inf.name

    try:
        result = subprocess.run(
            [opa_binary, "eval",
             "-d", policy_dir,
             "-d", data_path,
             "-i", input_path,
             f"data.policy.{rule}"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"opa eval failed: {result.stderr}")

        output = json.loads(result.stdout)
        expressions = output.get("result", [{}])[0].get("expressions", [])
        if expressions:
            return expressions[0].get("value")
        return None
    finally:
        Path(data_path).unlink(missing_ok=True)
        Path(input_path).unlink(missing_ok=True)


# ---- Fixtures ----

@pytest.fixture(scope="session")
def policy_data(opa, policy_rego):
    """Parse the policy and return reference key mappings by TEE block."""
    policy_path, stub_path, policy_dir = policy_rego
    return parse_policy_reference_keys(opa, policy_path)


# ---- Tests ----

PLATFORMS = [
    ("baremetal", "tdx"),
    ("baremetal", "snp"),
    ("azure", "tdx"),
    ("azure", "snp"),
]


@pytest.mark.parametrize("platform,tee", PLATFORMS)
def test_veritas_covers_policy(platform, tee, policy_data):
    """Veritas must produce all reference keys for claims it covers.

    If Veritas produces at least one key for a policy claim (executables,
    hardware, configuration), it must produce ALL keys for that claim.
    Claims where Veritas produces zero keys are skipped — those values
    come from the hardware platform, not from software measurements.
    """
    tee_block = TEE_BLOCKS[(platform, tee)]
    if tee_block not in policy_data:
        pytest.skip(f"Policy has no rules for TEE block '{tee_block}'")

    veritas_keys = _veritas_keys(platform, tee)

    # Group policy keys by claim
    claims = {}
    for key, info in policy_data[tee_block].items():
        claim = info["claim"]
        if claim not in ("executables", "hardware", "configuration"):
            continue
        claims.setdefault(claim, set()).add(key)

    gaps = {}
    for claim, policy_keys in claims.items():
        covered = policy_keys & veritas_keys
        if not covered:
            # Veritas has no keys for this claim — not its responsibility
            continue
        missing = policy_keys - veritas_keys
        if missing:
            gaps[claim] = sorted(missing)

    assert not gaps, (
        f"Veritas partially covers these claims for {tee_block} but "
        f"is missing keys: {gaps}"
    )


@pytest.mark.parametrize("platform,tee", PLATFORMS)
def test_veritas_keys_used_by_policy(platform, tee, policy_data):
    """Every key Veritas produces should be checked by the policy."""
    tee_block = TEE_BLOCKS[(platform, tee)]
    if tee_block not in policy_data:
        pytest.skip(f"Policy has no rules for TEE block '{tee_block}'")

    policy_keys = set(policy_data[tee_block].keys())
    veritas_keys = _veritas_keys(platform, tee)

    unused = veritas_keys - policy_keys
    if unused:
        pytest.xfail(
            f"Veritas produces keys not checked by the policy for "
            f"{tee_block}: {sorted(unused)}. These may be intentionally "
            f"unchecked (e.g. init_data) or indicate a naming mismatch."
        )


@pytest.mark.parametrize("platform,tee", PLATFORMS)
def test_opa_eval_passes(platform, tee, opa, policy_rego, policy_data):
    """OPA eval must return success values when Veritas keys are correct."""
    tee_block = TEE_BLOCKS[(platform, tee)]
    _, _, policy_dir = policy_rego
    if tee_block not in policy_data:
        pytest.skip(f"Policy has no rules for TEE block '{tee_block}'")

    policy_refs = policy_data[tee_block]
    veritas_keys = _veritas_keys(platform, tee)

    # Only test claims where Veritas provides ALL needed keys
    claims_to_test = {}
    for key, info in policy_refs.items():
        claim = info["claim"]
        if claim not in claims_to_test:
            claims_to_test[claim] = {"keys_needed": set(), "all_covered": True}
        claims_to_test[claim]["keys_needed"].add(key)
        if key not in veritas_keys:
            claims_to_test[claim]["all_covered"] = False

    data_ref = _build_data_reference(veritas_keys)
    inp = _build_input_for_tee(tee_block, policy_refs, data_ref)

    for claim, claim_info in claims_to_test.items():
        if not claim_info["all_covered"]:
            missing = claim_info["keys_needed"] - veritas_keys
            continue

        # Helper rules (like tdx_uefi_event_tdvfkernel_ok) are not
        # directly evaluable as trust claims
        if claim not in ("executables", "hardware", "configuration"):
            continue

        result = _run_opa_eval(opa, policy_dir, data_ref, inp, claim)

        # Success values: executables=3 or 4, hardware=2, configuration=2 or 3
        # Default (fail) values: executables=33, hardware=97, configuration=36
        fail_defaults = {"executables": 33, "hardware": 97, "configuration": 36}
        assert result != fail_defaults.get(claim), (
            f"OPA eval returned default (fail) for {claim}={result} on "
            f"{tee_block}. The policy could not match Veritas reference "
            f"keys against the input. This indicates a key naming mismatch."
        )
