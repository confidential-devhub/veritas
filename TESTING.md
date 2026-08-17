# Testing

```
pip install -e ".[test]"
pytest
```

The policy validation tests download the OPA binary and the attestation policy
from `openshift/trustee-operator` on first run (cached in `tests/.cache/`).
No cluster needed.

Override the policy URL with `VERITAS_POLICY_URL=https://...`.
