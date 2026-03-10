"""Extract and display CoCo reference values for Trustee RVPS."""

import argparse
import json
import logging
import sys
from pathlib import Path

from veritas.models import group_by_category
from veritas.platforms import EXTRACTORS

log = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=EXTRACTORS.keys())
    parser.add_argument("--tee", default="tdx", choices=["tdx", "snp"])
    parser.add_argument("--authfile", help="Registry auth file for pulling images")
    parser.add_argument("--initdata", help="Path to initdata.toml for hash computation")
    parser.add_argument("-o", "--output", default="output.json", help="Output file (default: output.json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    try:
        extractor_cls = EXTRACTORS[args.platform]
        extractor = extractor_cls(tee=args.tee, authfile=args.authfile)
        values = extractor.extract()
        if args.initdata:
            values.append(extractor.compute_initdata(args.initdata))
    except RuntimeError as e:
        log.error("%s", e)
        sys.exit(1)

    output = {
        "platform": extractor.platform,
        "evidence_type": extractor.evidence_type,
        **group_by_category(values),
    }
    Path(args.output).write_text(json.dumps(output, indent=2) + "\n")
    log.info("Written to %s", args.output)


if __name__ == "__main__":
    main()
