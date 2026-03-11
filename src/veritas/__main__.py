"""Extract CoCo reference values for Trustee RVPS."""

import argparse
import logging
import sys
from pathlib import Path

from veritas.models import format_trustee
from veritas.platforms import EXTRACTORS

log = logging.getLogger(__name__)

RVPS_FILENAME = "rvps-reference-values.yaml"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=EXTRACTORS.keys())
    parser.add_argument("--tee", default="tdx", choices=["tdx", "snp"])
    parser.add_argument("--authfile", help="Registry auth file for pulling images")
    parser.add_argument("--ocp-version", action="append", dest="ocp_versions",
                        help="OCP version (repeatable, e.g. --ocp-version 4.20.6 --ocp-version 4.20.15)")
    parser.add_argument("--osc-version", action="append", dest="osc_versions",
                        help="OSC dm-verity image tag (azure only, repeatable). Defaults to latest")
    parser.add_argument("--initdata", help="Path to initdata.toml for hash computation")
    parser.add_argument("-o", "--output", default=".",
                        help="Output directory (default: current directory)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    try:
        extractor_cls = EXTRACTORS[args.platform]
        kwargs = {"tee": args.tee, "authfile": args.authfile}
        if args.ocp_versions:
            kwargs["ocp_versions"] = args.ocp_versions
        if args.osc_versions:
            kwargs["osc_versions"] = args.osc_versions
        extractor = extractor_cls(**kwargs)
        values = extractor.extract()
        if args.initdata:
            values.append(extractor.compute_initdata(args.initdata))
    except RuntimeError as e:
        log.error("%s", e)
        sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    rvps_path = output_dir / RVPS_FILENAME
    versions = args.ocp_versions or args.osc_versions
    rvps_path.write_text(format_trustee(values, extractor.platform, args.tee, versions=versions))
    log.info("Written %s", rvps_path)


if __name__ == "__main__":
    main()
