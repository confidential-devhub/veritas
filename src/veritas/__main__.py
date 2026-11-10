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
    if sys.argv[1:2] == ["collateral"]:
        from veritas.collaterals import main as collateral_main
        return collateral_main(sys.argv[2:])

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=EXTRACTORS.keys())
    parser.add_argument("--tee", default="tdx", choices=["tdx", "snp"])
    parser.add_argument("--authfile", help="Registry auth file for pulling images")
    parser.add_argument("--ocp-version", action="append", dest="ocp_versions",
                        help="OCP version (repeatable, e.g. --ocp-version 4.20.6 --ocp-version 4.20.15)")
    parser.add_argument("--image-tag", action="append", dest="image_tags",
                        help="Image tag (azure only, repeatable). Can be a version (e.g. 1.12.1) "
                        "or git commit hash (e.g. 062b4c37...). Defaults to latest")
    parser.add_argument("--image-repo",
                        help="[Deprecated] Use --mirror-registry instead. "
                        "Full image repository override for the azure dm-verity image.")
    parser.add_argument("--kernel-cmdline",
                        help="Override kernel command line (baremetal only). "
                        "When set, computes a single measurement value instead of "
                        "one per CPU count. Default: kata default cmdline with nr_cpus=1..N")
    parser.add_argument("--max-cpu-count", type=int, default=32,
                        help="Max nr_cpus to generate cmdline variants for (default: 32, "
                        "ignored when --kernel-cmdline is set)")
    parser.add_argument("--mem-size", type=int, default=2048,
                        help="VM memory size in MB for tdvfkernel hash (default: 2048, "
                        "kata default). Only affects baremetal TDX.")
    parser.add_argument("--kata-rpm",
                        help="Path to a local kata-containers RPM. When set, uses this "
                        "RPM instead of the one from the OCP release extensions image. "
                        "An --ocp-version is still required to resolve the edk2 RPM.")
    parser.add_argument("--gpu", action="store_true",
                        help="Generate measurements for GPU pods (uses kata-cc-nvidia-gpu.initrd "
                        "and GPU-specific cmdline). When used with --kernel-cmdline, picks the "
                        "GPU initrd. Without --kernel-cmdline, auto-generates both GPU and non-GPU.")
    parser.add_argument("--initdata", action="append", dest="initdata_paths",
                        help="Path to initdata.toml for hash computation (repeatable)")

    parser.add_argument("--hw-xfam-allow", action="append", dest="hw_xfam_allow",
                        help="XFAM CPU feature enabled for the TD (TDX only, repeatable). "
                        "e.g. --hw-xfam-allow x87 --hw-xfam-allow sse --hw-xfam-allow avx")
    disconnected = parser.add_argument_group("Disconnected environments")
    disconnected.add_argument("--mirror-registry",
                              help="Registry mirror host to use in place of public registries. "
                              "Assumes the mirror preserves the original image path structure, "
                              "as produced by oc-mirror. Used for the dm-verity image (azure) "
                              "and the OCP release payload and extensions image (baremetal). "
                              "Example: my-acr.azurecr.io")
    disconnected.add_argument("--cosign-pub-key",
                              help="Path to a local cosign public key PEM file. When set, skips the "
                              "download of the Red Hat cosign key from security.access.redhat.com. "
                              "Required in disconnected environments.")
    disconnected.add_argument("--skip-tlog", action="store_true",
                              help="Skip transparency log (Rekor) verification when verifying "
                              "image signatures. Use in disconnected environments where Rekor "
                              "is not accessible. The cosign signature is still verified "
                              "against the public key.")
    disconnected.add_argument("--rekor-url",
                              help="Rekor server URL for signature verification (default: Red Hat Rekor instance)")
    disconnected.add_argument("--rekor-pub-key-url",
                              help="Rekor public key URL for signature verification (default: Red Hat TUF server)")
    parser.add_argument("--data-key", default="reference_value",
                        help="ConfigMap data key name (default: reference_value)")
    parser.add_argument("--cm-name", default="trusteeconfig-rvps-reference-values",
                        help="ConfigMap metadata.name (default: trusteeconfig-rvps-reference-values)")
    parser.add_argument("--bot-version", default="1.2", choices=["1.1", "1.2"],
                        help="Red Hat build of Trustee format version (default: 1.2 for OSC 1.13+). "
                        "Use 1.1 for OSC 1.12 and earlier")
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
        if args.mirror_registry:
            kwargs["mirror_registry"] = args.mirror_registry
        if args.platform == "baremetal":
            if args.ocp_versions:
                kwargs["ocp_versions"] = args.ocp_versions
            kwargs["kernel_cmdline"] = args.kernel_cmdline
            kwargs["max_cpu_count"] = args.max_cpu_count
            kwargs["mem_size"] = args.mem_size * 1024 * 1024
            kwargs["kata_rpm"] = args.kata_rpm
            kwargs["gpu"] = args.gpu
        else:  # azure
            if args.image_tags:
                kwargs["image_tags"] = args.image_tags
            if args.rekor_url:
                kwargs["rekor_url"] = args.rekor_url
            if args.rekor_pub_key_url:
                kwargs["rekor_pub_key_url"] = args.rekor_pub_key_url
            if args.image_repo:
                log.warning("--image-repo is deprecated, use --mirror-registry instead.")
                kwargs["image_repo"] = args.image_repo
            if args.cosign_pub_key:
                kwargs["cosign_pub_key"] = args.cosign_pub_key
            if args.skip_tlog:
                kwargs["skip_tlog"] = args.skip_tlog
        extractor = extractor_cls(**kwargs)
        values = extractor.extract()
        if args.initdata_paths:
            values.append(extractor.compute_initdata(args.initdata_paths))
        if args.hw_xfam_allow:
            if args.tee != "tdx":
                log.warning("--hw-xfam-allow is only relevant for TDX, ignoring")
            else:
                from veritas.models import ReferenceValue
                from veritas.xfam import compute_xfam
                xfam_hex = compute_xfam(args.hw_xfam_allow)
                algo = "sha256" if args.platform == "azure" else "sha384"
                values.append(ReferenceValue(
                    name="xfam",
                    values=[xfam_hex],
                    category="hardware",
                    description="Extended features mask (XSAVE CPU features enabled for the TD)",
                    algorithm=algo,
                    source="--hw-xfam-allow " + " ".join(args.hw_xfam_allow),
                ))
        if args.tee == "tdx" and not args.hw_xfam_allow:
            log.warning(
                "No --hw-xfam-allow provided. The default attestation "
                "policy checks xfam and will FAIL without it. Pass --hw-xfam-allow "
                "with the CPU features enabled for the TD, or customize the policy "
                "to skip the xfam check."
            )
    except RuntimeError as e:
        log.error("%s", e)
        sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    rvps_path = output_dir / RVPS_FILENAME
    versions = args.ocp_versions or args.image_tags
    skipped = getattr(extractor, "skipped_versions", None)
    rvps_path.write_text(format_trustee(values, extractor.platform, args.tee,
                                        versions=versions, skipped=skipped,
                                        data_key=args.data_key,
                                        cm_name=args.cm_name,
                                        bot_version=args.bot_version))
    log.info("Written %s", rvps_path)


if __name__ == "__main__":
    main()
