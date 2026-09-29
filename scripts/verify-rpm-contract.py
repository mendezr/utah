#!/usr/bin/env python3
"""Assert that Utah actually contains its Bluefin and GNOME 51 RPM contracts.

Mirrors assert_packages_present from projectbluefin/bluefin's
build_files/shared/package-lib.sh: name every missing package, once.
"""

from __future__ import annotations

import argparse
import configparser
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import NamedTuple

# The NVIDIA userspace no longer arrives as RPMs. UBlue's akmods bundle used to
# supply nvidia-driver, nvidia-driver-cuda and nvidia-container-toolkit, but it
# publishes nothing for Hummingbird's kernel, so install-nvidia.sh builds the
# open module from NVIDIA's own source and installs the matching userspace from
# the same payload. Those files are what the image needs; the RPM names were
# only ever how they happened to arrive.
#
# nvidia-container-toolkit still arrives as an RPM, from NVIDIA own repository
# rather than from the akmods bundle, so it is asserted by name. It was recorded
# here as a real loss on the reasoning that the bundle was unusable; the bundle
# was one source, not the only one.
NVIDIA_PACKAGES: tuple[str, ...] = ("nvidia-container-toolkit",)


def section(path: Path, name: str) -> list[str]:
    data = tomllib.loads(path.read_text())
    return list(data.get(name, {}).get("packages", []))


def is_installed(pkg: str) -> bool:
    return subprocess.run(
        ["rpm", "-q", pkg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ).returncode == 0


# Include all libdnf default directories: omitting distro.repos.d would let a
# repository be enabled from a path the attestation never scans.
DEFAULT_REPOSDIRS = (
    "etc/yum.repos.d", "etc/yum/repos.d", "etc/distro.repos.d"
)
REQUIRED_SECURITY_OPTIONS = frozenset(
    {"gpgcheck", "repo_gpgcheck", "sslverify", "proxy"}
)


class RepositoryPolicy(NamedTuple):
    allowed: frozenset[str]
    baseurls: dict[str, tuple[str, ...]]
    options: dict[str, dict[str, str]]


def is_repo_enabled(value: str) -> bool:
    return value.strip().lower() not in {"0", "false", "no", "off"}


def normalize_baseurl(url: str) -> str:
    """Normalize URL spelling without case-folding its case-sensitive path."""
    value = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", r"$\1", url.strip().rstrip("/"))
    scheme, separator, rest = value.partition("://")
    if not separator:
        return value
    host, slash, path = rest.partition("/")
    return f"{scheme.lower()}://{host.lower()}{slash}{path}"


def split_baseurls(raw: str) -> list[str]:
    """DNF accepts several baseurls, all of which must be approved."""
    return [value for value in re.split(r"[\s,]+", raw.strip()) if value]


def normalize_repo_option(name: str, value: str) -> str:
    value = value.strip()
    if name in {"gpgcheck", "repo_gpgcheck", "sslverify"}:
        aliases = {"yes": "1", "true": "1", "on": "1", "no": "0", "false": "0", "off": "0"}
        return aliases.get(value.lower(), value)
    return value


def repo_pin_errors(
    section_name: str,
    parser: configparser.ConfigParser,
    source: str,
    policy: RepositoryPolicy,
) -> list[str]:
    """Enforce both the pinned origin and its per-repository security settings."""
    errors: list[str] = []
    declared = policy.baseurls.get(section_name, ())
    if not declared:
        errors.append(
            f"Allowlisted repository '{section_name}' in {source} has no pinned baseurl"
        )
    else:
        baseurl = parser.get(section_name, "baseurl", fallback="").strip()
        indirection = next(
            (key for key in ("metalink", "mirrorlist")
             if parser.get(section_name, key, fallback="").strip()),
            "",
        )
        if indirection:
            errors.append(
                f"Allowlisted repository '{section_name}' in {source} resolves via {indirection}"
            )
        elif not baseurl:
            errors.append(f"Allowlisted repository '{section_name}' in {source} has no baseurl")
        else:
            entries = split_baseurls(baseurl)
            if not entries:
                errors.append(
                    f"Allowlisted repository '{section_name}' in {source} has no baseurl entries"
                )
            pins = {normalize_baseurl(value) for value in declared}
            for index, value in enumerate(entries, start=1):
                if normalize_baseurl(value) not in pins:
                    errors.append(
                        f"Repository '{section_name}' in {source} has unpinned baseurl entry {index}"
                    )

    options = policy.options.get(section_name)
    if options is None:
        errors.append(
            f"Allowlisted repository '{section_name}' in {source} has no security policy"
        )
    else:
        missing = REQUIRED_SECURITY_OPTIONS - options.keys()
        if missing:
            errors.append(
                f"Allowlisted repository '{section_name}' in {source} security policy "
                f"omits: {', '.join(sorted(missing))}"
            )
        if normalize_repo_option("sslverify", options.get("sslverify", "")) != "1":
            errors.append(
                f"Repository '{section_name}' security policy must keep sslverify enabled"
            )
        if options.get("proxy", ""):
            errors.append(
                f"Repository '{section_name}' security policy must not approve a proxy"
            )
        for name, expected in options.items():
            actual = parser.get(section_name, name, fallback="")
            if normalize_repo_option(name, actual) != normalize_repo_option(name, expected):
                if name == "proxy":
                    errors.append(
                        f"Repository '{section_name}' in {source} has a proxy configured; "
                        "proxies are not approved"
                    )
                else:
                    errors.append(
                        f"Repository '{section_name}' in {source} has {name}={actual!r}; "
                        f"expected {expected!r}"
                    )
    return errors


def check_repo_sections(
    parser: configparser.ConfigParser,
    source: str,
    policy: RepositoryPolicy,
    *,
    skip_sections: frozenset[str] = frozenset(),
) -> list[str]:
    """Check enabled repo IDs and attest all configured allowlisted IDs."""
    errors: list[str] = []
    for section_name in parser.sections():
        if section_name in skip_sections:
            continue
        enabled = is_repo_enabled(parser.get(section_name, "enabled", fallback="1"))
        if enabled:
            baseurl = parser.get(section_name, "baseurl", fallback="").lower()
            if "fedora" in section_name.lower() or "fedoraproject.org" in baseurl:
                errors.append(
                    f"Fedora repository '{section_name}' is enabled in {source}"
                )
                continue
            if section_name not in policy.allowed:
                errors.append(
                    f"Unapproved repository '{section_name}' is enabled in {source}"
                )
                continue
        if section_name in policy.allowed:
            errors.extend(repo_pin_errors(section_name, parser, source, policy))
    return errors


def verify_repository_policy(
    repos_dir: Path,
    policy: RepositoryPolicy,
    *,
    check_mode: bool = False,
) -> list[str]:
    """Check every repo file in a directory; ignore builder-only files off-image."""
    errors: list[str] = []
    for repo_file in sorted(repos_dir.glob("*.repo")):
        try:
            text = repo_file.read_text(encoding="utf-8", errors="replace")
            if check_mode and "# builder-only: true" in text:
                continue
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(text)
        except (OSError, configparser.Error) as error:
            errors.append(f"Could not read or parse repo file {repo_file}: {error}")
            continue
        errors.extend(
            check_repo_sections(
                parser, repo_file.name, policy,
            )
        )
    return errors


def resolve_reposdirs(
    parser: configparser.ConfigParser,
    default_dirs: list[Path],
    root: Path,
) -> list[Path]:
    if not parser.has_option("main", "reposdir"):
        return list(default_dirs)
    raw = parser.get("main", "reposdir", fallback="")
    entries = [entry.strip() for entry in raw.replace(",", " ").split() if entry.strip()]
    if not entries:
        return list(default_dirs)
    result: list[Path] = []
    for entry in entries:
        path = Path(entry)
        resolved = root / (path.relative_to("/") if path.is_absolute() else path)
        if resolved not in result:
            result.append(resolved)
    return result


def verify_runtime_repository_policy(
    policy: RepositoryPolicy,
    *,
    root: Path = Path("/"),
) -> list[str]:
    """Attest repo sections in DNF config and every directory DNF reads."""
    errors: list[str] = []
    default_dirs = [root / value for value in DEFAULT_REPOSDIRS]
    searched: list[Path] = []
    for relative in ("etc/dnf/dnf.conf", "etc/dnf/libdnf5.conf"):
        conf_path = root / relative
        if not conf_path.is_file():
            continue
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read_string(conf_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, configparser.Error) as error:
            errors.append(f"Could not read DNF configuration {conf_path}: {error}")
            continue
        if parser.has_section("main") and parser.get("main", "proxy", fallback="").strip():
            errors.append(f"A DNF-wide proxy is configured in {conf_path}; proxies are not approved")
        errors.extend(
            check_repo_sections(
                parser, str(conf_path), policy,
                skip_sections=frozenset({"main"}),
            )
        )
        for directory in resolve_reposdirs(parser, default_dirs, root):
            if directory not in searched:
                searched.append(directory)
    if not searched:
        searched = default_dirs
    for directory in searched:
        errors.extend(
            verify_repository_policy(
                directory, policy,
            )
        )
    return errors


def read_repository_policy(
    overlay: Path,
) -> tuple[RepositoryPolicy | None, list[str]]:
    """Read the fail-closed repository policy from the Utah overlay manifest."""
    try:
        repositories = tomllib.loads(overlay.read_text()).get("repositories", {})
    except (OSError, tomllib.TOMLDecodeError) as error:
        return None, [f"Could not read repository policy from {overlay}: {error}"]
    if not isinstance(repositories, dict):
        return None, [f"{overlay} [repositories] must be a table"]
    allowed = repositories.get("allowed")
    raw_baseurls = repositories.get("baseurls")
    raw_options = repositories.get("security")
    if not isinstance(allowed, list) or not isinstance(raw_baseurls, dict) or not isinstance(raw_options, dict):
        return None, [f"{overlay} needs [repositories] allowed, baseurls, and security policy"]
    if any(not isinstance(value, str) or not value for value in allowed):
        return None, [f"{overlay} [repositories].allowed entries must be non-empty strings"]
    if len(set(allowed)) != len(allowed):
        return None, [f"{overlay} [repositories].allowed contains duplicate IDs"]
    pins: dict[str, tuple[str, ...]] = {}
    for repo_id, values in raw_baseurls.items():
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(value, str) or not value.strip() for value in values)
        ):
            return None, [f"{overlay} baseurl pins for {repo_id} must be a non-empty string list"]
        if any(
            not normalize_baseurl(value).startswith(("https://", "file:///"))
            for value in values
        ):
            return None, [f"{overlay} baseurl pins for {repo_id} must use HTTPS or local file URLs"]
        pins[repo_id] = tuple(values)
    options: dict[str, dict[str, str]] = {}
    for repo_id, values in raw_options.items():
        if not isinstance(values, dict) or any(not isinstance(value, str) for value in values.values()):
            return None, [f"{overlay} security options for {repo_id} must be string values"]
        if set(values) != REQUIRED_SECURITY_OPTIONS:
            return None, [
                f"{overlay} security policy for {repo_id} must specify exactly "
                f"{', '.join(sorted(REQUIRED_SECURITY_OPTIONS))}"
            ]
        if normalize_repo_option("sslverify", values["sslverify"]) != "1" or values["proxy"]:
            return None, [
                f"{overlay} security policy for {repo_id} must require sslverify=1 and no proxy"
            ]
        if any(
            normalize_repo_option(name, values[name]) not in {"0", "1"}
            for name in ("gpgcheck", "repo_gpgcheck")
        ):
            return None, [
                f"{overlay} security policy for {repo_id} must set signature checks to 0 or 1"
            ]
        options[repo_id] = values
    names = set(allowed)
    if names != set(pins) or names != set(options):
        return None, [
            f"{overlay} repository IDs in allowed, baseurls, and security must match"
        ]
    return RepositoryPolicy(frozenset(names), pins, options), []


def verify_repository_policy_from_manifest(overlay: Path, *, check_mode: bool) -> list[str]:
    policy, errors = read_repository_policy(overlay)
    if errors or policy is None:
        return errors
    if check_mode:
        return verify_repository_policy(overlay.parent, policy, check_mode=True)
    return verify_runtime_repository_policy(policy)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("overlay", type=Path, nargs="?", default=None)
    args = parser.parse_args()
    overlay = args.overlay or args.manifest.with_name("utah.toml")

    repository_errors = verify_repository_policy_from_manifest(
        overlay, check_mode=args.check
    )
    if repository_errors:
        print("ERROR: repository policy violations:", file=sys.stderr)
        for error in repository_errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    flavor = os.environ.get("IMAGE_FLAVOR", "main")
    unavailable = set(section(overlay, "unavailable"))

    # Prefer the set install-packages.py actually resolved. Recomputing it here
    # is what let the two drift once: install added [fedora_v<major>] for the
    # running release and this check never did, so a contract package was
    # installed but never verified -- it could have gone missing silently. The
    # file is written by the install step, so in an image build it is always
    # present; the manifest path below is the off-image fallback for --check,
    # which asserts nothing about installation.
    resolved = Path("/usr/share/utah/contract.txt")
    if resolved.exists():
        contract = [line for line in resolved.read_text().split() if line]
        gnome_names = set(section(overlay, "gnome"))
        parity_names = set(section(overlay, "parity"))
        hardware_names = set(section(overlay, "hardware"))
        service_names = set(section(overlay, "services"))
        overlay_names = gnome_names | parity_names | hardware_names | service_names
        bluefin = [p for p in contract if p not in overlay_names]
        gnome = [p for p in contract if p in gnome_names]
        parity = [p for p in contract if p in parity_names]
        hardware = [p for p in contract if p in hardware_names]
        services = [p for p in contract if p in service_names]
    else:
        bluefin = [p for p in section(args.manifest, "fedora") if p not in unavailable]
        gnome = section(overlay, "gnome")
        parity = section(overlay, "parity")
        hardware = section(overlay, "hardware")
        services = section(overlay, "services")
    nvidia = list(NVIDIA_PACKAGES) if "nvidia" in flavor else []
    expected = [*bluefin, *gnome, *parity, *hardware, *services, *nvidia]

    print(
        f"Verifying {len(bluefin)} Bluefin packages, {len(gnome)} GNOME desktop packages,"
        f" {len(parity)} parity packages,"
        f" {len(hardware)} firmware packages,"
        f" {len(services)} desktop service packages, and {len(nvidia)} NVIDIA packages",
        flush=True,
    )
    if args.check:
        assert len(set(expected)) == len(expected), "RPM contract contains duplicate package names"
        return 0

    missing = [pkg for pkg in expected if not is_installed(pkg)]
    if missing:
        print(
            f"ERROR: {len(missing)} of {len(expected)} contract packages are not installed:",
            file=sys.stderr,
        )
        for pkg in missing:
            print(f"  - {pkg}", file=sys.stderr)
        return 1
    print(f"All {len(expected)} contract packages are present.")

    if "nvidia" not in flavor:
        return 0

    # Assert what a source build actually produces: a module for every kernel
    # the image can boot, and the userspace that goes with it.
    ogc = Path("/usr/lib/utah/ogc-kernel-release")
    ogc_release = ogc.read_text().strip() if ogc.exists() else None

    # This deliberately mirrors install-nvidia.sh, including its fallback. `rpm
    # -q kernel` is not reliable here: `kernel` is a metapackage a bootc base may
    # not carry, and on failure rpm prints "package kernel is not installed" to
    # stdout -- whose last word is "installed", which this used to accept as a
    # release string and then report a missing module for a kernel of that name.
    base = subprocess.run(["rpm", "-q", "kernel", "--qf", "%{VERSION}-%{RELEASE}.%{ARCH}\n"],
                          capture_output=True, text=True).stdout.split()
    base = base[-1].strip() if base else ""
    # Identify the kernel by its module tree, not by a build tree. A build tree
    # only exists while kernel-devel is installed, and install-nvidia.sh removes
    # that again once the module is compiled -- 215 MiB there is no reason to
    # ship. Requiring one here meant plain nvidia could never pass: the OGC
    # flavors only satisfied it because install-ogc-kernel.sh leaves its own
    # tree behind. A module tree is what says the image can boot that kernel,
    # which is the thing being asserted.
    if not base or not Path(f"/usr/lib/modules/{base}").is_dir():
        candidates = sorted(d.name for d in Path("/usr/lib/modules").glob("*")
                            if d.name != ogc_release and d.is_dir())
        if not candidates:
            print("ERROR: no kernel module tree found; cannot verify NVIDIA modules",
                  file=sys.stderr)
            return 1
        base = candidates[-1]

    releases = [base]
    if flavor == "nvidia-gaming":
        releases.append(ogc.read_text().strip())

    failed = False
    for release in releases:
        release = release.strip() if release else ""
        if not release:
            print("ERROR: empty kernel release; no kernel to check NVIDIA module against",
                  file=sys.stderr)
            failed = True
            continue
        module = Path(f"/usr/lib/modules/{release}/extra/nvidia/nvidia.ko")
        if not module.exists():
            print(f"ERROR: NVIDIA module missing for kernel {release}", file=sys.stderr)
            failed = True
    for path in (Path("/usr/bin/nvidia-smi"), Path("/usr/lib/utah/nvidia-driver-version")):
        if not path.exists():
            print(f"ERROR: NVIDIA userspace incomplete, {path} is missing", file=sys.stderr)
            failed = True
    if failed:
        return 1
    version = Path("/usr/lib/utah/nvidia-driver-version").read_text().strip()
    print(f"NVIDIA {version} present for: {', '.join(releases)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
