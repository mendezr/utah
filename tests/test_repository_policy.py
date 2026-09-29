"""Behavioral tests for allowlisted DNF repository policy."""

from __future__ import annotations

import configparser
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify-rpm-contract.py"
spec = importlib.util.spec_from_file_location("verify_rpm_contract_policy", SCRIPT)
verifier = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verifier
spec.loader.exec_module(verifier)

REPO = "public-hummingbird-x86_64-rpms"
BASEURL = "https://packages.redhat.com/api/pulp-content/public-hummingbird/x86_64/"
ALLOWED = {REPO}
PINS = {REPO: (BASEURL,)}
SECURITY = {
    REPO: {"gpgcheck": "1", "repo_gpgcheck": "0", "sslverify": "1", "proxy": ""}
}


def policy(
    allowed: set[str] = ALLOWED,
    baseurls: dict[str, tuple[str, ...]] = PINS,
    options: dict[str, dict[str, str]] = SECURITY,
) -> verifier.RepositoryPolicy:
    return verifier.RepositoryPolicy(frozenset(allowed), baseurls, options)


def config(**options: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    body = [f"[{REPO}]", "enabled=1", f"baseurl={BASEURL}"]
    body.extend(f"{name}={value}" for name, value in options.items())
    parser.read_string("\n".join(body))
    return parser


class RepositoryOptionPolicyTests(unittest.TestCase):
    def errors(self, **options: str) -> list[str]:
        return verifier.check_repo_sections(
            config(**options), "hummingbird.repo", policy()
        )

    def test_approved_origin_and_security_options_pass(self) -> None:
        self.assertEqual(
            self.errors(gpgcheck="1", repo_gpgcheck="0", sslverify="1"), []
        )

    def test_equivalent_scheme_host_case_and_trailing_slash_pass(self) -> None:
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(
            f"[{REPO}]\nenabled=1\n"
            "baseurl=HTTPS://Packages.RedHat.COM/api/pulp-content/public-hummingbird/x86_64\n"
            "gpgcheck=1\nrepo_gpgcheck=0\nsslverify=1\n"
        )
        self.assertEqual(
            verifier.check_repo_sections(parser, "hummingbird.repo", policy()),
            [],
        )

    def test_every_url_in_a_multivalue_baseurl_must_be_pinned(self) -> None:
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(
            f"[{REPO}]\nenabled=1\n"
            f"baseurl={BASEURL} https://user:secret@evil.invalid/mirror\n"
            "gpgcheck=1\nrepo_gpgcheck=0\nsslverify=1\n"
        )
        errors = verifier.check_repo_sections(parser, "hummingbird.repo", policy())
        self.assertTrue(any("unpinned baseurl" in error for error in errors), errors)
        self.assertNotIn("secret", " ".join(errors))

    def test_a_metalink_beside_the_pinned_baseurl_is_rejected(self) -> None:
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(
            f"[{REPO}]\nenabled=1\nbaseurl={BASEURL}\n"
            "metalink=https://evil.invalid/mirrors.xml\n"
            "gpgcheck=1\nrepo_gpgcheck=0\nsslverify=1\n"
        )
        errors = verifier.check_repo_sections(parser, "hummingbird.repo", policy())
        self.assertTrue(any("metalink" in error for error in errors), errors)

    def test_each_security_sensitive_option_is_attested(self) -> None:
        changes = {
            "proxy": "https://proxy.evil.invalid:8080",
            "sslverify": "0",
            "gpgcheck": "0",
            "repo_gpgcheck": "1",
        }
        for name, value in changes.items():
            with self.subTest(option=name):
                actual = {
                    "gpgcheck": "1", "repo_gpgcheck": "0", "sslverify": "1"
                }
                actual[name] = value
                errors = self.errors(**actual)
                self.assertTrue(errors, f"changed {name} passed: {actual}")
                self.assertTrue(any(name in error or "proxy" in error for error in errors), errors)
                if name == "proxy":
                    self.assertNotIn("proxy.evil.invalid", " ".join(errors))

    def test_the_digest_pinned_local_repository_keeps_its_gpg_exception(self) -> None:
        local_id = "utah-packages"
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(
            "[utah-packages]\nenabled=1\nbaseurl=file:///etc/utah-packages\n"
            "gpgcheck=0\nrepo_gpgcheck=0\nsslverify=1\n"
        )
        self.assertEqual(
            verifier.check_repo_sections(
                parser, "utah-packages.repo",
                policy(
                    {local_id},
                    {local_id: ("file:///etc/utah-packages",)},
                    {local_id: {
                        "gpgcheck": "0", "repo_gpgcheck": "0", "sslverify": "1", "proxy": ""
                    }},
                ),
            ),
            [],
        )

    def test_an_allowlisted_id_needs_both_origin_and_security_pins(self) -> None:
        errors = verifier.check_repo_sections(
            config(gpgcheck="1", repo_gpgcheck="0", sslverify="1"),
            "hummingbird.repo", policy(baseurls={}, options={}),
        )
        self.assertTrue(any("baseurl" in error for error in errors), errors)
        self.assertTrue(any("security policy" in error for error in errors), errors)

    def test_runtime_checks_sections_in_dnf_conf(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dnf = root / "etc/dnf"
            dnf.mkdir(parents=True)
            (dnf / "dnf.conf").write_text(
                f"[main]\nreposdir=/custom/repos\n\n[{REPO}]\n"
                f"enabled=1\nbaseurl={BASEURL}\n"
                "gpgcheck=0\nrepo_gpgcheck=0\nsslverify=1\n"
            )
            errors = verifier.verify_runtime_repository_policy(policy(), root=root)
        self.assertTrue(any("gpgcheck" in error and "dnf.conf" in error for error in errors), errors)

    def test_runtime_rejects_a_dnf_wide_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dnf = root / "etc/dnf"
            dnf.mkdir(parents=True)
            (dnf / "dnf.conf").write_text(
                "[main]\nproxy=http://proxy.evil.invalid:8080\n"
            )
            errors = verifier.verify_runtime_repository_policy(policy(), root=root)
        self.assertTrue(any("DNF-wide proxy" in error for error in errors), errors)

    def test_runtime_scans_distro_reposdir_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repos = root / "etc/distro.repos.d"
            repos.mkdir(parents=True)
            (repos / "hummingbird.repo").write_text(
                f"[{REPO}]\nenabled=1\nbaseurl=https://evil.invalid/mirror\n"
                "gpgcheck=1\nrepo_gpgcheck=0\nsslverify=1\n"
            )
            errors = verifier.verify_runtime_repository_policy(policy(), root=root)
        self.assertTrue(any("unpinned baseurl" in error for error in errors), errors)

    def test_runtime_honors_a_custom_reposdir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dnf = root / "etc/dnf"
            dnf.mkdir(parents=True)
            (dnf / "dnf.conf").write_text("[main]\nreposdir=/custom/repos\n")
            repos = root / "custom/repos"
            repos.mkdir(parents=True)
            (repos / "hummingbird.repo").write_text(
                f"[{REPO}]\nenabled=1\nbaseurl=https://evil.invalid/mirror\n"
                "gpgcheck=1\nrepo_gpgcheck=0\nsslverify=1\n"
            )
            errors = verifier.verify_runtime_repository_policy(policy(), root=root)
        self.assertTrue(any("unpinned baseurl" in error for error in errors), errors)

    def test_shipped_manifest_and_repository_files_pass_offline_policy_check(self) -> None:
        self.assertEqual(
            verifier.verify_repository_policy_from_manifest(
                ROOT / "packages/utah.toml", check_mode=True
            ),
            [],
        )

    def test_manifest_cannot_authorize_proxy_or_disabled_tls_verification(self) -> None:
        for insecure in (
            'proxy = "http://proxy.invalid:8080"',
            'sslverify = "0"',
        ):
            with self.subTest(policy=insecure), tempfile.TemporaryDirectory() as tmp:
                overlay = Path(tmp) / "utah.toml"
                option, value = insecure.split(" = ", 1)
                security = {
                    "gpgcheck": '"1"', "repo_gpgcheck": '"0"',
                    "sslverify": '"1"', "proxy": '""',
                }
                security[option] = value
                overlay.write_text(
                    f'[repositories]\nallowed = ["{REPO}"]\n'
                    f'\n[repositories.baseurls]\n{REPO} = ["{BASEURL}"]\n'
                    f'\n[repositories.security."{REPO}"]\n'
                    + "".join(f"{name} = {entry}\n" for name, entry in security.items())
                )
                self.assertTrue(
                    verifier.read_repository_policy(overlay)[1],
                    "manifest should not approve a transport downgrade",
                )

    def test_manifest_cannot_pin_an_unencrypted_http_origin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            overlay = Path(tmp) / "utah.toml"
            http_baseurl = "http://" + BASEURL.removeprefix("https://")
            overlay.write_text(
                f'[repositories]\nallowed = ["{REPO}"]\n'
                f'\n[repositories.baseurls]\n{REPO} = ["{http_baseurl}"]\n'
                f'\n[repositories.security."{REPO}"]\n'
                'gpgcheck = "1"\nrepo_gpgcheck = "0"\nsslverify = "1"\nproxy = ""\n'
            )
            self.assertTrue(verifier.read_repository_policy(overlay)[1])

    def test_cli_check_rejects_an_insecure_allowlisted_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "bluefin.toml"
            manifest.write_text('[fedora]\npackages = []\n')
            overlay = root / "utah.toml"
            overlay.write_text(
                f'[repositories]\nallowed = ["{REPO}"]\n'
                f'\n[repositories.baseurls]\n{REPO} = ["{BASEURL}"]\n'
                f'\n[repositories.security."{REPO}"]\n'
                'gpgcheck = "1"\nrepo_gpgcheck = "0"\nsslverify = "1"\nproxy = ""\n'
            )
            (root / "hummingbird.repo").write_text(
                f"[{REPO}]\nenabled=1\nbaseurl={BASEURL}\n"
                "gpgcheck=0\nrepo_gpgcheck=0\nsslverify=0\n"
            )
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(sys, "argv", [str(SCRIPT), "--check", str(manifest), str(overlay)]), \
                    patch.dict(os.environ, {"IMAGE_FLAVOR": "main"}), \
                    redirect_stdout(stdout), redirect_stderr(stderr):
                code = verifier.main()
        self.assertEqual(code, 1)
        self.assertIn("sslverify", stderr.getvalue())

    def test_offline_check_covers_repo_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "hummingbird.repo").write_text(
                f"[{REPO}]\nenabled=1\nbaseurl={BASEURL}\n"
                "gpgcheck=0\nrepo_gpgcheck=0\nsslverify=1\n"
            )
            errors = verifier.verify_repository_policy(root, policy())
        self.assertTrue(any("gpgcheck" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
