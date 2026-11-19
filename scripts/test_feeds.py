#!/usr/bin/env python3
"""Self-test for feeds.py using throwaway repos. Run: python3 scripts/test_feeds.py"""
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "feeds.py"
NEVER_BLOCK = HERE.parent / "never-block.yaml"


def run(files: dict[str, str], *args, today="2026-11-19", private=None, extra_args=()):
    tmp = Path(tempfile.mkdtemp())
    try:
        (tmp / "indicators").mkdir()
        shutil.copy(NEVER_BLOCK, tmp / "never-block.yaml")
        for name, body in files.items():
            (tmp / "indicators" / name).write_text(textwrap.dedent(body))
        out = tmp / "out"
        cmd = [sys.executable, str(SCRIPT), args[0] if args else "build", "--repo", str(tmp), "--today", today]
        if not args or args[0] == "build":
            cmd += ["--out", str(out)]
        cmd += list(extra_args)
        env = {k: v for k, v in os.environ.items() if k != "NEVER_BLOCK_PRIVATE"}
        if private is not None:
            env["NEVER_BLOCK_PRIVATE"] = private
        p = subprocess.run(cmd, capture_output=True, text=True, env=env)
        feeds = {f.name: f.read_text() for f in out.glob("*")} if out.exists() else {}
        return p.returncode, p.stdout + p.stderr, feeds
    finally:
        shutil.rmtree(tmp)


def doc(indicators: str, ticket="1001", category="c2", added="2026-11-19", extra=""):
    return {f"TICKET-{ticket}.yaml": f"ticket: {ticket}\ncategory: {category}\nadded: {added}\n{extra}indicators:\n{indicators}"}


class FeedsTest(unittest.TestCase):
    def assertRejected(self, files, needle):
        code, out, _ = run(files)
        self.assertEqual(code, 1, out)
        self.assertIn(needle, out)

    def test_good_build(self):
        code, out, feeds = run(doc("  - 45.83.64.1\n  - 45.83.65.0/24\n  - 2a0e:1c80::/48\n  - Evil-Login.Example.ORG.\n  - bad.pages.dev\n"))
        self.assertEqual(code, 0, out)
        self.assertEqual(feeds["ips.txt"], "45.83.64.1\n45.83.65.0/24\n2a0e:1c80::/48\n")
        self.assertEqual(feeds["ipv4.txt"], "45.83.64.1\n45.83.65.0/24\n")
        self.assertEqual(feeds["domains.txt"], "bad.pages.dev\nevil-login.example.org\n")
        self.assertIn("0.0.0.0 bad.pages.dev\n", feeds["domains-hosts.txt"])

    def test_empty_repo_builds_empty_feeds(self):
        code, out, feeds = run({})
        self.assertEqual(code, 0, out)
        self.assertEqual(feeds["ips.txt"], "")

    def test_rejects_private_and_doc_ranges(self):
        self.assertRejected(doc("  - 10.1.2.3\n"), "not a public address")
        self.assertRejected(doc("  - 203.0.113.5\n"), "not a public address")

    def test_rejects_broad_cidr(self):
        self.assertRejected(doc("  - 45.83.0.0/16\n"), "too broad")

    def test_rejects_host_bits_in_cidr(self):
        self.assertRejected(doc("  - 45.83.64.1/24\n"), "not a valid IP/CIDR")

    def test_rejects_never_block(self):
        self.assertRejected(doc("  - 8.8.8.8\n"), "never-block")
        self.assertRejected(doc("  - 104.16.5.5\n"), "never-block")

    def test_rejects_protected_domains(self):
        self.assertRejected(doc("  - login.microsoftonline.com\n"), "protected domain")
        self.assertRejected(doc("  - com\n"), "not a valid hostname")
        self.assertRejected(doc("  - www.google.com\n"), "protected domain")

    def test_shared_platforms(self):
        self.assertRejected(doc("  - pages.dev\n"), "shared platform")
        code, out, feeds = run(doc("  - phish.blob.core.windows.net\n"))  # subdomain is fine
        self.assertEqual(code, 0, out)
        self.assertEqual(feeds["domains.txt"], "phish.blob.core.windows.net\n")

    def test_rejects_urls_and_wildcards(self):
        self.assertRejected(doc("  - https://evil.example.org/x\n"), "hostnames only")
        self.assertRejected(doc("  - '*.evil.example.org'\n"), "hostnames only")

    def test_metadata_errors(self):
        self.assertRejected({"TICKET-1001.yaml": "ticket: 1002\ncategory: c2\nadded: 2026-11-19\nindicators:\n  - 45.83.64.1\n"},
                            "does not match file name")
        self.assertRejected(doc("  - 45.83.64.1\n", category="bad"), "category must be")
        self.assertRejected(doc("  - 45.83.64.1\n", extra="expire: 2026-12-01\n"), "unknown key")
        self.assertRejected({"evil.yaml": "x: 1\n"}, "TICKET-<number>.yaml")
        self.assertRejected(doc("  - 45.83.64.1\n", extra="expires: 2028-01-01\n"), "more than 365 days")

    def test_expiry_defaults_and_drop(self):
        files = doc("  - 45.83.64.1\n  - evil.example.org\n", added="2026-01-01")
        code, out, feeds = run(files, today="2026-05-01")  # IP (90d) expired, domain (180d) not
        self.assertEqual(code, 0, out)
        self.assertEqual(feeds["ips.txt"], "")
        self.assertEqual(feeds["domains.txt"], "evil.example.org\n")
        self.assertIn("expired", out)

    def test_duplicates_merge_latest_expiry(self):
        files = {**doc("  - 45.83.64.1\n", ticket="1", added="2026-10-01"),
                 **doc("  - value: 45.83.64.1\n    expires: 2027-06-01\n", ticket="2", added="2026-11-01")}
        code, out, feeds = run(files)
        self.assertEqual(code, 0, out)
        self.assertEqual(feeds["ips.txt"], "45.83.64.1\n")
        self.assertIn('"2027-06-01"', feeds["indicators.json"])
        self.assertIn('"1"', feeds["indicators.json"])

    def test_one_bad_entry_blocks_publish(self):
        code, out, feeds = run(doc("  - 45.83.64.1\n  - 8.8.8.8\n"))
        self.assertEqual(code, 1)
        self.assertEqual(feeds, {})

    def test_private_never_block(self):
        private = "networks:\n  - 45.83.64.0/24\nprotected_domains:\n  - partner.example.net\n"
        code, out, _ = run(doc("  - 45.83.64.9\n"), private=private)
        self.assertEqual(code, 1, out)
        self.assertIn("overlaps never-block network 45.83.64.0/24", out)
        code, out, _ = run(doc("  - portal.partner.example.net\n"), private=private)
        self.assertEqual(code, 1, out)
        self.assertIn("protected domain partner.example.net", out)

    def test_require_private(self):
        code, out, _ = run(doc("  - 45.83.64.9\n"), extra_args=["--require-private"])
        self.assertEqual(code, 1, out)
        self.assertIn("private list missing", out)
        code, out, _ = run(doc("  - 45.83.64.9\n"), private="networks: []\n", extra_args=["--require-private"])
        self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main(verbosity=1)
