#!/usr/bin/env python3
"""Validate indicator files and build the published blocklist feeds.

    python3 scripts/feeds.py check            # validate only (CI on pull requests)
    python3 scripts/feeds.py build --out DIR  # validate, then write feeds to DIR

Exit code is non-zero when any file has an error; nothing is written in that case.
Pass --today YYYY-MM-DD to evaluate expiry as of another date (tests).
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
INDICATOR_DIR = ROOT / "indicators"
NEVER_BLOCK = ROOT / "never-block.yaml"
# Organisation-specific entries (our own infrastructure, partners, vendors) are
# kept out of this public repo. They come from the NEVER_BLOCK_PRIVATE env var
# (an Actions secret holding YAML in the same format as never-block.yaml), or
# locally from never-block.private.yaml (git-ignored).
PRIVATE_ENV = "NEVER_BLOCK_PRIVATE"
PRIVATE_FILE_NAME = "never-block.private.yaml"

CATEGORIES = {"c2", "phishing", "malware", "brute-force", "scanning", "exfiltration", "spam", "other"}
FILE_KEYS = {"ticket", "category", "added", "expires", "indicators"}
ITEM_KEYS = {"value", "expires"}
DEFAULT_DAYS = {"ip": 90, "domain": 180}
MAX_DAYS = 365
MIN_PREFIX = {4: 24, 6: 48}  # broadest CIDR allowed
FILE_RE = re.compile(r"^TICKET-(\d+)\.ya?ml$")
LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
TLD_RE = re.compile(r"^([a-z]{2,63}|xn--[a-z0-9-]{1,59})$")


@dataclass
class Entry:
    value: str
    kind: str  # "ip" | "domain"
    ticket: str
    category: str
    added: dt.date
    expires: dt.date
    source: str


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def err(self, where: str, msg: str) -> None:
        self.errors.append(f"{where}: {msg}")

    def warn(self, where: str, msg: str) -> None:
        self.warnings.append(f"{where}: {msg}")


def parse_date(raw, where: str, key: str, rep: Report) -> dt.date | None:
    if not isinstance(raw, str):
        rep.err(where, f"'{key}' must be a date like 2026-11-19")
        return None
    try:
        return dt.date.fromisoformat(raw.strip())
    except ValueError:
        rep.err(where, f"'{key}' is not a valid YYYY-MM-DD date: {raw!r}")
        return None


def private_never_block_text() -> tuple[str, str] | None:
    """Return (label, YAML text) of the private never-block list, if one is configured."""
    env = os.environ.get(PRIVATE_ENV, "")
    if env.strip():
        return f"${PRIVATE_ENV}", env
    path = NEVER_BLOCK.parent / PRIVATE_FILE_NAME
    if path.is_file():
        return PRIVATE_FILE_NAME, path.read_text()
    return None


def load_never_block(rep: Report, require_private: bool):
    sources = [("never-block.yaml", NEVER_BLOCK.read_text())]
    private = private_never_block_text()
    if private:
        sources.append(private)
    elif require_private:
        rep.err("never-block", f"private list missing: set the {PRIVATE_ENV} secret")
    nets, protected, shared = [], set(), set()
    for label, text in sources:
        try:
            # BaseLoader keeps every scalar a string (no surprise ints/dates).
            data = yaml.load(text, Loader=yaml.BaseLoader) or {}
        except yaml.YAMLError as e:
            rep.err(label, f"YAML syntax error: {e}")
            continue
        if not isinstance(data, dict):
            rep.err(label, "expected networks / protected_domains / shared_platforms")
            continue
        for raw in data.get("networks") or []:
            try:
                nets.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                rep.err(label, f"invalid network {raw!r}")
        protected |= {d.lower().rstrip(".") for d in data.get("protected_domains") or []}
        shared |= {d.lower().rstrip(".") for d in data.get("shared_platforms") or []}
    return nets, protected, shared


def is_parent_or_same(parent: str, child: str) -> bool:
    return child == parent or child.endswith("." + parent)


def classify(value: str, where: str, rep: Report, nets, protected, shared) -> tuple[str, str] | None:
    """Return (kind, normalised value) or None after recording an error."""
    v = value.strip()
    if not v:
        rep.err(where, "empty indicator")
        return None

    # --- IP / CIDR ---
    if re.fullmatch(r"[0-9a-fA-F:.]+(/\d{1,3})?", v) and (":" in v or re.fullmatch(r"[\d./]+", v)):
        try:
            net = ipaddress.ip_network(v, strict=True)
        except ValueError as e:
            rep.err(where, f"{v}: not a valid IP/CIDR ({e})")
            return None
        if net.prefixlen < MIN_PREFIX[net.version]:
            rep.err(where, f"{v}: CIDR too broad (IPv{net.version} must be /{MIN_PREFIX[net.version]} or smaller)")
            return None
        if not net.is_global or net.is_multicast:
            rep.err(where, f"{v}: not a public address (private, reserved or documentation range)")
            return None
        for n in nets:
            if n.version == net.version and net.overlaps(n):
                rep.err(where, f"{v}: overlaps never-block network {n}")
                return None
        return "ip", str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)

    # --- Domain ---
    d = v.lower().rstrip(".")
    if any(c in d for c in "/:*@ ") or d.startswith("http"):
        rep.err(where, f"{v}: hostnames only (no scheme, path, port or wildcard)")
        return None
    if not d.isascii():
        rep.err(where, f"{v}: use the punycode (xn--) form for internationalised domains")
        return None
    labels = d.split(".")
    if len(labels) < 2 or len(d) > 253 or not all(LABEL_RE.match(lab) for lab in labels) or not TLD_RE.match(labels[-1]):
        rep.err(where, f"{v}: not a valid hostname")
        return None
    for p in protected:
        if is_parent_or_same(p, d) or is_parent_or_same(d, p):
            rep.err(where, f"{v}: conflicts with protected domain {p}")
            return None
    for s in shared:
        if is_parent_or_same(d, s):  # d is the platform itself or a parent of it
            rep.err(where, f"{v}: is a shared platform ({s}); block the specific subdomain instead")
            return None
    return "domain", d


def load_entries(today: dt.date, rep: Report, require_private: bool = False) -> list[Entry]:
    nets, protected, shared = load_never_block(rep, require_private)
    entries: list[Entry] = []
    files = sorted(p for p in INDICATOR_DIR.glob("*") if p.is_file() and not p.name.startswith((".", "_")))
    for path in files:
        where = f"indicators/{path.name}"
        m = FILE_RE.match(path.name)
        if not m:
            rep.err(where, "file must be named TICKET-<number>.yaml")
            continue
        try:
            doc = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        except yaml.YAMLError as e:
            rep.err(where, f"YAML syntax error: {e}")
            continue
        if not isinstance(doc, dict):
            rep.err(where, "expected a mapping with ticket, category, added, indicators")
            continue
        unknown = set(doc) - FILE_KEYS
        if unknown:
            rep.err(where, f"unknown key(s): {', '.join(sorted(unknown))}")
        missing = {"ticket", "category", "added", "indicators"} - set(doc)
        if missing:
            rep.err(where, f"missing key(s): {', '.join(sorted(missing))}")
            continue

        ticket = str(doc["ticket"]).strip()
        if not ticket.isdigit():
            rep.err(where, "ticket must be the numeric ticket number")
        elif ticket != m.group(1):
            rep.err(where, f"ticket {ticket} does not match file name")
        category = str(doc["category"]).strip()
        if category not in CATEGORIES:
            rep.err(where, f"category must be one of: {', '.join(sorted(CATEGORIES))}")
        added = parse_date(doc["added"], where, "added", rep)
        if added is None:
            continue
        if added > today + dt.timedelta(days=1):
            rep.err(where, "'added' is in the future")
        file_exp = parse_date(doc["expires"], where, "expires", rep) if "expires" in doc else None

        items = doc["indicators"]
        if not isinstance(items, list) or not items:
            rep.err(where, "'indicators' must be a non-empty list")
            continue
        for i, item in enumerate(items, 1):
            iw = f"{where} indicator #{i}"
            exp = file_exp
            if isinstance(item, dict):
                bad = set(item) - ITEM_KEYS
                if bad or "value" not in item:
                    rep.err(iw, "expected 'value' and optional 'expires'")
                    continue
                if "expires" in item:
                    exp = parse_date(item["expires"], iw, "expires", rep)
                    if exp is None:
                        continue
                item = item["value"]
            if not isinstance(item, str):
                rep.err(iw, "indicator must be a single value")
                continue
            got = classify(item, iw, rep, nets, protected, shared)
            if not got:
                continue
            kind, value = got
            expires = exp or added + dt.timedelta(days=DEFAULT_DAYS[kind])
            if expires < added:
                rep.err(iw, f"{value}: expires before it was added")
                continue
            if expires > added + dt.timedelta(days=MAX_DAYS):
                rep.err(iw, f"{value}: expiry more than {MAX_DAYS} days after 'added'")
                continue
            entries.append(Entry(value, kind, ticket, category, added, expires, where))
    return entries


def merge_active(entries: list[Entry], today: dt.date, rep: Report) -> dict[str, dict]:
    """Drop expired entries and merge duplicates (latest expiry wins)."""
    active: dict[str, dict] = {}
    expired_files: dict[str, int] = {}
    for e in entries:
        if e.expires < today:
            expired_files[e.source] = expired_files.get(e.source, 0) + 1
            continue
        cur = active.get(e.value)
        if cur is None:
            active[e.value] = {"value": e.value, "type": e.kind, "tickets": [e.ticket],
                               "categories": [e.category], "added": e.added.isoformat(),
                               "expires": e.expires.isoformat()}
        else:
            if e.ticket not in cur["tickets"]:
                cur["tickets"].append(e.ticket)
            if e.category not in cur["categories"]:
                cur["categories"].append(e.category)
            cur["added"] = min(cur["added"], e.added.isoformat())
            cur["expires"] = max(cur["expires"], e.expires.isoformat())
    for src, n in sorted(expired_files.items()):
        rep.warn(src, f"{n} expired indicator(s) no longer published; delete the file once all have expired")
    return active


def ip_sort_key(v: str):
    n = ipaddress.ip_network(v, strict=False)
    return (n.version, n.network_address, n.prefixlen)


def write_feeds(active: dict[str, dict], out: Path) -> dict[str, int]:
    out.mkdir(parents=True, exist_ok=True)
    ips = sorted((v for v, e in active.items() if e["type"] == "ip"), key=ip_sort_key)
    v4 = [v for v in ips if ":" not in v]
    v6 = [v for v in ips if ":" in v]
    domains = sorted(v for v, e in active.items() if e["type"] == "domain")

    # Plain one-per-line, no comments or headers: OPNsense, FortiGate and PAN-OS
    # all read this format, and not all of them skip comment lines.
    def write(name: str, lines: list[str]) -> None:
        (out / name).write_text("".join(f"{line}\n" for line in lines))

    write("ips.txt", ips)
    write("ipv4.txt", v4)
    write("ipv6.txt", v6)
    write("domains.txt", domains)
    write("domains-hosts.txt", [f"0.0.0.0 {d}" for d in domains])
    meta = sorted(active.values(), key=lambda e: (e["type"], e["value"]))
    (out / "indicators.json").write_text(json.dumps(meta, indent=1) + "\n")
    return {"ips": len(ips), "ipv4": len(v4), "ipv6": len(v6), "domains": len(domains)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["check", "build"])
    ap.add_argument("--out", type=Path, help="output directory for build")
    ap.add_argument("--require-private", action="store_true",
                    help=f"fail if no private never-block list is configured (${PRIVATE_ENV})")
    ap.add_argument("--repo", type=Path, default=ROOT, help="repo root (default: this checkout)")
    ap.add_argument("--today", type=dt.date.fromisoformat, default=dt.datetime.now(dt.timezone.utc).date())
    args = ap.parse_args()
    if args.command == "build" and not args.out:
        ap.error("build needs --out")

    global INDICATOR_DIR, NEVER_BLOCK
    INDICATOR_DIR, NEVER_BLOCK = args.repo / "indicators", args.repo / "never-block.yaml"
    rep = Report()
    entries = load_entries(args.today, rep, args.require_private)
    active = merge_active(entries, args.today, rep)

    for w in rep.warnings:
        print(f"WARNING {w}")
    for e in rep.errors:
        print(f"ERROR   {e}")
    if rep.errors:
        print(f"\n{len(rep.errors)} error(s); nothing published.")
        return 1

    counts = {"ips": sum(e["type"] == "ip" for e in active.values()),
              "domains": sum(e["type"] == "domain" for e in active.values())}
    if args.command == "build":
        counts = write_feeds(active, args.out)
        print(f"Wrote feeds to {args.out}")
    print("OK: " + ", ".join(f"{k}={v}" for k, v in counts.items()) + f" active as of {args.today}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
