# Tenax threat feeds

IP addresses and hostnames the Tenax SOC has confirmed as malicious during
investigations, published as plain-text blocklists that firewalls and DNS
filters can pull on a schedule. Free to use, provided as-is with no warranty.

This repository is a read-only mirror. Changes are made and reviewed in our
internal repository, so issues and pull requests here aren't monitored.

## Feeds

Rebuilt on every approved change and daily (06:15 UTC), so expired entries drop
off on their own. All files are one entry per line with no comments or headers.

| File | Contents | Use with |
|---|---|---|
| `ips.txt` | IPv4 + IPv6 addresses and CIDRs | OPNsense URL Table alias, FortiGate, PAN-OS EDL |
| `ipv4.txt` / `ipv6.txt` | Same, split by family | Platforms that need one family per list |
| `domains.txt` | Hostnames | OPNsense Unbound blocklist, Pi-hole, DNS filters |
| `domains-hosts.txt` | `0.0.0.0 hostname` | Tools that only read hosts-file format |
| `indicators.json` | Each entry with type, ticket(s), category, added, expires | Scripting, auditing |

The files are on the `feeds` branch:

```
https://raw.githubusercontent.com/Tenax-Software-Solutions/threat-feeds/feeds/<file>
```

GitHub caches raw files for about 5 minutes, which is fine at an hourly refresh.

## Using the feeds

### OPNsense

**IPs:**

1. **Firewall → Aliases → Add**: Type **URL Table (IPs)**, Name `tenax_blocklist`,
   Content `https://raw.githubusercontent.com/Tenax-Software-Solutions/threat-feeds/feeds/ips.txt`,
   Refresh Frequency **0 days 1 hour**.
2. Add block rules that use the alias:
   - **WAN, inbound**: Source `tenax_blocklist`, action Block.
   - **LAN (or Floating, outbound)**: Destination `tenax_blocklist`, action Block or Reject.

     The outbound rule is the one that stops C2 traffic and phishing callbacks.
3. **Firewall → Diagnostics → Aliases** shows the loaded entries.

**Hostnames:**

1. **Services → Unbound DNS → Blocklist**: enable it, and add
   `https://raw.githubusercontent.com/Tenax-Software-Solutions/threat-feeds/feeds/domains.txt`
   under the custom blocklist URLs.
2. Apply. Clients have to use the firewall as their DNS server for this to work.

Don't resolve hostnames into a firewall IP alias. Many malicious hostnames sit
behind shared hosting or a CDN, and blocking those IPs blocks innocent sites.

### Other platforms

- **FortiGate**: Security Fabric → External Connectors → Threat Feeds → IP Address
  (`ips.txt`) or Domain Name (`domains.txt`).
- **Palo Alto**: Objects → External Dynamic Lists, type IP List (`ips.txt`) or
  Domain List (`domains.txt`).
- **Pi-hole / AdGuard Home**: add `domains.txt` as a blocklist.

## How entries are added

1. A SOC analyst adds a file `indicators/TICKET-<number>.yaml`, copied from
   [`indicators/_TEMPLATE.yaml.example`](indicators/_TEMPLATE.yaml.example),
   and opens a pull request.
2. CI checks every entry (see below). A SOC lead reviews and merges it.
3. The feeds are rebuilt and published within a few minutes.

Each entry carries only an internal ticket number and a generic category. This
repository is public: never commit names of affected organisations, internal
hostnames, usernames or investigation detail.

When merging, keep the commit message to the PR title and number. The default
message is set by the templates in `.gitea/default_merge_message/`; remove any
trailer lines (such as `Reviewed-on:`) if they appear, since commit messages are
published here.

More indicators for the same ticket go in the same file. To remove an indicator
early (for example a false positive), open a PR that deletes the line, or set its
`expires` to today.

### What CI rejects

- Private, reserved, documentation or multicast addresses.
- CIDRs broader than IPv4 /24 or IPv6 /48.
- Anything overlapping [`never-block.yaml`](never-block.yaml): public DNS
  resolvers, Cloudflare's shared ranges, protected domains (Microsoft 365, Google
  and so on, including their parents and subdomains), and the root of shared
  platforms such as `pages.dev` or `windows.net`. A specific subdomain on a
  shared platform (`phish.blob.core.windows.net`) is allowed. A private list in
  the same format adds our own infrastructure.
- URLs, ports, paths, wildcards, and non-punycode domains.
- Missing or wrong ticket, category or dates, unknown keys (catches typos like
  `expire:`), or an expiry more than 365 days after `added`.

If any file has an error, nothing is published. The last good feed stays live.

### Expiry

IPs default to 90 days and domains to 180 days after `added`. Set `expires:`
for the whole file, or on a single indicator, to change that (365 days at most).
If an indicator appears again under a new ticket, add it to the new ticket's
file. Duplicates are merged and the latest expiry wins.

## Development

```sh
pip install pyyaml
python3 scripts/feeds.py check                 # validate
python3 scripts/feeds.py build --out /tmp/out  # build feeds locally
python3 scripts/test_feeds.py                  # self-test
```

Our own never-block entries come from the `NEVER_BLOCK_PRIVATE` CI secret, or
from a git-ignored `never-block.private.yaml` when you run the script locally.
