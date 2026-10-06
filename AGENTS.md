# Agent rules

## This repo is public: placeholders only, never real environment data

Anything committed here — code, comments, check/finding text, tests,
testdata bundles and golden files, docs, commit messages — must use placeholders, not values
copied from a live Dynatrace cluster or from the lab apps it monitors. This
applies even when you just read the value from a live response and it would
make a test "more realistic".

Never commit:

- Cluster hostnames / URLs, environment IDs, cluster IDs, dashboard / object IDs
- API tokens, token IDs, license keys, account names, email addresses
- Real host names, private IPs / AWS hostnames (`ip-…compute.internal`)
- Real entity IDs (`HOST-…`, `PROCESS_GROUP-…`, `SERVICE-…` with real hex)
- Real app, team, host-group, VM, tag, rule or container names from the lab
- Audit snapshots that identify a real environment (counts are fine once
  every name and ID in them is a placeholder)

Use these instead (keep them consistent across files):

| Kind | Placeholder |
|---|---|
| Cluster URL | `https://<cluster-host>` |
| Environment ID | `<env-id>` |
| Other object IDs | `<dashboard-id>`, `<object-id>`, … |
| Entity IDs | `HOST-0000000000000001`, `PROCESS_GROUP-0000000000000001`, `SERVICE-0000000000000001` |
| Host names | `host-01.example.internal`, `ip-10-0-0-1.ec2.internal` |
| IPs | `10.0.0.x` (RFC 1918) or `192.0.2.x` (documentation range) |
| Apps / teams / host groups | `shop-app`, `payments`, `team:payments`, `shop-web`, `shop-svc` |
| Emails | `user@example.com` |

When a test needs a real response *shape* (e.g. a validateOnly body from a
new Managed version), keep the structure verbatim and replace the values.
Schema IDs (`builtin:…`), metric keys, API paths and Dynatrace version
numbers are product facts, not environment data — those are fine.

Local-only material (live audit snapshots, cluster links, `.audit/`,
`reports/`, `findings.json`, `report.md`) stays out of git; `.gitignore` already covers the usual
paths.

Before committing, check the diff:

```bash
git diff --cached | grep -nE 'ip-172-|compute\.internal|managed-sprint|dynalabs|(HOST|PROCESS_GROUP|SERVICE)-[1-9A-F][0-9A-F]{15}|@dynatrace\.com|dt0c01\.'
```

Anything it prints (other than this file) must be replaced first.
