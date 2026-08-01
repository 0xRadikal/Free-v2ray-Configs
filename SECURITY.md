# 🔐 Security Policy

This file describes how to report a problem, what is in scope, and — just as
importantly — **what this repository does not protect you from**. Every factual
claim below is checkable against the code in this repository; line references
point at [`.github/workflows/aggregate.yml`](.github/workflows/aggregate.yml).

---

## ⚠️ Read this first: the biggest risk is not in this code

This repository is an **aggregator**. It collects configs that 21 third-party
upstreams have already published, deduplicates them, rebrands the remarks, and
checks that the files are structurally valid for real clients.

It does **not** operate, own, audit, or vet the proxy servers those configs point
at.

> **Using a free proxy config means routing your traffic through a machine
> operated by someone you do not know and cannot identify.** That operator can
> see traffic metadata, can see anything not end-to-end encrypted, can log, can
> throttle, and can disappear. No amount of validation in this pipeline changes
> that, and nothing in this repository should be read as a safety claim about a
> server.

Concretely, the following are **not** claims this project makes:

- ❌ that a config is safe, private, or anonymous
- ❌ that `verified/` configs are trustworthy — `verified/` means only *"this
  endpoint answered a real HTTP request from the machine that ran the test"*
  (see [README → Does it actually work?](README.md#-does-it-actually-work))
- ❌ that any config will work for you, from your network
- ❌ that upstream sources are audited

If you need a trustworthy tunnel, run your own server. That is not a slogan;
it is the only configuration in which the operator is someone you can hold
accountable.

---

## 📦 Supported versions

| What | Supported |
|---|---|
| `main` branch, current published output | ✅ yes — this is the only supported state |
| Older output commits | ❌ no — they are made unreachable and garbage-collected by design (rolling squash, see [README](README.md#-how-publishing-stays-cheap)) |
| Tags / releases | ❌ none are published |
| Forks | ❌ not supported; a fork's output is whatever its owner runs |

There is no patch-backport model here. The output is regenerated from scratch
roughly every 15 minutes, so **the fix for a bad release is the next run** —
which is also why publishing is fail-closed (below): a broken release must never
be allowed to overwrite a good one in the first place.

---

## 🐞 Reporting a vulnerability

**For issues in the code, workflow, or published output — open a GitHub Issue:**
<https://github.com/0xRadikal/Free-v2ray-Configs/issues>

**If disclosing publicly would put users at risk, do not open an issue.**
Contact the maintainer privately first, via Telegram: [@Raydikalx](https://t.me/Raydikalx).

When reporting, please include:

1. what you did (exact command, URL, or file),
2. what you expected,
3. what actually happened, and
4. the commit SHA of `scripts/**` you were looking at, if relevant.

Please **do not** paste real credentials, private keys, or personal UUIDs into a
public issue — redact them.

Expectations, stated honestly: this is a single-maintainer hobby project. There
is **no bounty**, **no SLA**, and response is best-effort. Reports that come with
a reproduction are acted on far faster than reports that do not.

---

## 🔑 Secrets and tokens

These are verifiable claims, not assurances:

- **The workflow references no repository secrets at all.** `grep -n 'secrets\.'
  .github/workflows/aggregate.yml` returns nothing. Publishing uses the
  automatic, per-run `GITHUB_TOKEN` that GitHub Actions injects — there is no
  Personal Access Token in the workflow, and none is required to run it.
- **Least-privilege permissions.** The workflow declares exactly one permission
  (line 62–63):

  ```yaml
  permissions:
    contents: write
  ```

  No `packages:`, no `id-token:`, no `actions: write`, no `pull-requests:`.
- **No credentials are committed.** If you find anything that looks like a
  credential anywhere in this repository — including in the published output —
  please report it via the private channel above, not as a public issue.

---

## 🔗 Supply chain

| Component | How it is pinned | Integrity verified? |
|---|---|---|
| Python runtime deps (`requirements.txt`) | exact `==` pins: `requests==2.34.2`, `PyYAML==6.0.3`, `maxminddb==3.1.1` | by pip, against PyPI |
| `xray-knife` 10.1.1 | version **and** SHA-256 of both the release archive and the extracted binary, cross-checked against upstream's own `.dgst` file in MD5/SHA-256/SHA-512 | ✅ yes |
| `sing-box` 1.13.14 | version **and** SHA-256 of both the release archive (checked before extraction) and the extracted binary (checked before install) | ✅ yes |
| `mihomo` v1.19.29 | version **and** SHA-256 of both the release archive (checked before extraction) and the extracted binary (checked before install) | ✅ yes |
| GitHub Actions | commit SHAs, with the version in a trailing comment: `checkout` v4.4.0, `setup-python` v5.6.0, `cache` v4.3.0, `upload-artifact` v4.6.2 | ✅ yes — a SHA is immutable |
| Dependency updates | [`.github/dependabot.yml`](.github/dependabot.yml) — `pip` + `github-actions`, weekly | — |
| Vulnerability alerts | Dependabot alerts **and** automated security updates are enabled on the repository | ✅ yes — the live count is on the Security tab; see below for how the first one was handled |

### The gap that used to be here, and how it was closed

Until recently `sing-box` and `mihomo` were downloaded from GitHub Releases with
only the *version* pinned, and this section documented that as an open item
rather than hiding it. It is now closed. Both binaries are verified twice — the
archive before it is unpacked, and the extracted binary before it is installed —
using a shared `verify()` helper so the two paths cannot drift apart:

| Artifact | SHA-256 |
|---|---|
| `sing-box-1.13.14-linux-amd64.tar.gz` (23,832,905 B) | `f48703461a15476951ac4967cdad339d986f4b8096b4eb3ff0829a500502d697` |
| extracted `sing-box` binary | `68aeab83cc4ab2659a5b92232261a20746ccdafc3b3d1e19b2d63247eec3bbf7` |
| `mihomo-linux-amd64-v1.19.29.gz` (17,858,765 B) | `60de76a35a6cbf7b4fa4a20f5c257c24345d1d635ab1aa3877022a1997ef413c` |
| extracted `mihomo` binary | `9c397be7489538628fae781bc005e4c5b8cd7b0961b8bb2ca815c8150f193577` |

Each value was established from **two independent sources**: the `digest` field
GitHub itself reports for the release asset, and a separate local download hashed
with `sha256sum`. Both binaries were then executed and confirmed to self-report
the pinned version (`sing-box version 1.13.14`, `Mihomo Meta v1.19.29`).

Ordering is part of the guarantee, not a detail: verifying an archive *after*
unpacking it would already have handed untrusted input to `tar`/`gunzip`. Four
tests in `scripts/test_pipeline.py` enforce this — that every step downloading
from `releases/download/` compares a `sha256sum` and treats a mismatch as fatal,
that every declared hash is actually *used* (a declared-but-unused hash is the
classic hollow green), that no two declared hashes are identical (copy-paste
trap), and that each verification precedes the extraction or install it guards.

The reasoning that motivated the original gap still stands, and is why the
version pin alone was never enough:

<!-- Paraphrase, not a quotation. The comment sits in the preamble to the
     workflow's "📦 Install xray-knife (pinned + checksum verified)" step. It is
     cited by step name rather than by line number on purpose: this reference
     used to read "aggregate.yml:376-379" and went stale the moment the step
     above it grew, which is precisely the class of quiet inaccuracy this
     document is written against. It reads
     "فقط pin کردنِ *نسخه* تضمینی نمی‌دهد، چون یک انتشارِ گیت‌هاب قابلِ جای‌گزینی
     است (asset را می‌توان با همان نام دوباره بارگذاری کرد)." Presenting an English
     rendering of that in blockquote form would invite a reader to go looking for
     these exact words and find something else — a small gap between what is
     advertised and what is delivered. -->
*(paraphrase — the original is Persian)* A GitHub release asset is replaceable:
the same asset name can be re-uploaded with different bytes. Pinning only the
*version* therefore guarantees nothing about the bytes you receive.

`xray-knife` was hardened this way first; the two validator binaries have now
been brought up to the same standard, so all three downloaded binaries are
byte-pinned rather than merely version-pinned.

The GitHub Actions used to carry the same weakness — they were referenced by
mutable major tags — and that has since been closed: every `uses:` in the
workflow now names an immutable commit SHA, with the human version kept in a
trailing comment so Dependabot can still propose upgrades. That is why the row
above reads ✅ where it previously read ❌.

**What the checksums now buy, stated precisely.** The threat they close is an
attacker who can replace an asset on the `SagerNet/sing-box` or
`MetaCubeX/mihomo` release pages — i.e. a compromise of those upstream projects.
Previously that would have been silent; now the run fails with an explicit
mismatch and the offending file is deleted. Even before, the blast radius was
limited to the CI runner and to *validation being wrong* (a bad config declared
valid); it never granted write access to this repository's history, because
publishing uses the scoped `GITHUB_TOKEN`, not a PAT.

**Residual risk, stated too.** A checksum pins bytes, not intent: if a release
were malicious *at the moment these hashes were recorded*, pinning would
faithfully reproduce that. The hashes therefore guarantee "the same bytes we
verified", not "bytes proven benign". Raising the pin on a version bump is a
deliberate act that must repeat the two-source verification above.

### The first alert, and what it actually meant

Turning alerts on produced one almost immediately —
[GHSA-gc5v-m9x4-r6x2](https://github.com/advisories/GHSA-gc5v-m9x4-r6x2)
(CVE-2026-25645, moderate): insecure temp-file reuse in the
`extract_zipped_paths()` utility of `requests`, affecting every version
`< 2.33.0`. It is recorded here rather than quietly patched, because how an
alert is *assessed* is as much a part of a security posture as how fast it is
closed.

Measured exposure, before deciding anything:

- this project never calls `extract_zipped_paths()` — its entire `requests`
  surface is a single `requests.get(url, timeout=…, headers=…)` call;
- inside the previously pinned 2.32.4, `requests` itself called it once, at import
  time, on `DEFAULT_CA_BUNDLE_PATH` — a constant path belonging to the
  installation, not user input — and on an ordinary filesystem install that call
  returns at the first `os.path.exists()` and never reaches the
  `tempfile.mkstemp()` branch, which requires the package to be running from
  inside a zip archive;
- in 2.33.0 and later the internal call was removed altogether.

So the practical exploitability here was close to nil. The pin was still raised,
to `2.34.2`, for two reasons: an open alert on the default branch is a fact
about the repository regardless of reachability, and "not reachable today" is a
property of the current code, which changes. Before the pin moved, the full
301-test suite was run against 2.34.2 and a live fetch was made through the
real `fetch_source()` path (HTTP 200, configs parsed, output guard satisfied) —
the version was not raised on the assumption that a minor bump is harmless.

---

## 🛡️ Fail-closed publishing (security-relevant behaviour)

Publishing is a force-push with a lease, so it is treated as a dangerous
operation and guarded accordingly. The first gate below runs in its own workflow
step; the rest are implemented in the publish step:

- **Validation gate.** Every generated `clash.yaml` / `singbox.json` is checked
  with `sing-box check -c` and `mihomo -t -d … -f` — implemented in
  [`scripts/validate.py`](scripts/validate.py) and invoked as
  `python scripts/validate.py --out . --strict --json validation.json`.
  **Any failure aborts the run** and the previous good release stays in place.
  The `--strict` flag is what makes it a gate rather than a report, and the step
  carries no `continue-on-error`.
  `validate.py` does contain a structural-only fallback for when the validator
  binaries are absent, which would downgrade rather than fail — that path is
  unreachable in CI, because the install step runs under `set -euo pipefail` and
  ends with `sing-box version` and `mihomo -v`, so a failed download aborts the
  run before validation is reached. The fallback exists for local runs.
- **`--force-with-lease`, never a bare `--force`.** A contested push is rejected,
  the step re-anchors onto the newer commit, and both the human commit and the
  new output survive.
- **Source-regression guard.** Every path differing between the anchor commit and
  the branch tip is classified; if anything outside the known output set changed,
  the step refuses to publish rather than reverting a human's work.
- **Output sanity gates.** Publishing is refused if any critical output file is
  missing or empty, if `all/configs.txt` has fewer than 100 payload lines, or if
  the computed tree holds fewer than 15 files.
- **Source must-exist guard.** The publish tree is required to still contain
  `scripts/aggregate.py`, `scripts/core.py`, `README.md`, and the workflow file.
- **No recursion.** The `push:` trigger is filtered to `scripts/**` and the
  workflow file — paths the bot never writes — and pushes made with
  `GITHUB_TOKEN` do not start new workflow runs.

---

## 🔒 Branch and tag protection

Two repository rulesets are active. Neither has any bypass actor, so they apply
to the repository owner exactly as they apply to anyone else.

| Ruleset | Target | Rules | Scope |
| --- | --- | --- | --- |
| `main: no deletion, linear history only` | branch | `deletion`, `required_linear_history` | `~DEFAULT_BRANCH` |
| `tags: protected (no delete, no rewrite)` | tag | `deletion`, `non_fast_forward`, `update` | `~ALL` |

Every rule above was first measured against a throwaway ref — never against
`main` or `v1.0` — by attempting the operation it is supposed to refuse and
confirming HTTP 422, and by attempting the operations it must still allow and
confirming they succeed. Refusals report
`Cannot delete this tag`, `Cannot force-push to this tag`, or
`Cannot update this protected ref.`

The tag rules were then re-measured a second time against the armed `~ALL`
ruleset itself, using a disposable tag, because "the rule works on a glob I
chose" and "the rule works at the scope I shipped" are two different claims.
The branch rules were not re-tested that way on `main`: deliberately attempting
to delete the default branch of a live repository is not a test worth running.
They were confirmed instead by reading the effective rules for `main` and by
watching real publishing runs continue to succeed afterwards.

Tag **creation** is deliberately still permitted (measured: HTTP 201), so
cutting a new release is unaffected; what is blocked is moving or deleting a tag
that already exists. `v1.0` was confirmed to point at the same commit before and
after all of this, cross-checked against the release record.

One measured detail worth stating so it is not mistaken for a hole later: a
*no-op* ref write — setting a tag to the sha it already has — returns HTTP 200
even under `update`. Nothing is rewritten in that case, so it is correct
behaviour rather than a bypass.

### What is *not* protected, and why

**Force-pushing `main` is still possible for an account with write access.**
That is a real gap and it is stated plainly rather than papered over. The reason
is structural: publishing itself is a rolling squash. Each run rewrites the tip
onto the latest human commit, which is by definition a non-fast-forward push.
Turning on `non_fast_forward` for `main` would therefore block the bot, not just
a careless human — the repository would stop updating. Four ways around that
were considered and each was measured or reasoned to a conclusion:

- **Exempt GitHub Actions via `bypass_actors`.** Not possible on a user-owned
  repository. Measured, verbatim:
  `Actor GitHub Actions integration must be part of the ruleset source or owner organization`
  (HTTP 422). Bypass by integration requires an organization.
- **Exempt by repository role instead.** Available, but useless here: a
  role-keyed bypass cannot tell the bot apart from the humans it is meant to
  restrict, because the owner already holds a role above `write`. A rule that
  exempts everyone it would otherwise stop is not a rule.
- **Give the bot a deploy key and push over SSH.** This would work, and it would
  allow `non_fast_forward` to be armed. It was rejected on balance: it replaces
  an ephemeral, per-run `GITHUB_TOKEN` with a permanent write credential stored
  in Actions secrets, which forfeits this repository's verifiable property that
  the workflow reads **no** `secrets.*` at all. Trading a durable secret for a
  branch rule is a net loss.
- **Publish fast-forward instead of squashing.** Removes the need for the force
  push, at the cost of retaining every output commit instead of one. At the
  effective 15-minute publish cadence that is about 35,000 commits a year, added
  to a repository whose clone already measures several gigabytes. The size is
  measured; the commit count is arithmetic from the schedule — but neither is
  speculative, and the direction is not in doubt.

Related: `enforcement: "evaluate"`, which would allow a dry-run rollout of a
rule before enforcing it, is unavailable here. Measured, verbatim:
`Enforcement evaluate option is not supported on this plan. Please upgrade to Enterprise to enable it.`

What *is* in place instead: `required_linear_history` prevents merge commits on
`main`, `deletion` prevents the branch from being removed, the publish step uses
`--force-with-lease` rather than a bare `--force`, and the source-regression
guard described above refuses to publish if anything outside the known output
set differs from the anchor commit. Those do not stop a determined force push;
they do stop the accidental ones.

### Operating on protected refs

Because tags carry `deletion` and `update` with no bypass, a tag genuinely
cannot be moved or removed while the ruleset is active — including by the owner.
To retire one deliberately, narrow the ruleset rather than disabling it, so
every other ref stays protected throughout:

```bash
# 1. exclude only the ref you intend to touch (PUT replaces the whole ruleset,
#    so every field must be present, not just the one being changed)
cat > /tmp/ruleset.json <<'JSON'
{
  "name": "tags: protected (no delete, no rewrite)",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~ALL"],
                                "exclude": ["refs/tags/THE_TAG"] } },
  "rules": [ { "type": "deletion" },
             { "type": "non_fast_forward" },
             { "type": "update" } ]
}
JSON
gh api -X PUT /repos/:owner/:repo/rulesets/RULESET_ID --input /tmp/ruleset.json

# 2. perform the deletion or move, now that the ref is out of scope
# 3. repeat step 1 with "exclude": [] to restore full coverage
```

To remove a ruleset outright: `gh api -X DELETE /repos/:owner/:repo/rulesets/RULESET_ID`.
The current ruleset ids are listed on the repository's **Settings → Rules** page;
they are intentionally not hard-coded here, because ids change if a ruleset is
recreated and a stale id in a document is worse than no id at all.

---

## 🎯 Scope

**In scope**

- `scripts/**` — the pipeline (parsing, dedup, branding, conversion, validation)
- `.github/workflows/aggregate.yml` — the CI/publish logic
- `docs/**` — the static dashboard
- integrity of the published output (`all/`, `heavy/`, `light/`, `protocols/`,
  `verified/`, `fast/`, `secure/`, `index.json`, `health.json`)
- anything that could let a third party write to this repository

**Out of scope**

- the behaviour, honesty, or safety of the **proxy servers** configs point at
- the content of **upstream sources** — this repo only aggregates what they publish
- third-party clients (v2rayNG, Nekobox, sing-box, mihomo, …)
- the fact that free configs are frequently dead — that is measured and reported
  in `health.json`, not a vulnerability
- your local network, device, or client configuration

---

## 📜 Legal

For educational and research purposes. No uptime or quality guarantee. You are
responsible for complying with the laws that apply to you. See
[LICENSE](LICENSE) (MIT).
