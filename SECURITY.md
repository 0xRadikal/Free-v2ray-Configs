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
| Python runtime deps (`requirements.txt`) | exact `==` pins: `requests==2.32.4`, `PyYAML==6.0.3`, `maxminddb==3.1.1` | by pip, against PyPI |
| `xray-knife` 10.1.1 | version **and** SHA-256 of both the release archive and the extracted binary, cross-checked against upstream's own `.dgst` file in MD5/SHA-256/SHA-512 | ✅ yes |
| `sing-box` 1.13.14 | version only | ❌ **no — see below** |
| `mihomo` v1.19.29 | version only | ❌ **no — see below** |
| GitHub Actions | major tags (`actions/checkout@v4`, `actions/setup-python@v5`, `actions/cache@v4`, `actions/upload-artifact@v4`) | ❌ not SHA-pinned |
| Dependency updates | [`.github/dependabot.yml`](.github/dependabot.yml) — `pip` + `github-actions`, weekly | — |

### Known gap, stated rather than hidden

`sing-box` and `mihomo` are downloaded from GitHub Releases with the version
pinned, but **their checksums are not verified**. The workflow itself names this
asymmetry, in the comment block at lines 370–373, and explains why
version-pinning alone is not integrity. That comment is written in Persian; in
English it says:

<!-- Paraphrase, not a quotation. The comment at aggregate.yml:370-373 reads
     "فقط pin کردنِ *نسخه* تضمینی نمی‌دهد، چون یک انتشارِ گیت‌هاب قابلِ جای‌گزینی
     است (asset را می‌توان با همان نام دوباره بارگذاری کرد)." Presenting an English
     rendering of that in blockquote form would invite a reader to go to line 371
     expecting these exact words and find something else — a small gap between
     what is advertised and what is delivered, which is the failure mode this
     whole document is written against. -->
*(paraphrase — the original is Persian)* A GitHub release asset is replaceable:
the same asset name can be re-uploaded with different bytes. Pinning only the
*version* therefore guarantees nothing about the bytes you receive.

`xray-knife` was hardened this way; the two validator binaries were not. This is
a real, open hardening item, and it is listed here instead of being left for
someone else to discover. The same applies to SHA-pinning the GitHub Actions.

**Threat model for that gap:** it requires an attacker who can replace an asset
on the `SagerNet/sing-box` or `MetaCubeX/mihomo` release pages — i.e. a
compromise of those upstream projects. In that scenario the blast radius here is
limited to the CI runner and to *validation being wrong* (a bad config could be
declared valid). It does not give the attacker write access to this repository's
history, because publishing uses the scoped `GITHUB_TOKEN`, not a PAT.

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
