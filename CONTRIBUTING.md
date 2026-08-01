# 🤝 Contributing

Thanks for wanting to help. This project has a few unusual rules that come from
things that actually went wrong here, not from style preferences. Reading the
short version below will save you a rejected PR.

---

## ⚡ The short version

1. **Never edit generated output.** Anything under `all/`, `heavy/`, `light/`,
   `protocols/`, `archive/`, `verified/`, `fast/`, `secure/`, plus `index.json`,
   `health.json`, `state.json`, `top100.txt` — is written by the bot and will be
   overwritten within ~15 minutes. Change the **generator**, not its output.
2. **Every behaviour change needs a test** in `scripts/test_pipeline.py`.
3. **Run the suite before opening a PR** (one command, no dependencies to install
   beyond `requirements.txt`).
4. **Don't advertise what you don't deliver** — see the doctrine below.

---

## 🛠️ Setup

CI runs **Python 3.12** (`.github/workflows/aggregate.yml`, `python-version: "3.12"`).
Anything ≥ 3.12 is fine locally.

```bash
git clone https://github.com/0xRadikal/Free-v2ray-Configs.git
cd Free-v2ray-Configs
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

Runtime dependencies are deliberately few and exactly pinned:

```
requests==2.32.4
PyYAML==6.0.3
maxminddb==3.1.1
```

If your change needs a **new** dependency, say so explicitly in the PR and
justify it. `requirements.txt` already documents why `maxminddb` was chosen over
`geoip2` — that is the level of justification expected.

---

## 🧪 Running the tests

There is **one** command:

```bash
cd scripts
python3 test_pipeline.py
```

It prints one line per test and a summary, and exits non-zero if anything failed:

```
  ✅ test_state_history_growth_is_bounded
  …
  288/288 passed
```

Notes that matter:

- **The suite is self-contained — there is no `pytest`.** The runner is
  `_run_all()` inside `test_pipeline.py`; it discovers every module-level
  callable whose name starts with `test_`. Please don't convert the suite to
  pytest in a drive-by PR; that is a project-level decision.
- **There is no CLI test filter.** To run a single test:

  ```bash
  cd scripts
  python3 -c "import test_pipeline as t; t.test_state_history_growth_is_bounded()"
  ```

- **Some tests need the network** (they exercise fetching and reachability). A
  failure that only reproduces offline is usually environmental — mention it
  rather than "fixing" the test.

### ⚠️ The one trap that has actually bitten this repo

`test_pipeline.py` keeps its entry point at the **absolute end of the file**:

```python
if __name__ == "__main__":
    sys.exit(_run_all())
```

Python executes a module top to bottom, and `_run_all()` discovers tests through
`globals()`. So **any test defined *below* that block is never defined when the
suite runs** — it silently becomes dead code while the summary stays green. This
is not hypothetical: it happened during phase C11, where the suite happily
reported `247/247 passed` while **17 newly added tests never executed at all**.

**Rule:** append new tests to the end of the file and keep the `if __name__`
block last, or insert them before it. After adding tests, sanity-check that the
count went up:

```bash
grep -c '^def test_' scripts/test_pipeline.py    # must match the "N/M passed" total
```

---

## 📐 Project doctrine (please read before proposing a feature)

These are written into the code and are enforced in review.

### 1. Advertised = delivered

`scripts/converters.py` states it directly:

> **The gap between what is advertised and what is delivered is itself a defect
> of trust.**

If you add a protocol to a list, a README table, or `index.json`, the pipeline
must actually produce working entries for it. Conversely, if a protocol cannot be
converted honestly, it is **excluded and the exclusion is documented** — that is
why `wireguard://` is not converted: a public WireGuard URI does not carry the
client private key or the assigned internal address, so any conversion would have
to fabricate them, producing a config that looks valid and never connects.

### 2. Never publish an empty file

An empty subscription file is **worse than a 404**: a client that fetches an empty
list replaces its working list with nothing, whereas a 404 makes clients keep the
previous list. Files in `protocols/` and `archive/` therefore appear only when
non-empty.

### 3. Output must be deterministic

Two consecutive runs on the same input must produce byte-identical files (apart
from timestamps). Three churn sources were found by measurement and removed —
please don't reintroduce them:

| Anti-pattern | Why it's banned |
|---|---|
| Reading the country label from whichever upstream was fetched first | The same server flipped `RU 🇷🇺` ⇄ `US 🇺🇸` between runs |
| Positional counters in remark tags | Inserting one config renamed every line after it |
| Emitting in network-response order | Same configs ⇒ different file bytes |

Tags are `sha256(dedup-key)[:6]` — content-derived, position-immune. Output is
sorted by dedup key.

### 4. Fail closed

If validation fails, the run must abort and leave the previous good release in
place. Never add a code path that publishes partial or unvalidated output.

### 5. Don't weaken a parser to "get more configs"

A parser that is more permissive than the converter is a bug, not a feature: the
lenient side lets a broken line win a dedup key, and a *working* config gets
dropped as its duplicate. Parsers and converters must agree.

---

## 🗺️ Where things live

| Path | What it does |
|---|---|
| `scripts/sources.py` | the upstream list — `LIGHT_SOURCES` (line 47) and `HEAVY_SOURCES` (line 63) |
| `scripts/core.py` | parsing, dedup keys, branding |
| `scripts/converters.py` | per-client schema translation + field validation |
| `scripts/aggregate.py` | orchestration, writes the published files |
| `scripts/validate.py` | `sing-box check` / `mihomo -t` gate |
| `scripts/pipeline.py` · `reachability.py` · `realtest.py` | the L0–L3 verification cascade |
| `scripts/geo.py` | country resolution (GeoIP) |
| `scripts/state.py` | cross-round memory (bounded history) |
| `scripts/filters.py` | drop rules for dummy/broken entries |
| `scripts/test_pipeline.py` | the whole test suite |
| `.github/workflows/aggregate.yml` | schedule, validation, and the rolling-squash publish |
| `docs/` | the static dashboard |

---

## ➕ Common contributions

### Adding an upstream source

1. Add the raw URL to `LIGHT_SOURCES` or `HEAVY_SOURCES` in `scripts/sources.py`.
   *Light* = curated/speed-tested upstreams; *heavy* = large and diverse.
2. Verify it actually returns configs, and that base64/plain detection works.
3. Update the source count where it appears (`README.md`, `README_FA.md`,
   `README_ZH.md`, `README_RU.md`, and any count in `index.json` generation).
4. Add the maintainer to the **Sources** credit list in the READMEs.
5. Run the suite.

Dead or redirecting sources will show up in `health.json` as `fail` / `empty`;
please check that file before claiming a source works.

### Adding protocol support

1. Implement parsing in `core.py` **and** conversion in `converters.py` — both,
   or neither (see doctrine #5).
2. Validate every field a client will reject: cipher whitelists, key lengths,
   REALITY `short-id`/public-key formats, transport parameters.
3. Add tests covering a valid config, a malformed one, and the dedup key.
4. Confirm the generated `clash.yaml` / `singbox.json` still pass
   `sing-box check -c` and `mihomo -t -f`.
5. Only then mention the protocol in the READMEs.

> Note the asymmetry precedent: ShadowsocksR is emitted **only** to Clash,
> because sing-box removed `ssr` in 1.6.0 and a single such outbound makes
> sing-box reject the **entire** file. Per-client capability differences are
> handled by emitting selectively, never by downgrading.

---

## 🔀 Pull requests

- Branch from `main`.
- Keep a PR to one logical change.
- **Do not include regenerated output files in the diff.** If they show up
  because you ran the pipeline locally, `git checkout --` them before committing.
- Commit messages follow Conventional Commits, as the history does:

  ```
  fix(dedup): keep the real host in the key — fronting no longer replaces it
  feat(sources): remember per-source unique yield across rounds
  test: lock the retirement of the orphan `data` branch
  ```

  Never use the marker `[auto-output]` in a human commit subject — the publish
  step uses it to find the last human commit, and a human commit carrying that
  marker would be skipped as if it were bot output.
- In the PR description, state **what you measured**, not just what you changed.
  "Ran the suite: 288/288" or "source returned 412 configs, 38 unique after
  dedup" is the expected style.

### What gets a PR rejected

- ❌ edits to generated output paths
- ❌ a behaviour change with no test
- ❌ adding a protocol/feature to a README that the code doesn't actually deliver
- ❌ making a parser more permissive than its converter
- ❌ a new dependency with no justification
- ❌ removing a fail-closed guard to "make the run succeed"

---

## 🐞 Reporting bugs

Use the issue templates:
<https://github.com/0xRadikal/Free-v2ray-Configs/issues/new/choose>

**"A config didn't work for me" is usually not a bug.** Most free configs are
dead at any moment — that is measured, not hidden: see
[README → Does it actually work?](README.md#-does-it-actually-work) and the
`cascade` block in `health.json`. A useful report instead looks like: *"every
`vless` entry in `protocols/vless.txt` is rejected by client X with error Y"*.

For security issues, follow [SECURITY.md](SECURITY.md) — and if disclosure would
put users at risk, report privately rather than opening an issue.

---

## 📜 License

By contributing you agree that your contribution is licensed under the
[MIT License](LICENSE) that covers this repository.
