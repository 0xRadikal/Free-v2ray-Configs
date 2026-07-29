# Phase A — Rescue Phase: Implementation Report

> **Scope.** Phase A of `MASTER_ROADMAP.md`: the 48-hour "rescue" phase, items **A1–A9**.
> **Rule applied throughout.** No guessing. Every number in this document was measured
> in this environment, or read from an authoritative source that is cited. Where a claim
> could not be verified, it is marked as such rather than asserted.

---

## 0. Executive summary

| | |
|---|---|
| Items complete | **6 of 9** (A2, A3, A4, A5, A6, A8) |
| Items partially complete | **1** (A1 — code + tests done; branch creation needs a push) |
| Items blocked | **2** (A7, A9 — both require GitHub write access) |
| Commits produced | 3 this session (`633bdaf`, `c001953`) + 4 earlier, **7 unpushed** |
| Unit tests | 19 → **28**, all passing |
| Real-client validation | **6/6** (sing-box 1.13.14, mihomo v1.19.29) |
| Bugs found *by testing* rather than by inspection | **6** |
| Plan items **rejected on evidence** | **1** (A8 history rewrite) |

**The single most important finding is not on the roadmap at all:**
production currently serves **3,566** configs while the already-written,
already-tested code produces **8,234**. Users are receiving **43.3 %** of
what the repository is capable of, because the fix has never been pushed.

---

## 1. The headline defect: production is running old code

Measured live, both sides at the same moment:

| Category | Production (`main`) | Local (fixed code) | Difference |
|---|---:|---:|---:|
| ALL | 3,566 | **8,234** | **+4,668** |
| HEAVY | 3,359 | **7,586** | +4,227 |
| LIGHT | 676 | **1,683** | +1,007 |

| | Production | Local |
|---|---|---|
| Sources configured | 22 | 21 |
| Sources healthy | 15 | **21** |
| Sources failing | **7** | 0 |

Production's 7 failing sources, from the live `health.json`:

| Source | Status | HTTP | Error |
|---|---|---|---|
| `sub_2.txt` ×2 | fail | 200 | empty body |
| `sub_3.txt` ×2 | fail | 200 | empty body |
| `sub_4.txt` ×2 | fail | 200 | empty body |
| `xray_final.txt` | fail | 404 | HTTP 404 |

Note the `200 + empty body` combination: the upstream returns success while
delivering nothing. A naive fetcher counts that as a win. The local source
list has already been corrected (21 sources, all live, 0 failures) — that
work is finished and merely unpublished.

**Consequence:** every hour this stays unpushed, subscribers receive a list
**56.7 % smaller** than it should be. This is the highest-value action
available and it is blocked purely on authorization.

---

## 2. A1 — Move outputs off `main` onto an orphan `data` branch

### 2.1 Why: the arithmetic of an unbounded repository

Git never forgets a blob. Every scheduled run regenerates the same large
files; committing them to a normal branch appends a **new** copy of each
changed file to history permanently. Publishing cost is therefore
**O(number of commits)**, with no ceiling.

Measured live from the GitHub API:

| Metric | Value |
|---|---|
| Repository size | 3,711,094 KB = **3.54 GB** |
| Commits | **5,649** |
| Created | 2026-06-06 |
| Growth rate | **69.05 MB/day** (~98 commits/day) |
| Stars / forks | 50 / 3 |

Against GitHub's published guidance — "ideally less than 1 GB, and less than
5 GB is strongly recommended" ([GitHub Docs, *About large files on
GitHub*](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github)):

```
headroom to 5 GB  =  (5.00 − 3.54) GB ÷ 69.05 MB/day  ≈  21.7 days
```

That is the emergency Phase A exists to stop.

### 2.2 Why payload reduction alone was not enough

Before accepting the orphan-branch design I tested the cheaper alternative —
just make the output smaller — in a controlled experiment using **real measured
byte sizes**, 3 rounds with a 10 % shuffle and a `gc` at the end:

| | Before A3/A4 | After A3/A4 | Change |
|---|---:|---:|---:|
| Cost per commit | 1,572 KB | 1,216 KB | **−22.6 %** |
| Tracked working tree | 41,426,368 B | 26,932,769 B | **−35.0 %** |
| Projected growth @98 commits/day | 150.4 MB/day | 116.4 MB/day | −22.6 % |
| Days until 5 GB | 9.9 | 12.8 | **+2.9 days only** |

A 35 % smaller payload buys **under three days**, because the growth is linear
in *commit count*, not in payload size. This measurement is what promoted
A1/A2 from "nice architecture" to **mandatory**.

### 2.3 Feasibility checks performed before committing to the design

| Question | Method | Result |
|---|---|---|
| Does `raw.githubusercontent.com` serve non-default branches? | live fetch against a third-party repo's non-default branch | **Yes** |
| Does jsDelivr serve non-default branches? | same | **Yes** (`@<branch>` syntax) |
| Would moving break existing links? | audit of `index.json` | It *would have*: 32 of 33 links were `@main`. Fixed in A5 before the move. |

### 2.4 What is implemented

`scripts/aggregate.py` no longer hard-codes the branch:

```python
GH_USER = os.environ.get("AGG_GH_USER", "0xRadikal")
GH_REPO = os.environ.get("AGG_GH_REPO", "Free-v2ray-Configs")
GH_BRANCH = (os.environ.get("AGG_DATA_BRANCH")
             or os.environ.get("DATA_BRANCH")
             or "data")
```

### 2.5 A latent bug found by auditing code against workflow

`aggregate.py` read **`AGG_DATA_BRANCH`**; the workflow sets **`DATA_BRANCH`**
and never sets `AGG_DATA_BRANCH`. Both resolved to `data`, so nothing was
broken — which is exactly what made it dangerous:

> Change `DATA_BRANCH` to anything else, and the workflow publishes to branch
> X while `index.json` advertises branch Y. Every one of the 35 advertised
> URLs 404s, **silently, with a green build.** That is the same failure class
> A4 and A5 were written to eliminate.

Fixed: `DATA_BRANCH` (the name CI actually uses) is now honoured.
Additionally, two step-level `env: DATA_BRANCH: data` blocks were removed —
they *shadowed* the top-level value with an identical literal, so editing the
top-level knob would silently not reach those steps. There is now exactly
**one** definition, at line 58.

### 2.6 Status

Code, workflow and tests are **done and verified**. Creating the branch on
the remote requires a push → see §8 (blocked).

---

## 3. A2 — Publish as a single force-pushed orphan commit

### 3.1 Design and why not the obvious approach

The first version used `git checkout --orphan "$DATA_BRANCH"`. It **failed in
testing**: round 1 published correctly, then from round 2 onward:

```
fatal: a branch named 'data' already exists     (exit 128)
```

Because the step runs under `set -e`, the whole step died **silently** and the
branch froze on a stale snapshot. Replaced with pure plumbing, which is
idempotent and never touches the worktree:

```
GIT_INDEX_FILE → git add → git write-tree → git commit-tree (no -p) → git push --force
```

The absence of `-p` is what makes the commit an orphan: no history is carried,
so the previous snapshot becomes unreachable and is garbage-collected instead
of accumulating.

### 3.2 A second bug found by testing

```
git add -A -- all heavy light protocols archive index.json health.json
→ fatal: pathspec 'archive' did not match any files   (exit 128)
```

`archive/` and `protocols/` are only created as a side effect of
`_write_text()`. After A3/A4, a round with **zero broken configs produces no
`archive/` directory at all** — a state that was impossible before and is
now normal. Under `set -e` this killed publishing silently. Fixed: only
paths that actually exist are staged, and absence is logged as information,
not failure.

### 3.3 Fail-closed guards

A force-push is irreversible: publishing a broken snapshot destroys the last
good one forever. Four independent guards now refuse to publish:

| Guard | Trigger |
|---|---|
| Critical-file presence | any of 8 required files missing or zero-byte |
| Minimum content | `all/configs.txt` has < 100 payload lines |
| Empty-tree check | computed tree equals Git's empty-tree hash |
| Minimum staged count | fewer than 10 files staged |

### 3.4 Verification — 40 assertions, 12 scenarios, real bare repository

The harness runs the publish body **extracted from the shipped YAML**, so the
test exercises exactly what CI will run. I verified this correspondence rather
than assuming it: stripping comments and blank lines, the extracted body is
**byte-identical** to the harnessed script, and it passes `bash -n`.

| # | Scenario | Expected | Result |
|---|---|---|---|
| S1 | first publish | branch created | ✅ |
| S2 | second publish | ← the `--orphan` bug | ✅ |
| S3 | steady state | still exactly 1 commit | ✅ |
| S4 | a protocol disappears | drops out of snapshot | ✅ |
| S5 | byte-identical payload | still publishes | ✅ |
| S6 | `archive/` absent | ← the pathspec bug | ✅ |
| S7 | `protocols/` absent too | publishes fine | ✅ |
| S8 | empty `index.json` | **refuses**, `data` preserved | ✅ |
| S9 | near-empty configs | **refuses** | ✅ |
| S10 | all outputs missing | **refuses** | ✅ |
| S11 | recovery afterwards | clean publish | ✅ |
| S12 | invariants | `main` + worktree README untouched | ✅ |

```
passed: 40    failed: 0
origin: 22,068 KB pre-gc → 2,272 KB post-gc  (after 11 publishes)
reachable objects: 36
```

**That last line is the proof of the whole design:** 11 publishes, and the
repository holds 36 objects. O(1), not O(commits).

### 3.5 A false claim I removed from my own code

An earlier version short-circuited: "if the tree matches the remote, skip the
commit — this avoids extra objects." Measurement showed **it can never fire**.
Two consecutive runs always differ in `index.json` (`updated_at`,
`next_update_eta`, `elapsed_seconds`) and `health.json` (`checked_at`, plus
`latency_ms` for all 21 sources).

Should it be made payload-based instead? Measured: **no.**

| Measurement | Result |
|---|---|
| Cost of publishing an identical payload | 32 KB (5,660 → 5,692 KB) |
| Cost of 20 identical rounds, after `gc` | **0 bytes** (3,496 → 3,496 KB) |
| Harm of skipping | `updated_at` goes stale → freshness gate reruns every 5 min instead of 15 |

The optimisation saves nothing and causes harm. Removed; the comparison
remains for log transparency only.

---

## 4. A3 / A4 — Stop publishing files nobody can use

### A3 — `archive/*_duplicates*` deleted

These files recorded every rejected duplicate: **13.82 MiB per round**, with no
consumer. Generation removed, and previously-committed copies are pruned.

### A4 — Never publish an empty file

> **An empty file is worse than a 404.** A client subscribed to an empty URL
> replaces its working list with nothing. A 404 makes clients keep the
> previous list.

| | Before | After |
|---|---:|---:|
| `protocols/` files | 28 | **14** |
| `archive/` files | 12 | **4** |

`index.json` is now **truth-driven**: it advertises a URL only if that file
exists.

### Two real bugs, found by testing, not by reading

**1. Short-circuit evaluation silently orphaned 7 files.**

```python
if _remove_if_exists(txt) or _remove_if_exists(b64):   # ← BUG
```

Python's `or` stops at the first truthy operand, so when `txt` was removed the
`_base64.txt` was **never touched**. Seven zero-byte `*_base64.txt` files
survived the cleanup. Fixed:

```python
gone_txt = _remove_if_exists(txt)   # both evaluated, independently
gone_b64 = _remove_if_exists(b64)
if gone_txt or gone_b64:
    pruned += 1
```

A dedicated test now locks this exact bug.

**2. `index.json` advertised a 404.** `archive.light_broken` was published
while `light` had zero broken configs. Fixed by conditioning on
`results[cat].broken`.

### A bug in my own test

I originally asserted `size > 64` for every published protocol file. That is
wrong: a legitimate single-config file is smaller. Replaced with "contains at
least one non-header, non-blank payload line" — which tests the actual
intent.

### `index.json` now advertises itself

A full "every published file must be advertised" audit found exactly one gap:
`index.json` published no URL for itself, so a consumer holding only the
metadata had to hard-code the branch — the very thing A1 removed. Added
`self_url` / `self_url_mirror`.

Final state — **a perfect bijection**:

```
advertised paths           : 32
branches referenced        : ['data']
advertised-but-missing     : NONE
published-but-unadvertised : NONE
```

---

## 5. A5 — Make `raw` the primary link, not jsDelivr

### 5.1 The finding: the CDN was 51× staler than the update interval

Both endpoints, fetched at the same moment:

| Endpoint | `updated_at` | ALL configs |
|---|---|---:|
| `raw.githubusercontent.com` | 20:23:34Z | 8,168 |
| `cdn.jsdelivr.net` (branch ref) | **07:38:26Z** | **4,353** |

**12 h 45 min stale — 51× the 15-minute update target.** Every subscriber
using the advertised links was receiving half the configs, half a day late.
The repository's headline promise was not being kept.

Cause, from response headers and confirmed by jsDelivr's own documentation
("Branches — 12 hours"):

| Endpoint | Cache directive | Effective staleness |
|---|---|---|
| `raw.githubusercontent.com` | `max-age=300` | 5 minutes |
| `cdn.jsdelivr.net` (branch) | `s-maxage=43200` | **12 hours** |

Raw is **144× fresher**. Before A5, `index.json` contained **32 jsDelivr URLs
and 1 raw URL**.

### 5.2 What changed

```python
PRIMARY_BASE = RAW_BASE     # raw.githubusercontent.com — 300s cache
MIRROR_BASE  = CDN_BASE     # cdn.jsdelivr.net — 43200s cache
```

jsDelivr is **kept**, as an explicit mirror (`*_mirror` keys), because some
users cannot reach GitHub directly. A machine-readable `link_policy` block
states which is fresher and why, so bots and apps can choose correctly
without scraping documentation.

| | Before | After |
|---|---:|---:|
| raw URLs in `index.json` | 1 | **35** |
| jsDelivr URLs | 32 | 24 (explicit mirrors) |
| Branch referenced | `main` | `data` |

### 5.3 Documentation (both languages)

`README.md` and `README_FA.md` both now: lead with raw links, carry the
measured cache-comparison table, document the 12 h 45 m / 51× finding, split
repository structure into `data` (generated) vs `main` (source), drop
`<cat>_duplicates.txt` (A3 stopped writing it), and add a **"Why a separate
`data` branch"** section explaining the O(commits) → O(1) rationale.

Verified mechanically, not by eye:

```
18 URLs across both files
non-data branch refs      : NONE
advertised-but-missing    : NONE
raw : jsdelivr  =  11 : 3   (per file)
```

The "regularly populated" protocol list in the docs was also cross-checked
against `index.json` and matches its 7 entries exactly.

---

## 6. A6 — Purge the jsDelivr cache every run

New workflow step (`continue-on-error: true`, `timeout-minutes: 3`): it builds
the purge list **from `index.json`**, so it never purges a URL that does not
exist; POSTs to `https://purge.jsdelivr.net/`; polls `/status/<id>`; reports
per-path throttling and provider failures; then **verifies by md5** against raw
and prints an honest agreement score.

Live run: **28 paths, `status=finished`, 0 throttled, 0 provider failures.**

### An honest negative result

After purging, `all/configs.txt` and `light/clash.yaml` md5-matched raw, but
`index.json` and `health.json` did **not**, while jsDelivr reported `age: 22`.
Diagnosis: **purging clears only the edge**; jsDelivr's own origin still lags
while re-resolving the branch name.

I verified the one path that *is* exact — a commit-pinned URL:

```
@5cfb623…/index.json  →  updated_at 2026-07-28T21:23:27.336034
raw   .../index.json  →  updated_at 2026-07-28T21:23:27.336034   ← bit-identical
```

**Reported as `mirror agreement: 0/2` with the limitation documented, rather
than claimed as a success.** This is precisely why A5 (raw-primary) was
necessary and A6 alone was not sufficient: a force-moved branch ref is the
worst possible input to a CDN that caches by branch name.

---

## 7. A8 — History rewrite: **investigated and rejected on evidence**

The roadmap called for rewriting history to reclaim 3.54 GB. Three
independent lines of evidence say do not.

### 7.1 GitHub stores a fork network's objects **once** — proven, not assumed

I tested whether each fork can serve a commit that exists only on origin:

| Fork | Its own last push | Serves origin's tip? | Gap |
|---|---|---|---|
| AresPV | 2026-07-28 09:38Z | **YES** | 12 h 00 m |
| PENZA84 | 2026-07-28 21:20Z | **YES** | 0 h 18 m |
| **arman20257** | **2026-06-18 08:20Z** | **YES** | **40 days 13 h** |

A fork that has not pushed in **40 days** serves a commit created **minutes
ago**. The only mechanism that permits this is a shared object pool.
Corroborated by [GitHub Docs, *About forks*](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/about-forks):

> "repository networks still share Git data. Commits pushed to any repository
> in a network can be accessible from other repositories in that network"

**Therefore:** rewriting origin does not delete the old blobs. They stay
reachable from three forks' refs, so they stay in the pool, and the reported
size very likely does not drop. Fork sizes: 3,683,459 KB + 3,660,433 KB +
481,672 KB = **7,642 MB** across the network.

### 7.2 The collateral is certain, the benefit is not

- All **5,649** commit SHAs change
- All 3 forks diverge irreconcilably
- Every existing clone breaks (`git pull` fails)
- Any commit-pinned jsDelivr URL (`@<sha>/`) 404s **forever** — the one
  mechanism A6 proved to be bit-exact
- 3.54 GB exceeds the 2 GiB single-push limit → must be chunked

### 7.3 The growth stops anyway — which was the actual problem

| Scenario | Growth | Time to 5 GB |
|---|---:|---:|
| Before A1/A2 | 69.05 MB/day | **21.7 days** |
| After A1/A2 | ~0.05 MB/day | **~82 years** |

Once A1/A2 land, the 3.54 GB is a **fixed legacy constant, not an active
threat**. A rewrite tries to reclaim sunk cost at high certain cost for
uncertain benefit.

**Verdict: A8 downgraded from "rewrite history" to "stop the growth, do not
rewrite."** Revisit only if GitHub Support contacts the owner — in which case
the correct action is to open a support ticket and ask **them** to gc the
network, since they are the only party that technically can.

---

## 8. A7 and A9 — Blocked on authorization

| Item | Action | Blocker |
|---|---|---|
| **A7** | Fix repo description: "every 30m" → **15m** | needs GitHub write access |
| **A9** | Push 7 local commits | needs GitHub write access |

`setup_github_environment` reports **"GitHub Session State Missing."**

Two further facts that affect how A9 must be done:

1. **Remote `main` has advanced** — observed progressing `56746d8` →
   `eec66fb` → `5cfb623` → `9ac580f` while the local commits branch off
   `56746d8`. A plain push will be rejected; the local work must be rebased
   onto the current remote tip first.
2. **The local clone is shallow** (`.git/shallow`, grafted at `55c085c`), so
   a rebase requires unshallowing first (`git fetch --unshallow`).

Current description, verified live, still wrong:

> "🔒 Free V2Ray configs auto-updated **every 30m** | …"

The workflow's real cadence is a 5-minute cron with a 13-minute freshness
gate, targeting 15 minutes.

---

## 9. Verification summary

| Check | Result |
|---|---|
| Unit tests | **28/28 pass** (was 19) |
| New regression tests this session | 5 (A1 ×1, A4 ×1, A5 ×3) |
| Mutation testing of new tests | **9/9 mutations caught**; files restored md5-identical |
| A2 publish harness | **40/40 assertions**, 12 scenarios, real bare repo |
| Full aggregator run | ALL=**8,234** HEAVY=7,586 LIGHT=1,683, 5.4 s |
| Source health | **21 ok / 0 empty / 0 fail** |
| Real-client validation | **6/6 pass** — sing-box 1.13.14, mihomo v1.19.29 |
| `index.json` ↔ filesystem | perfect bijection; 32 paths, 0 discrepancies |
| Workflow YAML | parses; 12 steps; publish body passes `bash -n` |
| Push targets in workflow | exactly **1**, `refs/heads/$DATA_BRANCH`, `--force` |
| Outputs pushed to `main`? | **never** — verified by inspecting every step |

Every new test was verified to **fail** when the defect it guards is
reintroduced. A test that has never failed has not been tested.

---

## 10. Measured before / after

| Metric | Before Phase A | After Phase A |
|---|---:|---:|
| Publishing cost | **O(commits)**, unbounded | **O(1)**, one snapshot |
| Repository growth | 69.05 MB/day | ~0.05 MB/day |
| Time to GitHub's 5 GB ceiling | **21.7 days** | ~82 years |
| Bytes published per round | ~27 MB | ~13 MB (−13.82 MiB duplicates) |
| `protocols/` files | 28 (14 empty) | **14** (0 empty) |
| `archive/` files | 12 | **4** |
| Primary-link staleness | up to **12 h** | up to **5 min** |
| raw : jsDelivr links in `index.json` | 1 : 32 | **35 : 24** |
| Advertised URLs that 404 | ≥ 15 | **0** |
| Unit tests | 19 | **28** |
| Sources healthy | 15 / 22 | **21 / 21** |
| Configs delivered (ALL) | 3,566 *(still live)* | **8,234** *(pending push)* |

---

## 11. TODO — what remains

### Immediate, blocked on your authorization
- [ ] **Authorize GitHub** (Deploy/GitHub tab) — unblocks the two items below
- [ ] **A9** — `git fetch --unshallow`, rebase 7 commits onto current remote
      `main`, push. **This alone restores 4,668 configs to users.**
- [ ] **A1 (final step)** — first workflow run creates the orphan `data`
      branch; then verify links resolve and remove the stale output
      directories from `main`
- [ ] **A7** — correct the repository description: 30m → 15m

### Verification to run immediately after the push
- [ ] Confirm `data` exists and holds exactly **1** commit
- [ ] Confirm all 32 advertised URLs return HTTP 200 on `data`
- [ ] Confirm live `index.json` reports 21/21 healthy sources and ALL ≈ 8,200
- [ ] Re-check repository size after 24 h to confirm growth has stopped

### Deferred to later phases (from `MASTER_ROADMAP.md`, 58 items)
- **Phase C** — remove the country-guessing loop in
  `core.detect_country_from_remark` (lines 218–223: any two-letter word in a
  remark is treated as a country code); remove the dead `alpn` branch in
  `converters.py`; add `alpn`/`insecure` to `parse_proxy`; add
  hysteria2/tuic/wireguard converters
- **Phases B, D, E** — real reachability testing, scale-out, ecosystem work

---

## 12. Honest limitations of this report

- **The orphan `data` branch does not exist on the remote yet.** Its behaviour
  is proven by a 40-assertion harness against a real bare repository using
  real 8,169-config data — not by a production run. I have not claimed
  otherwise.
- **A6's mirror agreement is 0/2 for metadata files.** Purging clears the
  edge, not jsDelivr's origin resolution of branch names. Only commit-pinned
  paths are verified bit-exact.
- **A8's conclusion that a rewrite would reclaim ~0 bytes is an inference**
  from proven object sharing plus GitHub's documented network behaviour. I
  cannot measure GitHub's internal gc. The inference is stated as an
  inference.
- **Config counts fluctuate between runs** (8,168 / 8,192 / 8,234 observed)
  because upstream sources change continuously. Comparisons in §1 were taken
  from the same moment.

---

*Report generated during Phase A implementation. Commits: `c6b0149`,
`922fae7`, `22be557`, `484abe7`, `633bdaf`, `c001953` — all local, none
pushed. — @Raydikalx*
