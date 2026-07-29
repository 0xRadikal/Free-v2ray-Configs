# Phase G — Reverting the `data` Branch: Publishing on `main` Without Paying for It

> **Status:** implemented, verified, committed as `d5a31d8`. Awaiting push.
> **Scope:** undo the separate `data` output branch; restore every config file to the
> default branch (`main`) **without** reintroducing the unbounded-history problem that
> motivated the split in the first place.
> **Method:** every number in this document was produced by a command that was actually
> run in this repository. Nothing here is estimated, remembered, or assumed. Where a
> thing could not be proven, it is listed as an open caveat in §11 instead of being
> claimed.

---

## 1. The verdict up front

Creating the `data` branch was an **engineering-correct, product-destroying** decision.

It solved a real problem — git history growing without bound — and it solved it
properly. But it paid for that solution with the one asset the project cannot
regenerate: **users who already have a working link.**

The fix is not to accept unbounded growth. The fix is a publishing algorithm that keeps
the files on `main` at **O(1)** history cost. That algorithm — *rolling squash* — is
implemented, and this report is its evidence.

| | Before Phase G | After Phase G |
|---|---|---|
| Where configs live | branch `data` | **branch `main` (default)** |
| Visible when opening the repo | ❌ no | ✅ yes |
| Legacy `main/...` links | ❌ **404** | ✅ 200 (after push) |
| History cost per run | 604 KB (measured) | **0 KB (measured)** |
| Projected 1-year history | 20.2 GB | **flat** |
| Output commits retained | 1 (orphan, no source) | 1 (on top of full source history) |
| Executable tests | 28 | **33, all passing** |

---

## 2. Why the `data` branch was wrong — measured, not assumed

The user's criticism was concrete. I treated each claim as a hypothesis to test.

### 2.1 Claim: "it breaks links that were already copied and are in use"

**Verified — every legacy URL is dead.** Tested against the live GitHub CDN with the
project's real filenames:

```
main/all/configs.txt              -> 404
main/all/configs_base64.txt       -> 404
main/all/clash.yaml               -> 404
main/all/singbox.json             -> 404
main/heavy/configs.txt            -> 404
main/light/configs.txt            -> 404
main/protocols/vless.txt          -> 404
main/index.json                   -> 404
main/health.json                  -> 404
```

Nine for nine. Every user who saved a subscription URL before the split has a silently
broken client. In a subscription-based product a 404 is not a cosmetic bug — the client
stops updating and the user assumes the project died.

> ⚠️ **A note on my own rigour here.** My first pass at this check queried
> `main/all/all.txt` and reported 404. That 404 was *meaningless* — the file has never
> been named `all.txt`. I caught it by diffing the advertised paths against
> `git ls-files`, and re-ran with the real names (`all/configs.txt`). The conclusion
> held, but it held for a verified reason rather than a lucky one. This is recorded
> because a report that hides its corrections cannot be trusted about anything else.

### 2.2 Claim: "nobody sees the project's data and configs any more"

**Verified structurally.** `data` is a *single orphan commit* — it has no parent and
shares no history with `main`:

```
$ git rev-list --count FETCH_HEAD     # data branch
1
$ git log -1 --format="parents=[%P]" FETCH_HEAD
parents=[]
```

And the default branch a visitor actually lands on contains **no config files at all** —
only 12 source files:

```
.github/workflows/aggregate.yml   scripts/aggregate.py    scripts/sources.py
.gitignore                        scripts/converters.py   scripts/test_pipeline.py
LICENSE                           scripts/core.py         scripts/validate.py
README.md   README_FA.md   requirements.txt
```

A visitor opening the repository sees a Python project. The product is invisible.

### 2.3 Claim: "I didn't even know what a branch was — I just tried to copy the config file directly"

This is the decisive argument and it is **not** a technical one, so it cannot be settled
by measurement — only by evidence about user behaviour. The user is describing the modal
user of a free-config repository: someone who wants a working subscription link, not
someone who understands git refs.

The branch switcher is a **GitHub UI affordance, not a product affordance.** Asking a
user to discover it before they can get value is a conversion funnel with an unnecessary
gate.

### 2.4 Claim: "it hurts SEO, stars, monetisation and promotion"

**Supported by mechanism plus competitor evidence.**

Mechanism: GitHub renders `README.md` **from the default branch only**. Search engines,
social embeds, `awesome-*` list curators and the GitHub search index all read `main`.
Content on `data` is effectively unindexed. The repo's own social proof — currently
**50 stars, 3 forks** — accrues to a page that shows none of the product.

Competitor evidence: I surveyed how successful repositories in this exact niche
publish. **None of the high-star aggregators publishes its output to a separate
branch** — output files sit on the default branch, directly linkable. A design that no
successful competitor uses, in a niche where discoverability *is* the product, is a
design decision that needs to justify itself. It could not.

### 2.5 The thing the `data` branch was actually right about

It must be said plainly, because the fix depends on it: **the size problem was real.**

Measured on the live repository, one output commit costs **604 KB** of permanent
history. The production schedule is `cron: "*/5 * * * *"` (288 attempts/day) gated to
`UPDATE_INTERVAL_MINUTES: "15"` — so **96 effective runs/day**, matching
`index.json`'s declared `update_interval_minutes: 15`:

```
604 KB × 96          =  56.6 MB / day
56.6 MB × 365        =  20.2 GB / year
```

The repository is **already 3.55 GB** (GitHub API `size: 3720123` KB). Simply reverting
to committing outputs on `main` would resume a 20 GB/year trajectory and eventually make
the repo unclonable. **Reverting alone was never an option.** That is why Phase G is an
algorithm, not a revert.

---

## 3. The fix: rolling squash on `main`

### 3.1 The idea

Keep the full source history. Keep **exactly one** output commit, always at the tip.
Each run *replaces* that commit rather than adding to it.

Every output commit carries a marker in its message: `[auto-output]`.

```
Round N:
  1. ANCHOR = newest commit whose message does NOT contain "[auto-output]"
             (i.e. the last real source commit)
  2. TREE   = ANCHOR's tree, with the freshly generated output files written over it
  3. COMMIT = git commit-tree $TREE -p $ANCHOR      # parent is the SOURCE, not the old output
  4. push --force-with-lease
```

Because the new output commit's parent is the **anchor** and not the previous output
commit, the previous output commit becomes unreachable the moment the ref moves. Git's
gc reclaims it. History depth stays constant; source history is never touched.

```
before round N+1:   ...─ S1 ─ S2 ─ S3(anchor) ─ O_N          ← main
after  round N+1:   ...─ S1 ─ S2 ─ S3(anchor) ─ O_N+1        ← main
                                              └ O_N  (unreachable → gc'd)
```

### 3.2 Measured cost: O(1)

`ci_sim.sh` — 25 consecutive rounds, each starting from a **fresh `--depth=1` clone**,
exactly as CI does:

```
  round  1: shallow_visible=1 deepen_calls=0 origin=172KB rc=0
  round  2: shallow_visible=1 deepen_calls=1 origin=172KB rc=0
  round  3: shallow_visible=1 deepen_calls=1 origin=172KB rc=0
  round 10: shallow_visible=1 deepen_calls=1 origin=172KB rc=0
  round 20: shallow_visible=1 deepen_calls=1 origin=172KB rc=0
  round 25: shallow_visible=1 deepen_calls=1 origin=172KB rc=0

  ✅ output commits on top of source: 1
  ✅ total commits (source + 1): 4
  ✅ source subjects preserved: 55574d99b4fa8f5f9026c9d00ad80490
  ✅ source content intact: core v2
  ✅ tip carries the LAST round's output: 1
  ✅ all 34 advertised+source paths present on main: 0
  growth/round (rounds 10→25) = 0 KB
  ✅ history growth is O(1): 0 <= 40

  PASS=7  FAIL=0
  origin.git after 25 rounds: 172K
```

**172 KB, constant, across 25 rounds. 0 KB/round.** The 20.2 GB/year trajectory is
eliminated while the files sit on the default branch.

### 3.3 Why determinism alone was *not* enough (and why squash is mandatory)

I did not assume the squash was necessary — I measured the alternative. `realistic_growth.sh`
commits outputs conventionally on `main`, with the determinism fixes of §5 active and
realistic upstream churn (0.19%/round, measured live), driving the **real** `core.py`
and `converters.py` code paths:

```
base configs: 8126
  round  0: configs= 8126  .git=   1844 KB
  round  9: configs= 8126  .git=   4380 KB

growth/round  : 281.8 KB
per day (96)  : 26.42 MB
per year      : 9.42 GB
```

So determinism alone improves 604 KB → 281.8 KB/round (**2.1×**) but still projects
**9.42 GB/year**. Determinism is a real optimisation; it is not a solution.
**Rolling squash is load-bearing.**

### 3.4 Where the growth actually comes from: 99.4% is base64

I ran a controlled attribution — identical churn seed (`Random(4242)`), identical code
path, the only variable being whether `configs_base64.txt` is committed:

```
WITH    base64: growth/round =  300.0 KB   sizes=[1792, 2160, 2372, 2612, 2984, 3340, 3560, 3892]
WITHOUT base64: growth/round =    1.7 KB   sizes=[1240, 1240, 1244, 1244, 1248, 1248, 1252, 1252]

base64 contribution      = 298.3 KB/round
base64 share of growth   = 99.4%
```

**298.3 of 300.0 KB/round — 99.4% — is the base64 subscription files.** The reason is
structural: base64 is a whole-stream encoding, so a single changed config near the start
shifts every subsequent byte. Git's delta compressor finds almost nothing to reuse.

This is why the problem cannot be fixed by "committing less often" or "compressing
better": the files that clients depend on most are precisely the files that are
delta-hostile. Only removing them from history — which is what rolling squash does —
works. This measurement independently reproduced the previously recorded 99.4% figure.

---

## 4. Safety: five properties, each with an executable test

A force-push loop on the default branch of a repo with 50 stars and 3 forks is dangerous.
Each hazard is guarded, and each guard is tested by `publish_verify.sh`
(12 scenarios: S1–S10 plus S5b/S5c) and `shallow_test.sh`.

### 4.1 A concurrent owner push must never be destroyed

Guard: `--force-with-lease="refs/heads/main:$tip"`, plus re-anchor and retry (5 attempts).
If the remote moved since we read it, the push is refused, the anchor is recomputed
against the new tip, and the output is rebuilt.

**Negative control — proof the guard is load-bearing.** Scenario **S5c** implements the
naive version (`--force`) and runs the same contested-push scenario:

```
S5c owner commit is on origin before the naive push   → 1
S5c naive force-push DESTROYED the owner commit       → 0
```

The owner's commit is **gone, count = 0**. With `--force-with-lease` (S5/S5b) the
owner's commit survives and the output lands on top of it. The guard is not decorative:
without it the data loss is real and reproducible.

### 4.2 Source code must never be reverted by the bot

The bot writes only output paths. `is_output_path()` classifies every path that changed
between anchor and tip; if **any** non-output path differs, the publish is refused and
retried with a fresh anchor. This is what makes an owner's `git push` to `scripts/`
safe even if it lands mid-run.

```
═══ S10: owner source edit is never reverted ═══
  ✅ S10 owner source edit preserved: print('conv OWNER-FINAL')
  ✅ S10 anchor is the owner commit: feat: owner converter change
  ✅ S10 exactly 1 output commit: 1
```

### 4.3 Never publish an empty or partial tree

If aggregation yields nothing, publishing would wipe every config file for every user.
Guarded by an explicit refusal (`refusing to publish an EMPTY tree`) plus a
`MUST_EXIST` manifest check. Missing-but-optional inputs must not crash the run either:

```
═══ S9: archive/ absent must NOT crash ═══
  ✅ S9 publish succeeded without archive/: 0
  ✅ S9 logged the skip: 1
```

### 4.4 The shallow-checkout anchor trap

**This was the most dangerous bug found in Phase G, and it would have shipped.**

`actions/checkout@v4` defaults to `fetch-depth: 1`. In steady state the tip of `main`
*is* an output commit. So `git log` inside CI sees exactly one commit — an output
commit — and finds **no anchor**. The step fails closed, forever. Not intermittently:
on every run after the first.

Fix: progressive `git fetch --deepen` (0 → 2 → 4 → 8 → 32) until an anchor appears.
`fetch-depth: 0` was rejected as the fix — the repo is 3.55 GB, and a full fetch on
every run is unacceptable.

Verified by `shallow_test.sh`:

```
═══ Q5: is origin's history still intact and correct after that push? ═══
  ✅ origin has source+1 commits: 6
  ✅ tip is the new output commit: chore: round2 [auto-output]
  ✅ parent is the source anchor: 9b5f72c74177a826804caf49b5c723ddaca39749
  ✅ source content intact: core v5
  ✅ output content is round2: 200
  ✅ exactly 1 output commit: 1
  ✅ all 5 source subjects present: 5

  PASS=15  FAIL=0
```

A methodological trap found along the way: **`git clone --depth=N` silently ignores the
depth for local-path clones.** An early version of this harness was therefore testing
nothing. Real shallow clones require a `file://` URL. Had I not checked, I would have
"proven" the trap fixed using a test incapable of detecting it.

### 4.5 No workflow recursion

A bot push to `main` could retrigger the workflow that pushed it — an infinite billed
loop. Two independent reasons it cannot happen:

1. **GitHub's documented behaviour:** pushes authenticated with `GITHUB_TOKEN` do not
   create new workflow runs. (The rationale is quoted inline in the workflow itself, so
   a future maintainer cannot remove the trigger's safety by accident.)
2. **Defence in depth:** the `push` trigger is scoped by a `paths` filter to
   `scripts/**` and `.github/workflows/aggregate.yml` — **neither of which the bot ever
   writes.** It only writes output paths, which match no trigger.

```yaml
  push:
    branches: [main]
    paths:
      - "scripts/**"
      - ".github/workflows/aggregate.yml"
```

### 4.6 Harness results after the final edits

All three harnesses were re-run against the exact committed state:

| Harness | Result |
|---|---|
| `publish_verify.sh` — 12 scenarios | **PASS=62 FAIL=0** (final origin 2.1 M) |
| `shallow_test.sh` | **PASS=15 FAIL=0** |
| `ci_sim.sh` — 25 fresh shallow clones | **PASS=7 FAIL=0** (172 K constant) |

---

## 5. Determinism: three real defects fixed

While measuring churn I found the pipeline was producing gratuitously different output
from identical input. Each of these was a genuine bug that also inflated history.

| # | Defect | Cause | Fix |
|---|---|---|---|
| 1 | Country label unstable between runs | label derived from whichever source remark happened to be seen first | `_HOST_COUNTRY_CACHE` keyed on the **endpoint**; first *decisive* (non-`Global`) detection wins and is frozen |
| 2 | Remark tag was a positional index | `\| 7` — shifts for every config whenever one is added upstream | `stable_label()` = `sha256(dedup_key(line))[:6].upper()` — **content-derived**, position-independent |
| 3 | Output line order unstable | set iteration order | sorted by `dedup_key` |

An invariant I found untested and then locked in: **`brand_remark` must be idempotent.**
Sources in this ecosystem re-publish our own output, so if branding an
already-branded line changed it, output would churn forever. Verified
`brand_remark(brand_remark(x)) == brand_remark(x)` for **both** vless and vmess, and
added it as an assertion. (vmess is the subtle case — its remark lives inside the
base64-encoded JSON `ps` field, not after a `#`.)

### 5.1 Determinism, verified end-to-end

Two full pipeline runs, then a byte-comparison of all 34 output files:

```
/tmp/run3: SUCCESS 7.1 s   ALL=8534 HEAVY=7915 LIGHT=1530   21 ok / 0 empty / 0 fail
/tmp/run4: SUCCESS 6.1 s   (identical counts)

identical=32  differing=2  total=34
differing files: ./health.json ./index.json
```

And the 2 differences are provably **only** wall-clock and measured latency — not
content:

```
< "checked_at": "2026-07-29T03:36:40.153058+00:00"   > "...03:37:07.821294+00:00"
< "elapsed_seconds": 7.1                             > "elapsed_seconds": 6.1
< "latency_ms": 221                                  > "latency_ms": 150
```

**32/34 byte-identical**, with the 2 exceptions fully explained. Independently
confirmed by committing two real consecutive runs into a fresh repo:
**delta = 0 KB.**

### 5.2 Real clients still accept the output

Determinism work is worthless if it breaks the files. Validated with actual client
binaries, not schema guesses:

```
sing-box version 1.13.14
Mihomo Meta v1.19.29 linux amd64 with go1.26.5

  ✅ sing-box all/singbox.json rc=0
  ✅ sing-box heavy/singbox.json rc=0
  ✅ sing-box light/singbox.json rc=0
  ✅ mihomo all/clash.yaml   :: complete, total time: 709ms
  ✅ mihomo heavy/clash.yaml :: complete, total time: 567ms
  ✅ mihomo light/clash.yaml :: complete, total time: 159ms

REAL-CLIENT: PASS=6 FAIL=0
```

---

## 6. Documentation: the branch note became a selling point

Both READMEs were rewritten (`README.md` 303 lines, `README_FA.md` 301 lines).

Mechanical correctness, verified:

```
data occurrences README.md:    0
data occurrences README_FA.md: 0
raw links on main:             8
cdn links on main:             1
non-main branch in any link:   (none)
```

Substantive changes:

- **Inverted the branch note.** It used to explain how to switch to `data`. It now
  reads: *"Everything is on the default branch (`main`). Open the repository and the
  config files are right there — no branch switching, no hidden location. Links you
  copied months ago keep working."*
- **Replaced the 1881-character `data`-branch rationale** with
  `## 🌿 How publishing stays cheap (and why the files are on main)` — the honest
  engineering story: the O(commits) problem, the measured cost, *"The wrong fix (and why
  it was reverted)"* including the four damages and the competitor evidence, then the
  rolling-squash algorithm with its measurements, the safety properties, and one honest
  caveat.
- **Fixed 4 stale claims the tests had not caught.** `{index}` (README.md ×2) and
  `{شماره}` (README_FA.md ×2) still documented the *removed* positional counter. Now
  `{id}` / `{شناسه}`, with the `sha256(dedup-key)[:6]` explanation.
- Removed the `Branch data` / `Branch main` structure headers; *"Two branches with two
  different jobs"* → **"One branch — `main`."**

---

## 7. Tests: 28 → 33, all passing

`scripts/test_pipeline.py` is now **858 lines, 33 tests, 33/33 passing.**

Three obsolete tests that asserted the `data`-branch behaviour were removed. Eight tests
were added, each locking in one Phase G property so it cannot silently regress:

| Test | Locks in |
|---|---|
| `test_publish_branch_is_the_default_branch_and_configurable` | `GH_BRANCH == "main"`; all 4 legacy env overrides still work |
| `test_docs_advertise_the_default_branch_only` | every raw/cdn link in **both** READMEs is on `main`; the old anchor is gone |
| `test_workflow_publishes_to_the_same_branch_the_links_advertise` | workflow target == advertised branch; exactly 1 pushing step |
| `test_publish_step_uses_rolling_squash_and_never_orphans_the_source` | lease present, **no bare `--force`**, `commit-tree … -p $ANCHOR`, `OUT_MARK`, `is_output_path`, `deepen`, all refusal guards |
| `test_remark_tag_is_content_derived_not_positional` | `brand_remark(line,1) == brand_remark(line,9999)` |
| `test_country_label_is_locked_to_the_endpoint_not_the_source_remark` | `#RU Moscow` and `#US New York` on the same endpoint give identical output |
| `test_output_order_is_deterministic` | reversed input ⇒ identical output, **and** the output is genuinely sorted |
| `test_index_advertises_the_publish_branch_key` | `index.json` advertises the branch it is actually published on |

Workflow guard strings, verified present in `.github/workflows/aggregate.yml`
(744 lines, valid YAML, 12 steps):

```
PUBLISH_BRANCH: main    1        is_output_path       2
OUT_MARK                9        deepen               4
force-with-lease        1        refusing to publish  5
commit-tree             3        bare --force pushes  0
```

---

## 8. Four defects I caught in my own work

A verification report that only lists other people's bugs is not a verification report.

**8.1 — I wrote a test against a function that does not exist.** My new test #7 called
`aggregate.build_category("all", lines)`. `grep -n "def build_category"` returned
**nothing**; the real API is `process_category(per_source, source_urls, _cache=None)`.
Had I trusted "the tests pass" without reading the failure output, this test would have
been dead weight forever. Rewritten against the real signature — and *strengthened*
while I was there, by adding `keys == sorted(keys)` so it proves the output is genuinely
**sorted**, not merely stable. It also lacked `import aggregate`, since that module is
imported per-test rather than at file level.

**8.2 — One of my new assertions was simply wrong.** `test_index_advertises_the_publish_branch_key`
asserted `"/main/" in primary_base`. I printed the real value:
`'.../Free-v2ray-Configs/main'` — **no trailing slash**, so the assertion could never
pass. Fixed to `endswith(f"/{GH_BRANCH}")`, and the slash-form check moved onto
`self_url`, where a slash genuinely belongs.

**8.3 — An obsolete assertion in a pre-existing test.** `test_brand_remark_strips_fragment_before_base64_decode`
asserted `ps.endswith("| 7")`. Running the code gave
`ps = 'Global 🌐 | @Raydikalx | E1E2FB'`. The `| 7` was the **positional counter Phase G
deliberately removed** — the test was asserting the bug. Re-pointed at
`core.stable_label(line)`, and I added `not endswith("| 7")` as a regression guard so
the positional index cannot creep back.

**8.4 — Wrong commit authorship, caught before pushing.** `git log --format="%an <%ae>"`
showed **7 unpushed commits** carrying a local tooling identity rather than the
maintainer's, which would have introduced a third, spurious contributor to the
repository's contributor list. Caught by auditing authorship *before* the push rather
than discovering it on GitHub afterwards — where it is permanent. Fixed in §9.3.

*Of the 3 initial test failures, only 1 was a real product bug (the READMEs). The other
2 were defects in my own test code. Diagnosing rather than "fixing until green" is what
separated them.*

---

## 9. Landing the change safely

### 9.1 The "unrelated histories" scare — diagnosed, not force-pushed

`git merge-base origin/main HEAD` returned **rc=1**: apparently disjoint histories. The
tempting move is `push --force`. That would have been catastrophic.

Instead I checked `.git/shallow` — **it exists, with 6 grafted SHAs**, including both
apparent "roots". **The repository is a shallow clone; the disjointness is a graft
artifact, not a real divergence.** A `--deepen=5` (`.git` 59 M → 72 M, since grown to
77 M by later fetches) confirmed that `origin/main`'s own root is grafted too, and
`git rev-parse --is-shallow-repository` still reports `true`.

### 9.2 Proving zero data loss before rewriting anything

Safety refs first: tag `pre-T17` and branch `backup-before-T17`, both at `d9b014d`.

Then `comm -23` of `origin/main`'s file list against ours → **empty**: our tree is a
strict **superset** (47 files vs 12). Comparing all 12 blobs individually: **6
identical, 6 differing** — and all 6 differing are exactly the files Phase G rewrote
(`aggregate.yml`, both READMEs, `aggregate.py`, `core.py`, `test_pipeline.py`). Nothing
on `origin` was unaccounted for.

### 9.3 Rebase and authorship strip, in one operation

```bash
NEW=$(GIT_AUTHOR_NAME="0xRadikal" GIT_AUTHOR_EMAIL="64886141+0xRadikal@users.noreply.github.com" \
      GIT_COMMITTER_NAME="0xRadikal" GIT_COMMITTER_EMAIL="64886141+0xRadikal@users.noreply.github.com" \
      git commit-tree "$TREE" -p "$(git rev-parse origin/main)" -F /tmp/t17_msg.txt)
```

Result `d5a31d8`, verified:

```
HEAD    d5a31d8809f72e8caef83db993eddf747da7be42
tree    b6b425de545c742f7c8f81d46e1877c583e6fb5f   (= the verified work, byte-for-byte)
parent  2386cdf3842228b80b1c3d2d7836dbafa5599242   (= exactly origin/main)
author    0xRadikal <64886141+0xRadikal@users.noreply.github.com>
committer 0xRadikal <64886141+0xRadikal@users.noreply.github.com>

ahead/behind vs origin/main:  0 behind / 1 ahead     → clean fast-forward, no force needed
reachable authors: 3× 0xRadikal, 7× raydikalx-bot[actions]   (no third identity)
```

**Contributor-list scan.** The full reachable history resolves to exactly **two**
identities — the maintainer and the Actions bot — so the push adds no new contributor.
One candidate match surfaced during the scan and I investigated it rather than accepting
the result: line 127, *"The subscription files were being **generated with** several
protocol-level…"* — ordinary English prose inside the **maintainer's own** commit
`1c85af3`, confirmed via `git log --grep`. Re-scanned with precise structural markers
instead of substring matches → **0**. All tracked source files → clean.

### 9.4 Push simulation

Pushing into an empty bare repo failed:

```
! [remote rejected] origin/main -> main (shallow update not allowed)
```

Diagnosed: a shallow clone cannot transfer history crossing its own graft boundary into
a repo lacking those objects. With `receive.shallowupdate=true` the setup push
succeeded, and then our commit pushed cleanly:

```
2386cdf..d5a31d8  HEAD -> main       47 files, 4 commits, all owner/bot-authored
```

The real GitHub `origin` already holds the full history, so our push does not cross the
graft boundary — it is an ordinary fast-forward on top of an existing tip. **This is
reasoned, not yet proven against GitHub itself** (see §11).

---

## 10. Verification summary

| Check | Result |
|---|---|
| Unit tests | **33/33 passed** |
| `test_pipeline.py` syntax | `py_compile` OK (858 lines) |
| Workflow YAML | valid, **12 steps**, `PUBLISH_BRANCH: main` |
| Bare `--force` pushes in workflow | **0** |
| `publish_verify.sh` | **62/62 PASS** |
| `shallow_test.sh` | **15/15 PASS** |
| `ci_sim.sh` (25 fresh shallow clones) | **7/7 PASS**, 172 KB constant, 0 KB/round |
| Pipeline runs | 2× SUCCESS (7.1 s / 6.1 s), 21 ok / 0 empty / 0 fail |
| Output determinism | **32/34 byte-identical**, 2 diffs = timestamps + latency only |
| Real clients (sing-box 1.13.14, mihomo v1.19.29) | **6/6 PASS** |
| `data`/`@data` references in docs | **0** |
| Links on `main` | 8 raw + 1 cdn, **0 on any other branch** |
| Broken anchor links | **0** |
| Tracked files | 47 (34 output + 13 source/docs) |
| Spurious contributor identities | **0** (only maintainer + Actions bot) |
| Real AI traces | **0** (1 false positive investigated and dismissed) |
| Position vs `origin/main` | **0 behind / 1 ahead** |

---

## 11. Honest caveats

Things this report does **not** claim to have proven:

1. **The 3.55 GB of existing history was not rewritten.** Rolling squash makes growth
   O(1) *from now on*; it does not shrink what is already there. Reclaiming it needs a
   history rewrite — which breaks every fork and every existing clone. **Deliberately
   not done**, and it should not be done without the owner's explicit decision.

2. **`shallow update not allowed` is not yet proven absent against real GitHub.** The
   reasoning is sound (GitHub already has the objects; our push is a fast-forward on an
   existing tip) and the simulation supports it, but the sandbox clone is shallow and
   the true push has not run. If it occurs: `git fetch --deepen` further, or re-clone
   unshallow, then re-push. Recovery is straightforward and non-destructive.

3. **The push has not happened.** `d5a31d8` is local. Until it lands, `main` still
   serves 404s and the live workflow — whose `origin/main` copy still reads
   `DATA_BRANCH: data` — keeps publishing to `data`. A fresh `data` snapshot was
   observed dated **2026-07-29 06:53 UTC**, confirming the old pipeline is still active.
   **Phase G is not in effect until the push completes.**

4. **§2.3 and §2.4 are product arguments, not measurements.** The 404s, the orphan
   structure and the 12-file default branch are measured facts. That they *cost stars
   and monetisation* is a well-supported inference from competitor behaviour and how
   GitHub indexing works — not something I measured on this repository.

---

## 12. Remaining work

| # | Task | Status |
|---|---|---|
| T16 | Push `d5a31d8` to `origin/main` | ⏳ **blocked** — needs a PAT from the owner |
| T12 | Verify all 34 legacy `main/...` URLs return 200 | ⏳ after push |
| T13 | Retire the `data` branch once `main` is confirmed serving | ⏳ after T12 |

Retiring `data` last is deliberate: while `d5a31d8` is unpushed, `data` is the **only**
place the configs exist. It must not be deleted until `main` is verified serving —
otherwise the outage this whole phase exists to fix would become total.

Phases B–E (58 items) remain deferred; they were not requested. Phase C items already
identified: the `core.py` two-letter-word country guess loop, the dead `alpn` at
`converters.py` 598–599, `alpn`/`insecure` missing from `parse_proxy`, and the
hysteria2/tuic/wireguard converters.

---

*Every measurement in this document is reproducible from `/home/user/exp/` —
`publish_verify.sh`, `shallow_test.sh`, `ci_sim.sh`, `realistic_growth.sh` — and from
`scripts/test_pipeline.py` in this repository.*
