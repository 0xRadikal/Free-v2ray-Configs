# 🏛️ Governance

This document describes **how decisions actually get made here** — not an
aspirational structure. If something below stops being true, the document is
the thing that is wrong, and fixing it is a welcome pull request.

---

## ⚡ The short version

- One maintainer. No steering committee, no working groups, no vote.
- Decisions are settled by **measurement**, not by seniority or by how long an
  argument goes on.
- Every rule that a contribution is judged against is written down in advance,
  in [CONTRIBUTING.md](CONTRIBUTING.md) — nothing is judged by unpublished taste.
- The licence is [MIT](LICENSE). If you disagree with a decision, you always
  keep the right to fork, and that is a feature of this project, not a threat
  to it.

---

## 👤 Who decides

| Role | Who | What they can do |
|---|---|---|
| Maintainer | [@0xRadikal](https://github.com/0xRadikal) | merge, release, administer the repository, final call on scope |
| Contributor | anyone who opens an issue, discussion or pull request | propose changes, review others' changes, dispute a decision |
| Automation | `raydikalx-bot[actions]` (GitHub Actions) | regenerate and republish the output files — nothing else |

At the time of writing, **exactly one account has write access**, and it is the
maintainer's. There is deliberately no second tier that exists only on paper.

Reviews are requested automatically through
[`.github/CODEOWNERS`](.github/CODEOWNERS), so a pull request from an outside
contributor cannot be lost simply because nobody was tagged.

---

## ⚖️ How a decision gets made

A proposal moves through these steps, in this order:

1. **Is it in scope?** The project aggregates, validates and republishes
   publicly posted proxy configurations, and reports honestly on how well they
   work. Anything that does not serve that is out of scope, however good it is.
2. **Does it violate the doctrine?** The five rules in
   [CONTRIBUTING → Project doctrine](CONTRIBUTING.md#-project-doctrine-please-read-before-proposing-a-feature)
   are not negotiable per-pull-request: *advertised = delivered*, *never publish
   an empty file*, *output must be deterministic*, *fail closed*, *don't weaken
   a parser*. A change that breaks one of them is declined even if it is
   otherwise well written.
3. **What does the measurement say?** Claims are settled with numbers from the
   repository's own artefacts — `index.json`, `health.json`, the test suite —
   rather than with opinion. "It feels faster" is not a result; "the source
   returned 412 configs, 38 unique after dedup" is.
4. **Does the suite still pass?** The test suite is the floor, not the ceiling.
   A behaviour change is expected to arrive with a test that would have failed
   before it.

The list of things that get a pull request rejected is published in advance:
[CONTRIBUTING → What gets a PR rejected](CONTRIBUTING.md#what-gets-a-pr-rejected).
It is kept in that one place on purpose, so the two documents cannot drift
apart.

---

## 🤖 What the automation is allowed to decide

Nothing about direction — only about content it has verified.

The publishing workflow runs on a schedule and republishes the generated
subscription files. It is bound by the same doctrine as a human: if validation
fails, it aborts and leaves the previous good release in place rather than
publishing something broken.

Because the workflow rewrites `main` on every publish, **human commits are
rebased onto `main`, never force-pushed over it.** If your branch falls behind
while you are working, rebase — do not resolve it by overwriting the branch.

---

## 🔒 What is enforced by the platform, not by trust

These are repository rulesets, active, with no bypass actors — they apply to
the maintainer too:

| Protection | Scope | Effect |
|---|---|---|
| `deletion` | default branch | `main` cannot be deleted |
| `required_linear_history` | default branch | no merge commits; history stays linear |
| `deletion`, `update`, `non_fast_forward` | all tags | a published tag cannot be moved, rewritten or removed |

A released tag is therefore immutable: whatever you downloaded at a given tag
is what that tag will always point at.

---

## 🙋 Disagreeing with a decision

This is expected, and there is a route for it:

1. Say so **in the thread where the decision was made**, and say what you
   measured. A decision made from bad data is worth reopening.
2. If the thread has gone stale, open a
   [Discussion](https://github.com/0xRadikal/Free-v2ray-Configs/discussions)
   so it is visible to more than two people.
3. If it concerns conduct rather than code, follow
   [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) instead — that route is private.

The maintainer makes the final call and is expected to give a reason for it.
"No" without a reason is a bug in this process.

---

## 🔑 Becoming a maintainer

There is no formal ladder yet, and inventing one for a project with a single
maintainer would be theatre. What is true:

- Write access is granted on a track record — reviewed contributions that hold
  up over time, not a single large pull request.
- It is granted by the maintainer, in the open, by saying so in an issue.
- The moment it happens, this document and `.github/CODEOWNERS` are updated in
  the same change, so the written structure never lags behind reality.

If you want to head that way, the most useful thing you can do is review other
people's pull requests against the doctrine above.

---

## 🚌 Continuity

The honest position: this is a single-maintainer project, so the bus factor is
one. Nothing here pretends otherwise. Two things limit the damage:

- Everything needed to run the pipeline is in the repository — sources, the
  workflow, the tests and the setup instructions. There is no private build
  step and no undocumented server.
- The MIT licence permits anyone to fork and continue without asking.

---

## ✏️ Changing this document

Open a pull request against it, the same as any other file. Changes that make
the description **more accurate** are the easiest kind to get merged; changes
that add structure the project does not actually have are the hardest.
