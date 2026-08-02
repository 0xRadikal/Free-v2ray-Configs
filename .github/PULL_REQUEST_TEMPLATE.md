<!--
Thanks for taking the time to send a patch — it is genuinely appreciated.

Everything below is short on purpose. The one section that really matters is
"What did you measure?", because this project treats a claim without a number
as an open question rather than a result.

Full guide: CONTRIBUTING.md
-->

## What does this change?

<!-- One or two sentences. What is different after this PR that was not before? -->

## Why?

<!-- The problem, not the patch. Link an issue with "Closes #123" if there is one. -->

## What did you measure?

<!--
Paste real output, not a description of it. Examples of the expected style:

  Ran the suite: 301/301 passed.
  Source returned 412 configs, 38 unique after dedup.
  vless parse rate went 3,655 -> 3,701 on the same input snapshot.

If a change genuinely cannot be measured (a typo fix, a comment), just say so.
-->

```text

```

## Checklist

- [ ] Branched from `main`, and this PR is **one logical change**.
- [ ] **No regenerated output files in the diff.** If the pipeline ran locally and
      rewrote them, `git checkout --` those paths before committing.
- [ ] Commit messages follow Conventional Commits, e.g.
      `fix(dedup): keep the real host in the key`.
- [ ] No commit subject contains `[auto-output]` — the publish step uses that
      marker to find the last human commit, so a human commit carrying it is
      skipped as if it were bot output.
- [ ] Behaviour changes come with a test. New parser/converter behaviour comes
      with a case that fails before the change and passes after it.
- [ ] Nothing is advertised that the code does not actually deliver — no README
      or docs claim for a protocol, tier or file the pipeline never writes.

<!--
For reference, these are the things that get a PR rejected (CONTRIBUTING.md):

  - edits to generated output paths
  - a behaviour change with no test
  - adding a protocol/feature to a README that the code doesn't actually deliver
  - making a parser more permissive than its converter
  - a new dependency with no justification
  - removing a fail-closed guard to "make the run succeed"

Security-sensitive fix? Please read SECURITY.md first. If disclosing the details
in public would put users at risk, contact the maintainer privately instead of
opening a PR.
-->
