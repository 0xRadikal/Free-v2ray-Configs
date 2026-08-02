# 🆘 Getting help

Short version: **check the live health files first**, then pick the channel that
matches what you have.

---

## 🩺 Before you ask: is it actually broken?

Most "it stopped working" reports are the pipeline behaving exactly as designed.
Free configs die constantly — that is measured here, not hidden.

| Question | Where the answer already is |
| --- | --- |
| How many configs passed the real client checks in the last run? | [`health.json`](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/health.json) → `cascade.buckets` |
| Is an upstream source down? | [`health.json`](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/health.json) → `summary` and the per-source list |
| What does each tier/file contain right now? | [`index.json`](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/index.json) |
| Did the last run even succeed? | [Actions tab](https://github.com/0xRadikal/Free-v2ray-Configs/actions) |
| Everything at a glance | [Live dashboard](https://0xradikal.github.io/Free-v2ray-Configs/) |

If `health.json` shows the last run finished and the buckets are non-zero, the
pipeline is fine — the specific server you tried is simply one of the many that
died since publication. Pull the subscription again and your client will fetch
a fresh list.

---

## 🧭 Where to go

| You have… | Go to |
| --- | --- |
| **A question** — "which tier should I use?", "does this work with client X?" | [Discussions → Q&A](https://github.com/0xRadikal/Free-v2ray-Configs/discussions) |
| **An idea** — a new output format, a tier, a docs improvement | [Discussions → Ideas](https://github.com/0xRadikal/Free-v2ray-Configs/discussions) |
| **A reproducible bug** — the pipeline, the workflow, or a published file is wrong | [New issue → Bug report](https://github.com/0xRadikal/Free-v2ray-Configs/issues/new/choose) |
| **A whole protocol/tier failing in a client** | [New issue → Config problem](https://github.com/0xRadikal/Free-v2ray-Configs/issues/new/choose) |
| **An upstream source to add** | [New issue → Suggest an upstream source](https://github.com/0xRadikal/Free-v2ray-Configs/issues/new/choose) |
| **A security problem** | [SECURITY.md](SECURITY.md) — report privately, not as a public issue |
| **General chat, outage notices, quick questions** | [@Raydikalx on Telegram](https://t.me/Raydikalx) |
| **Want to change the code** | [CONTRIBUTING.md](CONTRIBUTING.md) |

---

## ✍️ What a useful report looks like

The difference between a report that gets fixed and one that stalls is almost
always **numbers**.

Not very useful:

> The configs don't work.

Useful:

> Every `vless` entry in `protocols/vless.txt` is rejected by v2rayNG 1.9.x
> with `invalid reality settings`. 20/20 I tried failed the same way.
> `singbox.json` entries for the same servers import fine.

The second one names the file, the client, the error, and how many you tried —
which is enough to reproduce without a single follow-up question.

---

## ⏱️ What to expect

This is a single-maintainer project run in spare time. There is **no SLA**.
Issues with a reproduction get looked at first, because they can actually be
acted on. Questions that are already answered by `health.json` or the README
may just get a link back — that is not a brush-off, it is the fastest correct
answer.

Nothing here costs money and nothing is gated. If you want to support the work,
that is [entirely optional](https://github.com/0xRadikal/Free-v2ray-Configs#-optional--leave-a-tip).
