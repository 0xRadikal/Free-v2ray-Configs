# Accessibility

Everyone should be able to get a working config from this project, read its
documentation, and report a problem. That includes people who use a screen
reader, a keyboard only, screen magnification, high-contrast or reduced-motion
settings, or a small phone on a slow network.

This page explains what the project offers, what has been tested, what is known
to be missing, and how to tell us about a barrier.

---

## Priorities

- **Target:** we work toward [WCAG 2.2 Level AA](https://www.w3.org/TR/WCAG22/)
  for the dashboard. This is a goal, **not** a claim of verified conformance.
- **Keyboard:** every control on the dashboard can be reached and used with a
  keyboard, with a visible focus outline.
- **Screen readers:** real headings, lists, tables with header cells, labelled
  controls, and status messages announced through live regions.
- **Readable docs:** descriptive link text, alternative text on every
  meaningful image, a logical heading order, and real lists and tables.
- **No dependence on colour alone:** success and failure are written in words,
  not only shown in green or red.

## Contributor expectations

If you change the dashboard (`dashboard-src/`), please:

- check that the change works with a keyboard alone: **Tab** / **Shift+Tab**
  move between controls, **Enter** / **Space** activate them, the arrow keys
  move between tabs, and focus is always visible and never trapped
- give every control an accessible name, and use real headings, lists, tables
  and buttons rather than styled `<div>`s
- don't use colour as the only way to show meaning
- run an automated checker such as
  [axe DevTools](https://www.deque.com/axe/devtools/) and say in the pull
  request what you tested

For documentation: use descriptive link text (not "click here"), add
alternative text to new images (`alt=""` only for purely decorative ones), and
keep the heading order logical.

## Reporting accessibility issues

If something stops you, or makes using the project hard, please tell us. We
treat these reports as expertise, not complaints.

1. **Open an issue** with the
   [accessibility form](https://github.com/0xRadikal/Free-v2ray-Configs/issues/new?template=accessibility.yml).
   If a form is hard to use with your setup, a plain message on Telegram
   ([@Raydikalx](https://t.me/Raydikalx)) is fine too.
2. If you can, include:
   - what you were trying to do, and what happened instead
   - the page or file (a link is enough)
   - your device, operating system, browser, and any assistive technology,
     with versions if you know them
   - a screenshot or recording, **only if you are comfortable sharing one**

You never need to tell us about a disability or share any personal or medical
information.

### Severity

You don't have to pick a severity; we can do that together. As a guide:

- **Critical:** you cannot do a core task at all (for example, you cannot get
  or copy a subscription link).
- **Serious:** it is very difficult, but there is a workaround.
- **Moderate:** it is annoying or inconsistent.
- **Minor:** a small issue with little effect on use.

### How we respond

This is a project kept by one volunteer maintainer, so these are honest
targets rather than guarantees:

- We reply to say we have seen the report, and ask questions only if we need
  them.
- If there is a workaround, we tell you while a fix is in progress.
- Critical and serious barriers are worked on before features and cosmetic
  changes.
- We keep the issue updated when the status changes, and we ask you to confirm
  the fix if you are willing.

## Ownership and maintenance

Accessibility is owned by the project maintainer,
[@0xRadikal](https://github.com/0xRadikal), who triages reports, tracks known
barriers, and keeps this page current. Suggestions for this page are welcome
as an issue or a pull request.

## Supported environments

Most of what people use here is **plain text**, not an interface:

| Part | What it is | Why it matters for accessibility |
| --- | --- | --- |
| Subscription files (`*/configs.txt`, `*_base64.txt`, `clash.yaml`, `singbox.json`) | Plain files read by a VPN/proxy client | Their accessibility depends on **your client app** (v2rayNG, Hiddify, NekoBox, Clash Meta, sing-box …), which this project does not build |
| `README.md` and the `README_FA` / `README_RU` / `README_ZH` translations | Markdown rendered by GitHub | Rendered by GitHub's own interface |
| [Live dashboard](https://0xradikal.github.io/Free-v2ray-Configs/) | One self-contained web page (`docs/index.html`, built from [`dashboard-src/`](dashboard-src/)) | The only interactive interface this project ships |
| `index.json`, `health.json` | Machine-readable status | Anything the dashboard shows can also be read from these files with any tool |

The **subscription links are always available as plain text**, both in the
README and in the dashboard's static (no-JavaScript) content. You never need
the interactive dashboard to use the project.

- **Dashboard:** current versions of Chromium-based browsers (Chrome, Edge),
  Firefox and Safari, on desktop and mobile. It is one HTML file with no
  external fonts, scripts or trackers, so it also loads on slow or filtered
  networks.
- **Without JavaScript:** the dashboard still shows a static summary with every
  main subscription link.
- **Documentation:** whatever GitHub supports for rendering Markdown.
- **Client apps:** outside this project. Please report accessibility problems
  in an app to that app's maintainers.

## Known limitations

- **Dark theme only.** The dashboard has no light theme. Browser zoom and
  operating-system high-contrast modes still apply.
- **The dashboard is in English.** The README is available in English, فارسی,
  Русский and 中文, but the dashboard is not translated yet.
- **Long technical text.** Some README sections (the funnel, the pipeline
  internals) are long and technical. The **"Start here — copy one line"**
  section at the top is the short path.
- **Emoji in headings.** Headings start with an emoji, which some screen
  readers read aloud (for example "rocket, Start here"). It is cosmetic and does
  not block anything.
- **Configs themselves.** Whether a config connects depends on the server and
  your network, not on accessibility. See
  [README → Does it actually work?](README.md#-does-it-actually-work).

### What has been tested

These results are measured, with the date and the tool, so they can be repeated.

**Dashboard — 15 October 2026, automated scan with
[axe-core](https://github.com/dequelabs/axe-core) 4.10.3** (rule sets WCAG 2.0 /
2.1 / 2.2 A and AA, plus best practices), in headless Chromium:

| View | Before the fixes below | After |
| --- | --- | --- |
| Desktop, 1366 px wide | 3 violations | **0** |
| Mobile, 375 px wide | 3 violations | **0** |
| JavaScript disabled (static content) | 1 violation | **0** |

The issues found and fixed in that pass:

1. The *primary / mirror / base64* link tabs pointed screen readers at panels
   that did not exist. The tabs now control real panels.
2. Two wide tables could be scrolled sideways on a phone with a finger but not
   with a keyboard. They can now be focused and scrolled with the arrow keys.
3. The copy-button column had an empty header; it is now named for screen
   readers.
4. Two sidebar links were smaller than 24 × 24 px, the minimum touch-target
   size. They are now at least 24 px tall.

Things that were already in place and were checked, not assumed:

- The page declares its language (`lang="en"`).
- `:focus-visible` draws a 2 px outline on every focused element.
- `prefers-reduced-motion: reduce` turns off animations and transitions.
- Loading and error states are announced (`role="status"` / `role="alert"`).
- Every image in the README files has alternative text. The decorative divider
  line uses empty alternative text (`alt=""`) on purpose so screen readers skip
  it. The SVG artwork in [`assets/`](assets/) carries a `<title>` and
  `role="img"`, or `role="presentation"` when it is decorative.

**Automated tools find only part of the problems.** No manual screen-reader
session (NVDA, JAWS, VoiceOver, TalkBack) has been recorded yet. If you use
one, your report is especially valuable.

## Feedback and improvements

Accessibility is an ongoing practice, not a one-time fix. Suggestions for this
page or for the project's accessibility practices are welcome as an
[issue](https://github.com/0xRadikal/Free-v2ray-Configs/issues/new/choose) or a
pull request. For an active barrier, please use the reporting process above so
it is triaged as one.
