// Produces ../docs/index.html from bundle.html.
//
// This step used to live in somebody's shell history, which is how the byte
// figure in the banner went stale and how the exact splice recipe was twice
// reconstructed wrongly. It is a script now so that `pnpm run bundle` alone
// reproduces the published file, and so the recipe is reviewable.
//
// It does three things, and asserts its way through all of them:
//
//   1. Re-inserts the literal `</head>`. Parcel's minifier drops optional end
//      tags. An HTML5 parser does not care - it infers <head> either way, and
//      html5lib confirms the metadata lands there. Google's Search Console
//      ownership checker DOES care: with no literal <head> in the markup it
//      answered "Your meta tag is not in the <head> section of your home
//      page" and refused to verify. `<head id="head">` in the source survives
//      minification (optional tags keep their start tag once they carry an
//      attribute - `<html lang=en>` survives for the same reason); the end tag
//      is put back here.
//
//   2. Splices in the explanatory banner, immediately after the doctype.
//
//   3. Substitutes the one measured number in that banner that changes on
//      every build, and asserts the numbers that must NOT change. A claim
//      that silently drifts is the exact failure this dashboard argues
//      against, so a drifting claim breaks the build instead.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const BUNDLE = join(here, 'bundle.html');
const BANNER = join(here, 'docs-banner.txt');
const OUT = join(here, '..', 'docs', 'index.html');

const DOCTYPE = '<!DOCTYPE html>';

function must(cond, msg) {
  if (!cond) {
    console.error(`make-docs: ${msg}`);
    process.exit(1);
  }
}

const count = (hay, needle) => hay.split(needle).length - 1;

let html = readFileSync(BUNDLE, 'utf8');
const banner = readFileSync(BANNER, 'utf8');

// ---- structural preconditions -------------------------------------------
must(html.startsWith(DOCTYPE), `bundle.html does not start with ${DOCTYPE}`);
must(count(html, '<head') === 1, `expected exactly 1 "<head", found ${count(html, '<head')}`);
must(count(html, '</head') === 0, 'bundle.html already has a </head>; the minifier changed behaviour');
must(count(html, '<body') === 1, `expected exactly 1 "<body", found ${count(html, '<body')}`);

// ---- claims the banner makes, re-checked on this build ------------------
must(count(html, '<script src') === 0, 'an external script appeared; the banner claims zero');
must(count(html, 'rel=stylesheet') === 0, 'an external stylesheet appeared; the banner claims zero');
must(count(html, '<img') === 0, 'an <img> appeared; the banner claims zero');
must(count(html, '<style') === 1, 'expected exactly one inline <style> block');

// The two proofs of Search Console ownership. Losing either one silently
// would cost the property, so neither is allowed to vanish unnoticed.
must(
  count(html, 'name=google-site-verification') === 1,
  'the google-site-verification meta tag is missing from the build',
);
must(
  count(html, 'tL_l3mWWaWIHxF-BGJs-wedBq9Hn55OmsV4YyirIxSY') === 1,
  'the google-site-verification token does not match the one Search Console issued',
);

// ---- 1. restore the explicit </head> ------------------------------------
const bodyAt = html.indexOf('<body');
const headAt = html.indexOf('<head');
must(headAt < bodyAt, '<head> does not precede <body>');
must(
  html.indexOf('name=google-site-verification') > headAt &&
    html.indexOf('name=google-site-verification') < bodyAt,
  'the verification tag is not between <head> and <body>',
);
html = html.slice(0, bodyAt) + '</head>' + html.slice(bodyAt);

// ---- 2 & 3. banner, with the one figure that drifts substituted ---------
const bundleBytes = Buffer.byteLength(html, 'utf8');
must(banner.includes('__BUNDLE_BYTES__'), 'docs-banner.txt has no __BUNDLE_BYTES__ placeholder');
const stamped = banner.replace('__BUNDLE_BYTES__', bundleBytes.toLocaleString('en-US'));
must(!stamped.includes('__BUNDLE_BYTES__'), 'placeholder was not substituted');

const out = DOCTYPE + '\n' + stamped + '\n' + html.slice(DOCTYPE.length);

// ---- postconditions ------------------------------------------------------
// Checked against `html`, not `out`. The banner is prose that discusses
// <head> and </head> by name, so counting tags across the whole file measures
// the commentary as well as the markup. The first version of this check did
// exactly that and failed the build on its own explanation.
must(count(html, '<head') === 1 && count(html, '</head>') === 1, 'head tags are not balanced in the markup');
const hHead = html.indexOf('<head');
const hClose = html.indexOf('</head>');
const hTag = html.indexOf('name=google-site-verification');
must(hHead < hTag && hTag < hClose, 'verification tag is not inside the literal <head> element');
must(hClose < html.indexOf('<body'), '</head> was not placed before <body>');
must(out.endsWith(html.slice(DOCTYPE.length)), 'the spliced output does not end with the markup');

writeFileSync(OUT, out);
const oTag = out.indexOf('name=google-site-verification');
console.log(
  `make-docs: docs/index.html  ${out.length.toLocaleString('en-US')} B  ` +
    `(banner ${stamped.length.toLocaleString('en-US')} + bundle ${bundleBytes.toLocaleString('en-US')} + 2 newlines)`,
);
console.log(`make-docs: verification tag at byte ${oTag.toLocaleString('en-US')}, inside <head> ... </head>`);
