# CLAUDE.md

Guidance for working on this repository.

## What this is

**Apio systems - Honeypot for Contact Form 7** — a single-file WordPress plugin
that reduces spam on Contact Form 7 (CF7) submissions without any external
service, CAPTCHA, or user interaction. Spam that is caught is still stored in
Flamingo (marked as spam), so nothing is silently dropped.

- **Requires:** Contact Form 7 + Flamingo (both mandatory, declared via
  `Requires Plugins`).
- **License:** MIT. **Text Domain:** `apiosys-honeypot-cf7`.
- **Distributed on:** the WordPress.org plugin directory (hence `readme.txt`)
  and GitHub (`README.md`).

## Layout

- `apiosys-honeypot-cf7.php` — the entire plugin. All logic lives here.
- `readme.txt` — WordPress.org readme (the canonical changelog + "Stable tag").
- `README.md` — GitHub-facing readme.
- `uninstall.php` — deletes the single option row on uninstall.
- `.distignore` — files excluded from the built `.zip` (dev/meta files).
- `screenshot-*.png` — WordPress.org listing screenshots.
- No build step, no dependencies, no tests. It is plain procedural PHP.

## Architecture

Everything is procedural, prefixed `apiosys_honeypot_cf7_`. Settings live in a
single option, `apiosys_honeypot_cf7_settings` (an associative array), with
defaults from `apiosys_honeypot_cf7_default_settings()`. Read individual values
with `apiosys_honeypot_cf7_get_option($key, $default)`.

### Two CF7 form tags (shortcodes)
- `[honeypot]` — renders a hidden text field **and** a hidden checkbox trap
  (`apiosys_honeypot_cf7_handler`). Hidden via multiple techniques: off-screen
  positioning, an enqueued inline stylesheet, `aria-hidden`, `tabindex="-1"`,
  `autocomplete="nope"`.
- `[timestamp]` — renders a hidden, lightly obfuscated (XOR + base64) submit
  timestamp (`apiosys_honeypot_cf7_timestamp_handler`).

### Spam-detection pipeline
All checks hook `wpcf7_spam` and **early-return `$spam` if already true**, so
the first failing check wins and later checks are skipped. Each failure calls
`$submission->add_spam_log(['agent' => ..., 'reason' => ...])`. Priorities:

1. `apiosys_honeypot_cf7_js_check` (priority 5) — JS-presence marker; currently
   a **soft/no-op** check (blocks nothing). The `cf7_js_check` field it relies on
   is now *also* consumed as a weak signal by the scoring check (see below).
2. `apiosys_honeypot_cf7_validation` (10) — text honeypot filled / checkbox
   trap checked.
3. `apiosys_honeypot_cf7_timestamp_validation` (10) — missing, malformed,
   manipulated, too-fast, or too-old timestamp.
4. `apiosys_honeypot_cf7_email_domain_check` (10) — email TLD against the
   suspicious-TLD list (toggleable).
5. `apiosys_honeypot_cf7_content_analysis` (10) — **hard blocks.** URL/link count
   and uppercase %, min word count, repetitive patterns and **whitespace/blank-line
   flooding**, excessive special characters (all on the message field); plus a
   single merged **keyword/phrase** scan run across the message **and** the extra
   `text_field_names` fields, using `apiosys_honeypot_cf7_normalize()` so hyphens,
   punctuation and accents don't defeat a match. Honors the `disallow_message_links`
   toggle.
6. `apiosys_honeypot_cf7_field_pattern_analysis` (10) — company-name / job-title
   heuristics (mostly weak signals; only the "Name & Name GbR/LLC + non-Latin"
   pattern actually blocks).
7. `apiosys_honeypot_cf7_scoring` (20) — **weak-signal scoring.** Runs only after
   every hard check passes. Accumulates points from many individually-innocent
   signals (link in message, link in another field, free/disposable email, gmail
   dot/plus alias, random digits in the email local-part, very short message,
   "Name & Name Services/Ltd" company pattern, missing `cf7_js_check`) and flags
   spam when the total reaches `spam_score_threshold`. This is what catches
   "human-looking" spam that no single rule would.

### Shared helpers
`apiosys_honeypot_cf7_first_field()` (first non-empty of a field-name list),
`apiosys_honeypot_cf7_collect_text()` (concatenate all matching fields),
`apiosys_honeypot_cf7_stringify()` (array→string for checkbox/multi values),
`apiosys_honeypot_cf7_normalize()` (lowercase + `remove_accents` + collapse
punctuation, for keyword matching), `apiosys_honeypot_cf7_has_link()` (http/www/
bare-domain detection). Use these instead of re-implementing field lookups.

### Configurable field-name lists
The plugin does not assume fixed CF7 field names. `message_field_names` and
`email_field_names` are newline-separated settings; detection iterates them and
uses the first non-empty match. When adding a check that reads a form field,
prefer making the field name configurable the same way.

## Settings reference (keys in the option array)

`honeypot_field_name`, `checkbox_field_name`, `max_urls`,
`max_caps_percentage`, `min_words`, `min_submit_time`, `max_submit_time`,
`enable_email_domain_check`, `suspicious_tlds`, `spam_keywords` (merged
keywords+phrases), `message_field_names`, `email_field_names`,
`text_field_names` (extra fields to scan), `disallow_message_links`,
`enable_scoring`, `spam_score_threshold`, `enable_free_email_signal`,
`free_email_domains`, `company_field_names`, `enable_company_email_mismatch`,
`enable_work_email_validation`, `work_email_message`.

`spam_phrases` is **removed** as of 1.0.0; `apiosys_honeypot_cf7_maybe_migrate()`
folds any legacy value into `spam_keywords` once, on `admin_init`.

The admin UI lives under **Contact → Honeypot** (`add_submenu_page` on `wpcf7`).
When you add a setting: (1) add a default in
`apiosys_honeypot_cf7_default_settings()`, (2) sanitize it in
`apiosys_honeypot_cf7_sanitize_settings()`, (3) render a field in
`apiosys_honeypot_cf7_settings_page()`, (4) read it via
`apiosys_honeypot_cf7_get_option()`.

## Conventions

- Prefix every function/option with `apiosys_honeypot_cf7_`.
- All user-facing strings use `__()` / `esc_html__()` with the text domain, and
  translator comments (`/* translators: ... */`) for any placeholders.
- Escape on output (`esc_attr`, `esc_html`, `esc_textarea`) and sanitize on
  input; follow WordPress Plugin Directory (WPCS) expectations.
- Keep PHP compatible with **PHP 7.2** (no arrow functions, no typed props,
  etc.).
- Content matching is case-insensitive (`strtolower` + `strpos`).

## Releasing / versioning

The version appears in **three** places that must stay in sync:
1. `Version:` header in `apiosys-honeypot-cf7.php` (the single source of truth —
   there is intentionally no `@version` docblock tag to duplicate it),
2. the CSS version string in `wp_register_style()` (currently `1.0.3`),
3. `Stable tag:` in `readme.txt`.

Also update the `== Changelog ==` section in `readme.txt` (this is the canonical
changelog) and bump `Tested up to:` when validated against a new WP release.
Current version: **1.0.3** (ship further fixes as 1.0.4, etc.).
