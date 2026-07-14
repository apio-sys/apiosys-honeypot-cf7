=== Apio systems - Honeypot for Contact Form 7 ===
Contributors: apiosys
Tags: honeypot, antispam, forms
Requires at least: 6.5
Tested up to: 7.0
Stable tag: 1.0.1
Requires PHP: 7.2
License: MIT
License URI: https://github.com/apio-sys/apiosys-honeypot-cf7/blob/main/LICENSE

Basic Honeypot plugin for Contact Form 7 to drastically reduce spam on form submissions without user interaction.

== Description ==

I like to use Contact Form 7 on most of my WordPress sites. It's a powerful form manager that suits all my needs. I don't like to use external calls to protect the forms from spam submissions though (like reCaptcha or hCaptcha) and don't want to present a manual captcha to a user (math or other puzzle). Since I couldn't find a really basic honeypot script that works on most entries, I created one here. Hopefully it's useful to someone else also.

== Setup ==

- Install the plugin using the regular plugin setup routine or upload the entire apiosys-honeypot-cf7 folder to the /wp-content/plugins/ directory.
- Activate the plugin through the "Plugins" menu in WordPress, you MUST have Contact Form 7 AND Flamingo installed and enabled.
- Add the following shortcodes to your Contact Form 7 forms:

[honeypot] - Adds the hidden honeypot field
[timestamp] - Adds time-based validation

- Complete the rest of the options which you can find in Admin > Contact > Honeypot. A generally good working set of values is enabled by default there.

== What tests are used? ==

- A Honeypot Field
- A Checkbox Trap
- Time-Based Validation
- Email domain Check
- Content Analysis (across all form fields, not just the message)
- Weak-Signal Scoring (combines many small clues to catch "human-looking" spam)

== Does it really work? ==

It has been tested on several high-traffic WP sites. I see a return of ~ 1 ‰ (i.e. 1 in a thousand) of spam going through. That usually corresponds to humans paid to fill forms or sophisticated bots. Please feel free to contribute to make it even better. You can contribute directly [here](https://github.com/apio-sys/apiosys-honeypot-cf7).

== Screenshots ==

1. Spam caught when Honeypot field was filled.
2. Spam caught when the form was submitted too quickly.
3. Spam caught when too many URLs are present in the message fields.
4. Spam caught when certain keywords are detected.

== Installation ==

- Install the plugin using the regular plugin setup routine or upload the entire apiosys-honeypot-cf7 folder to the /wp-content/plugins/ directory.
- Activate the plugin through the "Plugins" menu in WordPress, you MUST have Contact Form 7 AND Flamingo installed and enabled.
- Add the following shortcodes to your Contact Form 7 forms:

[honeypot] - Adds the hidden honeypot field
[timestamp] - Adds time-based validation

- Complete the rest of the options which you can find in Admin > Contact > Honeypot. A generally good working set of values is enabled by default there.

== Changelog ==
= 1.0.1 - 2026-07-14 =
* CHANGE: Widened the "short message" scoring signal from under 6 words to under 15 words (still a single weak point). Catches content-free one-liners ("I agree", "write about your prices") from JS-executing bots that leave the honeypot empty, while staying well clear of genuine inquiries, which run to dozens of words.

= 1.0.0 - 2026-07-12 =
* FEAT: Weak-signal spam scoring - combines many small clues (links, free/disposable email, gmail alias tricks, random digits in email, very short messages, "Name & Name" company patterns, missing JavaScript) with a configurable threshold to catch human-looking spam that passes every individual check.
* FEAT: Content analysis now scans additional fields (name, company, job title, subject...), not only the message.
* FEAT: Keyword matching normalizes hyphens, punctuation and accents, so "no-obligation" matches "no obligation".
* FEAT: Detects whitespace / blank-line flooding used to hide spam.
* FEAT: URL detection now also counts www. and bare-domain links; optional "disallow any link in message" toggle.
* CHANGE: Merged the separate "spam keywords" and "spam phrases" lists into a single list (existing settings are migrated automatically).
* First mature release after months of testing on live data.

= 0.9.4 - 2025-12-04 =
* FEAT: Added checkbox trap.
* FEAT: Improved field hiding.
* FEAT: Email domain TLD check.
* FEAT: Updated default spam keywords list.
* FEAT: Separate list with spam phrases.
* FEAT: Obfuscated timestamp.

= 0.9.3 - 2025-11-16 =
* FIX: CSS resource version.

= 0.9.2 - 2025-11-14 =
* First production release.
