<?php
/**
 * Plugin Name: Apio systems - Honeypot for Contact Form 7
 * Plugin URI: https://apio.systems
 * Description: Advanced Honeypot plugin for Contact Form 7 to drastically reduce spam on form submissions without user interaction. Includes multiple honeypot fields, checkbox trap, time-based validation, and comprehensive content analysis. Store results in Flamingo.
 * Version: 1.0.1
 * Author: Joris Le Blansch
 * Author URI: https://www.apio.systems
 * License: MIT
 * License URI: https://github.com/apio-sys/apiosys-honeypot-cf7/blob/main/LICENSE
 * Text Domain: apiosys-honeypot-cf7
 * Requires at least: 6.5
 * Requires PHP: 7.2
 * Requires Plugins: contact-form-7, flamingo
 *
 * @version 1.0.0
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

// Get plugin option with default fallback
function apiosys_honeypot_cf7_get_option($key, $default = '') {
    $options = get_option('apiosys_honeypot_cf7_settings', array());
    return isset($options[$key]) ? $options[$key] : $default;
}

// Convert a posted field value (string or array, e.g. checkboxes) to a plain string
function apiosys_honeypot_cf7_stringify($value) {
    if (is_array($value)) {
        return implode(' ', array_map('strval', $value));
    }
    return (string) $value;
}

// Return the first non-empty value among a newline-separated list of field names
function apiosys_honeypot_cf7_first_field($data, $names_str) {
    $fields = array_filter(array_map('trim', explode("\n", $names_str)));
    foreach ($fields as $field) {
        if (isset($data[$field]) && !empty($data[$field])) {
            return apiosys_honeypot_cf7_stringify($data[$field]);
        }
    }
    return '';
}

// Concatenate the values of all matching fields (newline-separated list of field names)
function apiosys_honeypot_cf7_collect_text($data, $names_str) {
    $fields = array_filter(array_map('trim', explode("\n", $names_str)));
    $parts = array();
    foreach ($fields as $field) {
        if (isset($data[$field]) && !empty($data[$field])) {
            $parts[] = apiosys_honeypot_cf7_stringify($data[$field]);
        }
    }
    return implode("\n", $parts);
}

// Normalize text for robust keyword matching:
// lowercase, strip accents (mè -> me), and treat any punctuation/separator as a
// single space so "no-obligation", "no  obligation" and "no.obligation" all match "no obligation".
function apiosys_honeypot_cf7_normalize($text) {
    if (!is_string($text)) {
        $text = apiosys_honeypot_cf7_stringify($text);
    }
    $text = strtolower($text);
    if (function_exists('remove_accents')) {
        $text = remove_accents($text);
    }
    $text = preg_replace('/[^a-z0-9]+/', ' ', $text);
    return trim(preg_replace('/\s+/', ' ', $text));
}

// Detect whether a string contains a link (http/https, www., or a bare domain)
function apiosys_honeypot_cf7_has_link($text) {
    if (preg_match('/(?:https?:\/\/|www\.)/i', $text)) {
        return true;
    }
    // Bare domains such as example.com/foo or example.io — almost always spam in a contact form
    if (preg_match('/\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.(?:com|net|org|info|biz|io|co|me|shop|top|xyz|click|link|online|site|store|ru|cn)\b/i', $text)) {
        return true;
    }
    return false;
}

// Get default settings
function apiosys_honeypot_cf7_default_settings() {
    return array(
        'honeypot_field_name' => 'your-website',
        'checkbox_field_name' => 'contact-me-directly',
        'max_urls' => 1,
        'max_caps_percentage' => 50,
        'min_words' => 3,
        'min_submit_time' => 5,
        'max_submit_time' => 3600,
        'enable_email_domain_check' => 1,
        'suspicious_tlds' => ".shop\n.top\n.xyz\n.click\n.link\n.work\n.gdn\n.men\n.loan\n.date\n.racing\n.win\n.bid\n.stream\n.trade\n.accountant\n.science\n.party\n.download\n.review\n.webcam\n.cricket\n.faith",
        'spam_keywords' => "act fast\nact now\namazing opportunity\nbacklinks\nbetting\nbitcoin\nboost greater traffic\nboost your ranking\nbuy now\ncash flow\ncasino\ncheck this out\ncialis\nclaim your\nclick here\ncongratulations\ncrypto\ndon't miss out\nearn money\nearning money\nevaluation copy\nfacebook likes\nflash offer\nforex\nfree audit\nfree dating\nfree site audit\ngain followers\ngambling\nget more followers\ngoogle ranking\ngrow your brand\ngrow your business\nhundreds of dollars\nincrease followers\nincrease traffic\ninstagram followers\ninvestment opportunity\nlimited offer\nlimited time\nlimited-time deal\nlink building\nloan\nmake money\nmaking money\nmoney back guarantee\nmoney flow\nmortgage\nno obligation\norder now\npassive income\npharmacy\npoker\npornhub\nprescription\nproduce leads\nreal deal\nrisk free\nseo boost\nseo service\nseo services\nsite audit\nskeptical at first\nspecial offer\nthis system\nthousands of dollars\nunlock real growth\nvisit now\nweight loss\nwork from home\nyou've been selected\nyoutube views\noff topic but\nI was wondering if you knew\nI've been looking for\nI truly enjoy reading your blog\nlook forward to your new updates\nPlease let me know if you run into\nwould have some experience with\nfeel free to visit my\nvisit my web\nmy website\nmy blog\nmy page\nhere is my\nstop by my\ncheck out my\nalso visit my\ngreat blog you have\nnice blog here\namazing blog\nexcellent blog\nwonderful blog\nfantastic blog\nsuperb blog\nterrific blog\ngreat site you have\nnice site here\nawesome website\ngreat post\nnice post\nexcellent post\nwonderful post",
        'message_field_names' => "your-message\nmessage\nyour-comment\ncomment\nyour-subject\nsubject",
        'email_field_names' => "your-email\nemail\nyour-mail\nmail",
        'text_field_names' => "your-name\nfirst-name\nlast-name\nname\nfull-name\ncompany-name\ncompany\nyour-company\norganization\njob-title\njob\nposition\nyour-subject\nsubject",
        'disallow_message_links' => 0,
        'enable_scoring' => 1,
        'spam_score_threshold' => 3,
        'enable_free_email_signal' => 1,
        'free_email_domains' => "gmail.com\ngooglemail.com\nyahoo.com\nyahoo.co.uk\nymail.com\nhotmail.com\nhotmail.co.uk\noutlook.com\nlive.com\nmsn.com\naol.com\nicloud.com\nme.com\nmac.com\ngmx.com\ngmx.net\nmail.com\nmail.ru\nprotonmail.com\nproton.me\nyandex.com\nyandex.ru\nzoho.com\ntutanota.com\ninbox.com\nfastmail.com"
    );
}

// Add admin menu under Contact
add_action('admin_menu', 'apiosys_honeypot_cf7_add_admin_menu');
function apiosys_honeypot_cf7_add_admin_menu() {
    add_submenu_page(
        'wpcf7',
        __('Honeypot', 'apiosys-honeypot-cf7'),
        __('Honeypot', 'apiosys-honeypot-cf7'),
        'manage_options',
        'apiosys-honeypot-cf7',
        'apiosys_honeypot_cf7_settings_page'
    );
}

// Link to settings from plugin list
add_filter( 'plugin_action_links_' . plugin_basename(__FILE__), 'apiosys_honeypot_cf7_settings_link' );
function apiosys_honeypot_cf7_settings_link( array $links ) {
    $url = get_admin_url() . "admin.php?page=apiosys-honeypot-cf7";
    $settings_link = '<a href="' . $url . '">' . __('Settings', 'apiosys-honeypot-cf7') . '</a>';
      $links[] = $settings_link;
    return $links;
}

// Register settings
add_action('admin_init', 'apiosys_honeypot_cf7_register_settings');
function apiosys_honeypot_cf7_register_settings() {
    register_setting('apiosys_honeypot_cf7_settings', 'apiosys_honeypot_cf7_settings', 'apiosys_honeypot_cf7_sanitize_settings');
}

// One-time migration: as of 1.0.0 the separate "spam phrases" list was merged
// into the single "spam keywords" list. Fold any existing phrases into keywords.
add_action('admin_init', 'apiosys_honeypot_cf7_maybe_migrate');
function apiosys_honeypot_cf7_maybe_migrate() {
    $options = get_option('apiosys_honeypot_cf7_settings');
    if (!is_array($options) || empty($options['spam_phrases'])) {
        return;
    }
    $keywords = isset($options['spam_keywords']) ? rtrim($options['spam_keywords']) : '';
    $options['spam_keywords'] = ($keywords === '')
        ? $options['spam_phrases']
        : $keywords . "\n" . $options['spam_phrases'];
    unset($options['spam_phrases']);
    update_option('apiosys_honeypot_cf7_settings', $options);
}

// Sanitize settings
function apiosys_honeypot_cf7_sanitize_settings($input) {
    $sanitized = array();
    $sanitized['honeypot_field_name'] = sanitize_text_field($input['honeypot_field_name']);
    $sanitized['checkbox_field_name'] = sanitize_text_field($input['checkbox_field_name']);
    $sanitized['max_urls'] = absint($input['max_urls']);
    $sanitized['max_caps_percentage'] = absint($input['max_caps_percentage']);
    $sanitized['min_words'] = absint($input['min_words']);
    $sanitized['min_submit_time'] = absint($input['min_submit_time']);
    $sanitized['max_submit_time'] = absint($input['max_submit_time']);
    $sanitized['enable_email_domain_check'] = isset($input['enable_email_domain_check']) ? 1 : 0;
    $sanitized['suspicious_tlds'] = sanitize_textarea_field($input['suspicious_tlds']);
    $sanitized['spam_keywords'] = sanitize_textarea_field($input['spam_keywords']);
    $sanitized['message_field_names'] = sanitize_textarea_field($input['message_field_names']);
    $sanitized['email_field_names'] = sanitize_textarea_field($input['email_field_names']);
    $sanitized['text_field_names'] = isset($input['text_field_names']) ? sanitize_textarea_field($input['text_field_names']) : '';
    $sanitized['disallow_message_links'] = isset($input['disallow_message_links']) ? 1 : 0;
    $sanitized['enable_scoring'] = isset($input['enable_scoring']) ? 1 : 0;
    $sanitized['spam_score_threshold'] = isset($input['spam_score_threshold']) ? max(1, absint($input['spam_score_threshold'])) : 3;
    $sanitized['enable_free_email_signal'] = isset($input['enable_free_email_signal']) ? 1 : 0;
    $sanitized['free_email_domains'] = isset($input['free_email_domains']) ? sanitize_textarea_field($input['free_email_domains']) : '';
    return $sanitized;
}

// Settings page
function apiosys_honeypot_cf7_settings_page() {
    // Get current settings merged over defaults (so newly added keys always resolve)
    $options = wp_parse_args(
        get_option('apiosys_honeypot_cf7_settings', array()),
        apiosys_honeypot_cf7_default_settings()
    );
    ?>
    <div class="wrap">
        <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
        <div class="notice notice-info">
            <h3><?php esc_html_e('How to Use', 'apiosys-honeypot-cf7'); ?></h3>
            <p><?php esc_html_e('Add the following shortcodes to your Contact Form 7 forms:', 'apiosys-honeypot-cf7'); ?></p>
            <p><code>[honeypot]</code> - <?php esc_html_e('Adds hidden honeypot fields (text input + checkbox trap)', 'apiosys-honeypot-cf7'); ?></p>
            <p><code>[timestamp]</code> - <?php esc_html_e('Adds time-based validation', 'apiosys-honeypot-cf7'); ?></p>
            <p><strong><?php esc_html_e('Example form:', 'apiosys-honeypot-cf7'); ?></strong></p>
            <pre style="background: #f5f5f5; padding: 10px; border: 1px solid #ddd;">
&lt;label&gt; Your Name
    [text* your-name] &lt;/label&gt;

&lt;label&gt; Your Email
    [email* your-email] &lt;/label&gt;

&lt;label&gt; Your Message
    [textarea your-message] &lt;/label&gt;

[honeypot]
[timestamp]

[submit "Send"]</pre>
        </div>
        <form method="post" action="options.php">
            <?php settings_fields('apiosys_honeypot_cf7_settings'); ?>
            <table class="form-table">
                <tr>
                    <th colspan="2"><h2><?php esc_html_e('Honeypot Settings', 'apiosys-honeypot-cf7'); ?></h2></th>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="honeypot_field_name"><?php esc_html_e('Text Honeypot Field Name', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <input type="text" id="honeypot_field_name" name="apiosys_honeypot_cf7_settings[honeypot_field_name]" value="<?php echo esc_attr($options['honeypot_field_name']); ?>" class="regular-text" />
                        <p class="description"><?php esc_html_e('The name of the hidden text field. Use CF7-style names (e.g., your-website, your-company)', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="checkbox_field_name"><?php esc_html_e('Checkbox Trap Field Name', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <input type="text" id="checkbox_field_name" name="apiosys_honeypot_cf7_settings[checkbox_field_name]" value="<?php echo esc_attr($options['checkbox_field_name']); ?>" class="regular-text" />
                        <p class="description"><?php esc_html_e('The name of the hidden checkbox. Should sound enticing like "contact-me-directly", "receive-updates", "newsletter-subscribe"', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th colspan="2"><h2><?php esc_html_e('Time-Based Validation', 'apiosys-honeypot-cf7'); ?></h2></th>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="min_submit_time"><?php esc_html_e('Minimum Submit Time (seconds)', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="min_submit_time" name="apiosys_honeypot_cf7_settings[min_submit_time]" value="<?php echo esc_attr($options['min_submit_time']); ?>" min="1" max="60" class="small-text" />
                        <p class="description"><?php esc_html_e('Forms submitted faster than this will be marked as spam (recommended: 3-5 seconds)', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="max_submit_time"><?php esc_html_e('Maximum Submit Time (seconds)', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="max_submit_time" name="apiosys_honeypot_cf7_settings[max_submit_time]" value="<?php echo esc_attr($options['max_submit_time']); ?>" min="300" max="7200" class="small-text" />
                        <p class="description"><?php esc_html_e('Forms older than this will be marked as spam (recommended: 3600 = 1 hour)', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th colspan="2"><h2><?php esc_html_e('Email Domain Check', 'apiosys-honeypot-cf7'); ?></h2></th>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="enable_email_domain_check"><?php esc_html_e('Enable Email Domain Check', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <input type="checkbox" id="enable_email_domain_check" name="apiosys_honeypot_cf7_settings[enable_email_domain_check]" value="1" <?php checked(isset($options['enable_email_domain_check']) ? $options['enable_email_domain_check'] : 1, 1); ?> />
                        <p class="description"><?php esc_html_e('Check for suspicious email TLDs commonly used by spammers', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="email_field_names"><?php esc_html_e('Email Field Names', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <textarea id="email_field_names" name="apiosys_honeypot_cf7_settings[email_field_names]" rows="3" class="large-text"><?php echo esc_textarea($options['email_field_names']); ?></textarea>
                        <p class="description"><?php esc_html_e('One field name per line. These are the email fields that will be checked for suspicious domains.', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="suspicious_tlds"><?php esc_html_e('Suspicious TLDs', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <textarea id="suspicious_tlds" name="apiosys_honeypot_cf7_settings[suspicious_tlds]" rows="6" class="large-text code"><?php echo esc_textarea($options['suspicious_tlds']); ?></textarea>
                        <p class="description"><?php esc_html_e('One TLD per line (include the dot, e.g., .shop). Emails from these domains will be marked as spam.', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th colspan="2"><h2><?php esc_html_e('Content Analysis Settings', 'apiosys-honeypot-cf7'); ?></h2></th>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="message_field_names"><?php esc_html_e('Message Field Names', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <textarea id="message_field_names" name="apiosys_honeypot_cf7_settings[message_field_names]" rows="4" class="large-text"><?php echo esc_textarea($options['message_field_names']); ?></textarea>
                        <p class="description"><?php esc_html_e('One field name per line. The main message/comment fields. These are checked for URLs, length, uppercase, flooding and keywords.', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="text_field_names"><?php esc_html_e('Additional Fields to Scan', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <textarea id="text_field_names" name="apiosys_honeypot_cf7_settings[text_field_names]" rows="4" class="large-text"><?php echo esc_textarea($options['text_field_names']); ?></textarea>
                        <p class="description"><?php esc_html_e('One field name per line. Other free-text fields (name, company, job title, subject...) that are also scanned for spam keywords and links. This catches spam hidden outside the message field.', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="max_urls"><?php esc_html_e('Maximum URLs Allowed', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="max_urls" name="apiosys_honeypot_cf7_settings[max_urls]" value="<?php echo esc_attr($options['max_urls']); ?>" min="0" max="10" class="small-text" />
                        <p class="description"><?php esc_html_e('Messages with more URLs than this will be marked as spam (http/https and www. links are counted)', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="disallow_message_links"><?php esc_html_e('Disallow Any Link in Message', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <input type="checkbox" id="disallow_message_links" name="apiosys_honeypot_cf7_settings[disallow_message_links]" value="1" <?php checked($options['disallow_message_links'], 1); ?> />
                        <p class="description"><?php esc_html_e('When enabled, any link in the message marks it as spam (overrides the number above). Useful if your forms never need links from visitors.', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="max_caps_percentage"><?php esc_html_e('Maximum Uppercase Percentage', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="max_caps_percentage" name="apiosys_honeypot_cf7_settings[max_caps_percentage]" value="<?php echo esc_attr($options['max_caps_percentage']); ?>" min="0" max="100" class="small-text" />%
                        <p class="description"><?php esc_html_e('Messages with more uppercase letters than this percentage will be marked as spam', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="min_words"><?php esc_html_e('Minimum Word Count', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="min_words" name="apiosys_honeypot_cf7_settings[min_words]" value="<?php echo esc_attr($options['min_words']); ?>" min="1" max="20" class="small-text" />
                        <p class="description"><?php esc_html_e('Messages with fewer words than this will be marked as spam', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="spam_keywords"><?php esc_html_e('Spam Keywords &amp; Phrases', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <textarea id="spam_keywords" name="apiosys_honeypot_cf7_settings[spam_keywords]" rows="18" class="large-text code"><?php echo esc_textarea($options['spam_keywords']); ?></textarea>
                        <p class="description"><?php esc_html_e('One keyword or phrase per line. Any submission containing one of these (in the message or the additional scanned fields) is marked as spam. Case-insensitive; hyphens, punctuation and accents are ignored, so "no-obligation" matches "no obligation".', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th colspan="2"><h2><?php esc_html_e('Spam Scoring (Weak-Signal Detection)', 'apiosys-honeypot-cf7'); ?></h2></th>
                </tr>
                <tr>
                    <th colspan="2">
                        <p class="description" style="font-weight:normal;max-width:40em;"><?php esc_html_e('Catches "human-looking" spam that passes every individual check. Each weak signal below adds points; a submission is marked as spam only when the total reaches the threshold. Signals include: link in the message, link in another field, free/disposable email provider, gmail dot/plus alias tricks, random digits in the email name, a very short message, "Name &amp; Name Services" company patterns, and no JavaScript detected.', 'apiosys-honeypot-cf7'); ?></p>
                    </th>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="enable_scoring"><?php esc_html_e('Enable Spam Scoring', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <input type="checkbox" id="enable_scoring" name="apiosys_honeypot_cf7_settings[enable_scoring]" value="1" <?php checked($options['enable_scoring'], 1); ?> />
                        <p class="description"><?php esc_html_e('Turn the combined weak-signal scoring on or off.', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="spam_score_threshold"><?php esc_html_e('Spam Score Threshold', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="spam_score_threshold" name="apiosys_honeypot_cf7_settings[spam_score_threshold]" value="<?php echo esc_attr($options['spam_score_threshold']); ?>" min="1" max="10" class="small-text" />
                        <p class="description"><?php esc_html_e('Points required to mark a submission as spam. Lower = more aggressive (2), balanced = 3, higher = more lenient (4+).', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="enable_free_email_signal"><?php esc_html_e('Free Email as a Signal', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <input type="checkbox" id="enable_free_email_signal" name="apiosys_honeypot_cf7_settings[enable_free_email_signal]" value="1" <?php checked($options['enable_free_email_signal'], 1); ?> />
                        <p class="description"><?php esc_html_e('Add a point when the email uses a free/disposable provider (below). This is only a weak signal — it never blocks a submission on its own, so legitimate Gmail users are not blocked.', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="free_email_domains"><?php esc_html_e('Free / Disposable Email Domains', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <textarea id="free_email_domains" name="apiosys_honeypot_cf7_settings[free_email_domains]" rows="6" class="large-text code"><?php echo esc_textarea($options['free_email_domains']); ?></textarea>
                        <p class="description"><?php esc_html_e('One domain per line (e.g., gmail.com). Used only by the scoring signal above.', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}

// Add honeypot field to CF7 forms
add_action('wpcf7_init', 'apiosys_honeypot_cf7_add_shortcode');
function apiosys_honeypot_cf7_add_shortcode() {
    wpcf7_add_form_tag('honeypot', 'apiosys_honeypot_cf7_handler');
}

// Handle the honeypot shortcode - now includes both text field and checkbox trap
function apiosys_honeypot_cf7_handler($tag) {
    $text_field_name = apiosys_honeypot_cf7_get_option('honeypot_field_name', 'your-website');
    $checkbox_field_name = apiosys_honeypot_cf7_get_option('checkbox_field_name', 'contact-me-directly');
    
    // Generate a unique ID for ARIA relationships
    $unique_id = 'hp_' . wp_generate_password(8, false);
    
    // Multi-layer hiding approach:
    // 1. CSS class-based hiding (loaded via wp_enqueue_styles)
    // 2. Inline style as fallback
    // 3. ARIA attributes for accessibility (won't affect bots)
    // 4. Tabindex -1 to prevent keyboard navigation
    // 5. Autocomplete off to prevent browser autofill
    
    $html = sprintf(
        '<span class="wpcf7-form-control-wrap apiosys-hp-field" data-name="%1$s" style="position:absolute;left:-9999px;top:-9999px;" aria-hidden="true">
            <label for="%4$s_text" class="apiosys-hp-label">%2$s</label>
            <input type="text" id="%4$s_text" name="%1$s" value="" size="40" class="wpcf7-form-control wpcf7-text" tabindex="-1" autocomplete="nope" aria-describedby="%4$s_desc" />
            <span id="%4$s_desc" class="apiosys-hp-desc">Leave this field empty</span>
        </span>
        <span class="wpcf7-form-control-wrap apiosys-hp-checkbox" data-name="%3$s" style="position:absolute;left:-9999px;top:-9999px;" aria-hidden="true">
            <label for="%4$s_check" class="apiosys-hp-label">
                <input type="checkbox" id="%4$s_check" name="%3$s" value="1" class="wpcf7-form-control wpcf7-checkbox" tabindex="-1" autocomplete="nope" />
                <span class="wpcf7-list-item-label">%5$s</span>
            </label>
        </span>',
        esc_attr($text_field_name),
        esc_html__('Website URL (optional)', 'apiosys-honeypot-cf7'),
        esc_attr($checkbox_field_name),
        esc_attr($unique_id),
        esc_html__('Yes, contact me directly about special offers', 'apiosys-honeypot-cf7')
    );
    
    return $html;
}

// Validate honeypot on form submission
add_filter('wpcf7_spam', 'apiosys_honeypot_cf7_validation', 10, 2);
function apiosys_honeypot_cf7_validation($spam, $submission) {
    // If already marked as spam, return early
    if ($spam) {
        return $spam;
    }
    $data = $submission->get_posted_data();
    
    // Check text honeypot field
    $text_field_name = apiosys_honeypot_cf7_get_option('honeypot_field_name', 'your-website');
    if (isset($data[$text_field_name]) && !empty($data[$text_field_name])) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'honeypot',
            'reason' => __('Text honeypot field was filled', 'apiosys-honeypot-cf7')
        ));
        return $spam;
    }
    
    // Check checkbox honeypot field
    $checkbox_field_name = apiosys_honeypot_cf7_get_option('checkbox_field_name', 'contact-me-directly');
    if (isset($data[$checkbox_field_name]) && !empty($data[$checkbox_field_name])) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'honeypot',
            'reason' => __('Checkbox honeypot was checked', 'apiosys-honeypot-cf7')
        ));
        return $spam;
    }
    
    return $spam;
}

// Add time-based check
add_action('wpcf7_init', 'apiosys_honeypot_cf7_add_timestamp');
function apiosys_honeypot_cf7_add_timestamp() {
    wpcf7_add_form_tag('timestamp', 'apiosys_honeypot_cf7_timestamp_handler');
}

// Handle timestamp field with obfuscation
function apiosys_honeypot_cf7_timestamp_handler($tag) {
    $timestamp = time();
    // Light obfuscation: XOR with a simple key and base64 encode
    // This makes it slightly harder for bots to manipulate
    $key = 0x5A3C;
    $obfuscated = base64_encode(strval($timestamp ^ $key));
    
    $html = sprintf(
        '<input type="hidden" name="cf7_timestamp" value="%s" />
         <input type="hidden" name="cf7_ts_key" value="%s" />',
        esc_attr($obfuscated),
        esc_attr($key)
    );
    return $html;
}

// Validate timestamp
add_filter('wpcf7_spam', 'apiosys_honeypot_cf7_timestamp_validation', 10, 2);
function apiosys_honeypot_cf7_timestamp_validation($spam, $submission) {
    // If already marked as spam, return early
    if ($spam) {
        return $spam;
    }
    $data = $submission->get_posted_data();
    
    if (!isset($data['cf7_timestamp']) || !isset($data['cf7_ts_key'])) {
        // No timestamp found - mark as spam
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'timestamp',
            'reason' => __('Timestamp field missing', 'apiosys-honeypot-cf7')
        ));
        return $spam;
    }
    
    // Decode the obfuscated timestamp
    $key = intval($data['cf7_ts_key']);
    $decoded = base64_decode($data['cf7_timestamp']);
    if ($decoded === false) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'timestamp',
            'reason' => __('Invalid timestamp format', 'apiosys-honeypot-cf7')
        ));
        return $spam;
    }
    
    $timestamp = intval($decoded) ^ $key;
    $time_elapsed = time() - $timestamp;
    
    // Sanity check - timestamp should be reasonable
    if ($timestamp < strtotime('-1 day') || $timestamp > time() + 60) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'timestamp',
            'reason' => __('Timestamp appears manipulated', 'apiosys-honeypot-cf7')
        ));
        return $spam;
    }
    
    $min_time = apiosys_honeypot_cf7_get_option('min_submit_time', 5);
    $max_time = apiosys_honeypot_cf7_get_option('max_submit_time', 3600);
    
    // Form submitted too quickly
    if ($time_elapsed < $min_time) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'timestamp',
            /* translators: %d: number of seconds elapsed */
            'reason' => sprintf(__('Form submitted too quickly (%d seconds)', 'apiosys-honeypot-cf7'), $time_elapsed)
        ));
        return $spam;
    }
    
    // Form took too long
    if ($time_elapsed > $max_time) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'timestamp',
            /* translators: %d: number of seconds the form was open */
            'reason' => sprintf(__('Form session expired (%d seconds old)', 'apiosys-honeypot-cf7'), $time_elapsed)
        ));
        return $spam;
    }
    
    return $spam;
}

// Email domain validation
add_filter('wpcf7_spam', 'apiosys_honeypot_cf7_email_domain_check', 10, 2);
function apiosys_honeypot_cf7_email_domain_check($spam, $submission) {
    // If already marked as spam, return early
    if ($spam) {
        return $spam;
    }
    
    // Check if email domain check is enabled
    $enabled = apiosys_honeypot_cf7_get_option('enable_email_domain_check', 1);
    if (!$enabled) {
        return $spam;
    }
    
    $data = $submission->get_posted_data();
    
    // Get email field names from settings
    $field_names_str = apiosys_honeypot_cf7_get_option('email_field_names', "your-email\nemail");
    $email_fields = array_filter(array_map('trim', explode("\n", $field_names_str)));
    
    $email = '';
    foreach ($email_fields as $field) {
        if (isset($data[$field]) && !empty($data[$field])) {
            $email = $data[$field];
            break;
        }
    }
    
    if (empty($email)) {
        return $spam;
    }
    
    // Extract domain from email
    $email_parts = explode('@', $email);
    if (count($email_parts) !== 2) {
        return $spam;
    }
    $domain = strtolower($email_parts[1]);
    
    // Get suspicious TLDs
    $tlds_str = apiosys_honeypot_cf7_get_option('suspicious_tlds', '');
    $suspicious_tlds = array_filter(array_map('trim', explode("\n", strtolower($tlds_str))));
    
    // Check if email domain ends with a suspicious TLD
    foreach ($suspicious_tlds as $tld) {
        if (substr($domain, -strlen($tld)) === $tld) {
            $spam = true;
            $submission->add_spam_log(array(
                'agent' => 'email-domain',
                /* translators: %s: the suspicious TLD */
                'reason' => sprintf(__('Suspicious email TLD: %s', 'apiosys-honeypot-cf7'), $tld)
            ));
            return $spam;
        }
    }
    
    return $spam;
}

// Content analysis spam detection
add_filter('wpcf7_spam', 'apiosys_honeypot_cf7_content_analysis', 10, 2);
function apiosys_honeypot_cf7_content_analysis($spam, $submission) {
    // If already marked as spam, return early
    if ($spam) {
        return $spam;
    }

    $data = $submission->get_posted_data();

    // Primary message field (first non-empty match)
    $message = apiosys_honeypot_cf7_first_field(
        $data,
        apiosys_honeypot_cf7_get_option('message_field_names', "your-message\nmessage\nyour-comment\ncomment")
    );

    // Additional free-text fields to scan (name, company, job title, subject, ...)
    $field_text = apiosys_honeypot_cf7_collect_text(
        $data,
        apiosys_honeypot_cf7_get_option('text_field_names', '')
    );

    // Combined text used for keyword scanning across every configured field
    $scan_text = trim($message . "\n" . $field_text);

    // Nothing to analyze
    if ($scan_text === '') {
        return $spam;
    }

    // Checks 1-3, 6-7 apply to the main message field specifically
    if ($message !== '') {
        // 1. Excessive or disallowed URLs (counts http/https and www. links)
        $max_urls = apiosys_honeypot_cf7_get_option('max_urls', 2);
        $disallow_links = apiosys_honeypot_cf7_get_option('disallow_message_links', 0);
        $url_count = preg_match_all('/(?:https?:\/\/|www\.)[^\s]+/i', $message);
        if ($disallow_links && $url_count > 0) {
            $spam = true;
            $submission->add_spam_log(array(
                'agent' => 'content-analysis',
                'reason' => __('Links are not allowed in the message', 'apiosys-honeypot-cf7')
            ));
            return $spam;
        }
        if ($url_count > $max_urls) {
            $spam = true;
            $submission->add_spam_log(array(
                'agent' => 'content-analysis',
                /* translators: 1: number of URLs found, 2: maximum number allowed */
                'reason' => sprintf(__('Too many URLs in message (%1$d found, max %2$d allowed)', 'apiosys-honeypot-cf7'), $url_count, $max_urls)
            ));
            return $spam;
        }

        // 2. Excessive uppercase
        $max_caps = apiosys_honeypot_cf7_get_option('max_caps_percentage', 50);
        $letters_only = preg_replace('/[^a-zA-Z]/', '', $message);
        if (strlen($letters_only) > 10) {
            $uppercase_count = strlen(preg_replace('/[^A-Z]/', '', $letters_only));
            $caps_percentage = ($uppercase_count / strlen($letters_only)) * 100;
            if ($caps_percentage > $max_caps) {
                $spam = true;
                $submission->add_spam_log(array(
                    'agent' => 'content-analysis',
                    /* translators: 1: percentage of uppercase characters, 2: maximum percentage allowed */
                    'reason' => sprintf(__('Excessive uppercase text (%1$.0f%% caps, max %2$d%% allowed)', 'apiosys-honeypot-cf7'), $caps_percentage, $max_caps)
                ));
                return $spam;
            }
        }

        // 3. Minimum word count
        $min_words = apiosys_honeypot_cf7_get_option('min_words', 3);
        $word_count = str_word_count($message);
        if ($word_count < $min_words) {
            $spam = true;
            $submission->add_spam_log(array(
                'agent' => 'content-analysis',
                /* translators: 1: number of words in message, 2: minimum number required */
                'reason' => sprintf(__('Message too short (%1$d words, min %2$d required)', 'apiosys-honeypot-cf7'), $word_count, $min_words)
            ));
            return $spam;
        }

        // 6. Repetitive patterns and whitespace/newline flooding
        // The /s flag lets "." match newlines, catching runs of blank lines used to
        // push spam out of view (a common evasion of the old check).
        if (preg_match('/(.)\1{5,}/s', $message) || preg_match('/(.{2,})\1{3,}/s', $message)) {
            $spam = true;
            $submission->add_spam_log(array(
                'agent' => 'content-analysis',
                'reason' => __('Repetitive text pattern detected', 'apiosys-honeypot-cf7')
            ));
            return $spam;
        }
        if (preg_match('/(?:\r?\n[ \t]*){4,}/', $message)) {
            $spam = true;
            $submission->add_spam_log(array(
                'agent' => 'content-analysis',
                'reason' => __('Excessive blank lines (content flooding)', 'apiosys-honeypot-cf7')
            ));
            return $spam;
        }

        // 7. Excessive special characters
        $special_char_count = preg_match_all('/[^a-zA-Z0-9\s.,!?\-\'"()]/', $message);
        $total_chars = strlen($message);
        if ($total_chars > 0) {
            $special_char_percentage = ($special_char_count / $total_chars) * 100;
            if ($special_char_percentage > 30) {
                $spam = true;
                $submission->add_spam_log(array(
                    'agent' => 'content-analysis',
                    /* translators: %s: percentage of special characters in the message */
                    'reason' => sprintf(__('Excessive special characters (%.0f%% of message)', 'apiosys-honeypot-cf7'), $special_char_percentage)
                ));
                return $spam;
            }
        }
    }

    // 4/5. Spam keywords & phrases (merged list), matched across every scanned field.
    // Both the text and the keywords are normalized so "no-obligation" matches "no obligation".
    $keywords_str = apiosys_honeypot_cf7_get_option('spam_keywords', '');
    $legacy_phrases = apiosys_honeypot_cf7_get_option('spam_phrases', ''); // pre-1.0.0 installs
    if ($legacy_phrases !== '') {
        $keywords_str .= "\n" . $legacy_phrases;
    }
    $spam_keywords = array_filter(array_map('trim', explode("\n", $keywords_str)));
    $normalized_text = apiosys_honeypot_cf7_normalize($scan_text);

    foreach ($spam_keywords as $keyword) {
        $normalized_keyword = apiosys_honeypot_cf7_normalize($keyword);
        if ($normalized_keyword !== '' && strpos($normalized_text, $normalized_keyword) !== false) {
            $spam = true;
            $submission->add_spam_log(array(
                'agent' => 'content-analysis',
                /* translators: %s: the spam keyword that was detected */
                'reason' => sprintf(__('Spam keyword detected: "%s"', 'apiosys-honeypot-cf7'), $keyword)
            ));
            return $spam;
        }
    }

    return $spam;
}

// Weak-signal scoring: catches "human-looking" spam that passes every individual
// hard check. Each signal adds points; the submission is flagged only when the
// combined score reaches the configurable threshold. Runs after all hard checks (priority 20).
add_filter('wpcf7_spam', 'apiosys_honeypot_cf7_scoring', 20, 2);
function apiosys_honeypot_cf7_scoring($spam, $submission) {
    if ($spam) {
        return $spam;
    }
    if (!apiosys_honeypot_cf7_get_option('enable_scoring', 1)) {
        return $spam;
    }

    $data = $submission->get_posted_data();
    $threshold = max(1, intval(apiosys_honeypot_cf7_get_option('spam_score_threshold', 3)));

    $score = 0;
    $reasons = array();

    $message = apiosys_honeypot_cf7_first_field($data, apiosys_honeypot_cf7_get_option('message_field_names', ''));
    $other_text = apiosys_honeypot_cf7_collect_text($data, apiosys_honeypot_cf7_get_option('text_field_names', ''));
    $email = apiosys_honeypot_cf7_first_field($data, apiosys_honeypot_cf7_get_option('email_field_names', ''));

    // Link in the message (weak on its own; strong combined with other signals)
    if ($message !== '' && apiosys_honeypot_cf7_has_link($message)) {
        $score += 1;
        $reasons[] = 'link in message';
    }

    // Link in a field that should never contain one (name, company, job title...)
    if ($other_text !== '' && apiosys_honeypot_cf7_has_link($other_text)) {
        $score += 2;
        $reasons[] = 'link in a form field';
    }

    // Email-based signals
    if ($email !== '' && strpos($email, '@') !== false) {
        $email_parts = explode('@', strtolower($email));
        $local = $email_parts[0];
        $domain = end($email_parts);

        if (apiosys_honeypot_cf7_get_option('enable_free_email_signal', 1)) {
            $free_list = array_filter(array_map('trim', explode("\n", strtolower(
                apiosys_honeypot_cf7_get_option('free_email_domains', '')
            ))));
            foreach ($free_list as $free_domain) {
                if ($domain === $free_domain || substr($domain, -strlen('.' . $free_domain)) === '.' . $free_domain) {
                    $score += 1;
                    $reasons[] = 'free email provider';
                    break;
                }
            }
        }

        // Gmail plus-address alias trick (e.g. name+tag@gmail.com). Plain dots are
        // intentionally NOT counted — "first.last@gmail.com" is common and legitimate.
        if (($domain === 'gmail.com' || $domain === 'googlemail.com') &&
            strpos($local, '+') !== false) {
            $score += 1;
            $reasons[] = 'email alias trick';
        }

        // Name followed by random digits (typical throwaway bot account)
        if (preg_match('/[a-z]{2,}\d{2,}/', $local)) {
            $score += 1;
            $reasons[] = 'digits in email name';
        }
    }

    // Short message. Genuine inquiries to a contact form describe a need and run
    // to dozens of words; content-free one-liners ("I agree", "write about your
    // prices") are a weak spam signal on their own. Threshold kept generous (15)
    // so it only ever tips a submission over the line alongside two other signals.
    if ($message !== '' && str_word_count($message) < 15) {
        $score += 1;
        $reasons[] = 'short message';
    }

    // "Name & Name Services/Ltd/LLC..." company pattern
    $company = apiosys_honeypot_cf7_first_field($data, "company-name\ncompany\nyour-company\norganization");
    if ($company !== '' &&
        preg_match('/\S+\s+&\s+\S+/u', $company) &&
        preg_match('/\b(services|solutions|group|consult|marketing|agency|ltd|llc|inc|gbr|gmbh|ag|co)\b/i', $company)) {
        $score += 1;
        $reasons[] = 'company name pattern';
    }

    // No JavaScript marker (bots that do not execute JS never set this field)
    if (!isset($data['cf7_js_check']) || $data['cf7_js_check'] !== 'enabled') {
        $score += 1;
        $reasons[] = 'no javascript detected';
    }

    if ($score >= $threshold) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'spam-score',
            'reason' => sprintf(
                /* translators: 1: total score, 2: threshold, 3: comma-separated list of matched signals */
                __('Spam score %1$d (threshold %2$d): %3$s', 'apiosys-honeypot-cf7'),
                $score,
                $threshold,
                implode(', ', $reasons)
            )
        ));
    }

    return $spam;
}

// Company name / field analysis for known spam patterns
add_filter('wpcf7_spam', 'apiosys_honeypot_cf7_field_pattern_analysis', 10, 2);
function apiosys_honeypot_cf7_field_pattern_analysis($spam, $submission) {
    // If already marked as spam, return early
    if ($spam) {
        return $spam;
    }
    
    $data = $submission->get_posted_data();
    
    // Check company name field for suspicious patterns
    $company_fields = array('company-name', 'company', 'your-company', 'organization');
    foreach ($company_fields as $field) {
        if (isset($data[$field]) && !empty($data[$field])) {
            $company = $data[$field];
            
            // Check for "Name & Name GbR/LLC/Ltd" pattern (common spam pattern)
            if (preg_match('/\s+(GbR|LLC|Ltd|Inc|GmbH|AG)\s*$/i', $company) && 
                preg_match('/\s+&\s+/', $company)) {
                // Additional check: contains non-Latin characters mixed with company suffixes
                if (preg_match('/[\x{0E00}-\x{0E7F}\x{0400}-\x{04FF}\x{4E00}-\x{9FFF}]/u', $company)) {
                    $spam = true;
                    $submission->add_spam_log(array(
                        'agent' => 'field-analysis',
                        'reason' => __('Suspicious company name pattern', 'apiosys-honeypot-cf7')
                    ));
                    return $spam;
                }
            }
            break;
        }
    }
    
    // Check job title for unusual/random patterns
    $job_fields = array('job-title', 'job', 'position', 'your-position');
    foreach ($job_fields as $field) {
        if (isset($data[$field]) && !empty($data[$field])) {
            $job = strtolower($data[$field]);
            
            // Very unusual job titles that are often in spam databases
            $unusual_jobs = array(
                'guitar repairer', 'leather stamping machine operator',
                'pewter caster', 'fish and game warden', 'horse exerciser'
            );
            
            foreach ($unusual_jobs as $unusual) {
                if ($job === $unusual) {
                    // Just a weak signal - log but don't block
                    // Could be combined with other signals in future versions
                    break;
                }
            }
            break;
        }
    }
    
    return $spam;
}

// Enqueue frontend styles using WordPress best practices
add_action('wp_enqueue_scripts', 'apiosys_honeypot_cf7_enqueue_styles');
function apiosys_honeypot_cf7_enqueue_styles() {
    // Register the style handle (no file needed for inline-only styles)
    wp_register_style('apiosys-honeypot-cf7', false, array(), '1.0.1');
    
    // Enqueue the registered style
    wp_enqueue_style('apiosys-honeypot-cf7');
    
    // Get field names from settings
    $text_field_name = apiosys_honeypot_cf7_get_option('honeypot_field_name', 'your-website');
    $checkbox_field_name = apiosys_honeypot_cf7_get_option('checkbox_field_name', 'contact-me-directly');
    
    // Build the inline CSS with multiple hiding techniques
    // Using various methods to make it hard for bots to detect the hiding
    $inline_css = sprintf(
        '/* Honeypot field hiding - multiple techniques for robustness */
        .wpcf7-form-control-wrap[data-name="%1$s"],
        .wpcf7-form-control-wrap[data-name="%2$s"],
        .apiosys-hp-field,
        .apiosys-hp-checkbox {
            position: absolute !important;
            left: -9999px !important;
            top: -9999px !important;
            width: 1px !important;
            height: 1px !important;
            overflow: hidden !important;
            opacity: 0 !important;
            pointer-events: none !important;
            clip: rect(0, 0, 0, 0) !important;
            clip-path: inset(50%%) !important;
            white-space: nowrap !important;
            border: 0 !important;
            padding: 0 !important;
            margin: -1px !important;
        }
        /* Hide labels and descriptions */
        .apiosys-hp-label,
        .apiosys-hp-desc {
            position: absolute !important;
            left: -9999px !important;
            width: 1px !important;
            height: 1px !important;
            overflow: hidden !important;
        }',
        esc_attr($text_field_name),
        esc_attr($checkbox_field_name)
    );
    
    // Add inline CSS to the registered style
    wp_add_inline_style('apiosys-honeypot-cf7', $inline_css);
}

// Add JavaScript for additional bot detection (optional, progressive enhancement)
add_action('wp_footer', 'apiosys_honeypot_cf7_footer_script');
function apiosys_honeypot_cf7_footer_script() {
    ?>
    <script>
    (function() {
        // Add a marker that JavaScript is enabled
        // Bots that don't run JS won't have this
        var forms = document.querySelectorAll('.wpcf7-form');
        forms.forEach(function(form) {
            var jsField = document.createElement('input');
            jsField.type = 'hidden';
            jsField.name = 'cf7_js_check';
            jsField.value = 'enabled';
            form.appendChild(jsField);
        });
    })();
    </script>
    <?php
}

// Validate JavaScript check
add_filter('wpcf7_spam', 'apiosys_honeypot_cf7_js_check', 5, 2);
function apiosys_honeypot_cf7_js_check($spam, $submission) {
    // If already marked as spam, return early
    if ($spam) {
        return $spam;
    }
    
    $data = $submission->get_posted_data();
    
    // Note: This is a soft check - we don't want to block legitimate users
    // with JS disabled. But we can use it as a signal.
    // For now, just log it for analysis, don't block.
    /*
    if (!isset($data['cf7_js_check']) || $data['cf7_js_check'] !== 'enabled') {
        // JavaScript was not executed - could be a bot
        // For now, just note this, don't block
    }
    */
    
    return $spam;
}
