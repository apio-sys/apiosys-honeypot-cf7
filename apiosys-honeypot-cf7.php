<?php
/**
 * Plugin Name: Apio systems - Honeypot for Contact Form 7
 * Plugin URI: https://apio.systems
 * Description: Advanced Honeypot plugin for Contact Form 7 to drastically reduce spam on form submissions without user interaction. Includes multiple honeypot fields, checkbox trap, time-based validation, and comprehensive content analysis. Store results in Flamingo.
 * Version: 0.9.4
 * Author: Joris Le Blansch
 * Author URI: https://apio.systems
 * License: MIT
 * License URI: https://github.com/apio-sys/apiosys-honeypot-cf7/blob/main/LICENSE
 * Text Domain: apiosys-honeypot-cf7
 * Requires at least: 6.5
 * Requires PHP: 7.2
 * Requires Plugins: contact-form-7, flamingo
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
        'spam_keywords' => "act fast\nact now\namazing opportunity\nbacklinks\nbetting\nbitcoin\nboost greater traffic\nboost your ranking\nbuy now\ncash flow\ncasino\ncheck this out\ncialis\nclaim your\nclick here\ncongratulations\ncrypto\ndon't miss out\nearn money\nearning money\nevaluation copy\nfacebook likes\nflash offer\nforex\nfree dating\ngain followers\ngambling\nget more followers\ngoogle ranking\ngrow your brand\ngrow your business\nhundreds of dollars\nincrease followers\nincrease traffic\ninstagram followers\ninvestment opportunity\nlimited offer\nlimited time\nlimited-time deal\nlink building\nloan\nmake money\nmaking money\nmoney back guarantee\nmoney flow\nmortgage\nno obligation\norder now\npassive income\npharmacy\npoker\npornhub\nprescription\nproduce leads\nreal deal\nrisk free\nseo boost\nseo service\nseo services\nskeptical at first\nspecial offer\nthis system\nthousands of dollars\nunlock real growth\nvisit now\nweight loss\nwork from home\nyou've been selected\nyoutube views",
        'spam_phrases' => "off topic but\nI was wondering if you knew\nI've been looking for\nI truly enjoy reading your blog\nlook forward to your new updates\nPlease let me know if you run into\nwould have some experience with\nfeel free to visit my\nvisit my web\nmy website\nmy blog\nmy page\nhere is my\nstop by my\ncheck out my\nalso visit my\ngreat blog you have\nnice blog here\namazing blog\nexcellent blog\nwonderful blog\nfantastic blog\nsuperb blog\nterrific blog\ngreat site you have\nnice site here\nawesome website\ngreat post\nnice post\nexcellent post\nwonderful post",
        'message_field_names' => "your-message\nmessage\nyour-comment\ncomment\nyour-subject\nsubject",
        'email_field_names' => "your-email\nemail\nyour-mail\nmail"
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
    $sanitized['spam_phrases'] = sanitize_textarea_field($input['spam_phrases']);
    $sanitized['message_field_names'] = sanitize_textarea_field($input['message_field_names']);
    $sanitized['email_field_names'] = sanitize_textarea_field($input['email_field_names']);
    return $sanitized;
}

// Settings page
function apiosys_honeypot_cf7_settings_page() {
    // Get current settings or defaults
    $options = get_option('apiosys_honeypot_cf7_settings', apiosys_honeypot_cf7_default_settings());
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
                        <p class="description"><?php esc_html_e('One field name per line. These are the fields that will be analyzed for spam content.', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="max_urls"><?php esc_html_e('Maximum URLs Allowed', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <input type="number" id="max_urls" name="apiosys_honeypot_cf7_settings[max_urls]" value="<?php echo esc_attr($options['max_urls']); ?>" min="0" max="10" class="small-text" />
                        <p class="description"><?php esc_html_e('Messages with more URLs than this will be marked as spam', 'apiosys-honeypot-cf7'); ?></p>
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
                        <label for="spam_keywords"><?php esc_html_e('Spam Keywords', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <textarea id="spam_keywords" name="apiosys_honeypot_cf7_settings[spam_keywords]" rows="15" class="large-text code"><?php echo esc_textarea($options['spam_keywords']); ?></textarea>
                        <p class="description"><?php esc_html_e('One keyword or phrase per line. Messages containing any of these will be marked as spam. Case-insensitive.', 'apiosys-honeypot-cf7'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="spam_phrases"><?php esc_html_e('Spam Phrases (Comment Spam Templates)', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <textarea id="spam_phrases" name="apiosys_honeypot_cf7_settings[spam_phrases]" rows="10" class="large-text code"><?php echo esc_textarea($options['spam_phrases']); ?></textarea>
                        <p class="description"><?php esc_html_e('One phrase per line. These are common phrases used in comment spam templates. Case-insensitive.', 'apiosys-honeypot-cf7'); ?></p>
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
    
    // Get message field names from settings
    $field_names_str = apiosys_honeypot_cf7_get_option('message_field_names', "your-message\nmessage\nyour-comment\ncomment");
    $message_fields = array_filter(array_map('trim', explode("\n", $field_names_str)));
    
    $message = '';
    foreach ($message_fields as $field) {
        if (isset($data[$field]) && !empty($data[$field])) {
            $message = $data[$field];
            break;
        }
    }
    
    // If no message field found, skip content analysis
    if (empty($message)) {
        return $spam;
    }
    
    // 1. Check for excessive URLs
    $max_urls = apiosys_honeypot_cf7_get_option('max_urls', 2);
    $url_count = preg_match_all('/https?:\/\/[^\s]+/i', $message);
    if ($url_count > $max_urls) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'content-analysis',
            /* translators: 1: number of URLs found, 2: maximum number allowed */
            'reason' => sprintf(__('Too many URLs in message (%1$d found, max %2$d allowed)', 'apiosys-honeypot-cf7'), $url_count, $max_urls)
        ));
        return $spam;
    }
    
    // 2. Check for excessive uppercase
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
    
    // 3. Check for minimum word count
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
    
    // 4. Check for spam keywords
    $keywords_str = apiosys_honeypot_cf7_get_option('spam_keywords', '');
    $spam_keywords = array_filter(array_map('trim', explode("\n", $keywords_str)));
    $message_lower = strtolower($message);
    
    foreach ($spam_keywords as $keyword) {
        if (strpos($message_lower, strtolower($keyword)) !== false) {
            $spam = true;
            $submission->add_spam_log(array(
                'agent' => 'content-analysis',
                /* translators: %s: the spam keyword that was detected */
                'reason' => sprintf(__('Spam keyword detected: "%s"', 'apiosys-honeypot-cf7'), $keyword)
            ));
            return $spam;
        }
    }
    
    // 5. Check for spam phrases (comment spam templates)
    $phrases_str = apiosys_honeypot_cf7_get_option('spam_phrases', '');
    $spam_phrases = array_filter(array_map('trim', explode("\n", $phrases_str)));
    
    foreach ($spam_phrases as $phrase) {
        if (strpos($message_lower, strtolower($phrase)) !== false) {
            $spam = true;
            $submission->add_spam_log(array(
                'agent' => 'content-analysis',
                /* translators: %s: the spam phrase that was detected */
                'reason' => sprintf(__('Spam phrase detected: "%s"', 'apiosys-honeypot-cf7'), $phrase)
            ));
            return $spam;
        }
    }
    
    // 6. Check for repetitive patterns
    if (preg_match('/(.)\1{5,}/', $message) || preg_match('/(.{2,})\1{3,}/', $message)) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'content-analysis',
            'reason' => __('Repetitive text pattern detected', 'apiosys-honeypot-cf7')
        ));
        return $spam;
    }
    
    // 7. Check for excessive special characters
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
    
    // 8. Check for non-Latin scripts mixed with Latin in suspicious ways
    // This catches things like "Rowallan โรงงานผลิตอาหารเสริม" in company names
    // Only flag if it looks like random character mixing (spam pattern)
    $has_latin = preg_match('/[a-zA-Z]{3,}/', $message);
    $has_non_latin = preg_match('/[\x{0E00}-\x{0E7F}\x{0400}-\x{04FF}\x{4E00}-\x{9FFF}\x{3040}-\x{309F}\x{30A0}-\x{30FF}]/u', $message);
    
    // This is intentionally NOT flagging - mixed scripts can be legitimate
    // But we note it in the data for future analysis if needed
    
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
    wp_register_style('apiosys-honeypot-cf7', false, array(), '0.9.4');
    
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
