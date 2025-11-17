<?php
/**
 * Plugin Name: Apio systems - Honeypot for Contact Form 7
 * Plugin URI: https://apio.systems
 * Description: Basic Honeypot plugin for Contact Form 7 to drastically reduce spam on form submissions without user interaction. Includes honeypot field, time-based validation, and content analysis. Store results in Flamingo.
 * Version: 0.9.3
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
        'max_urls' => 1,
        'max_caps_percentage' => 50,
        'min_words' => 3,
        'min_submit_time' => 5,
        'max_submit_time' => 3600,
        'spam_keywords' => "act fast\nact now\namazing opportunity\nbacklinks\nbetting\nbitcoin\nboost your ranking\nbuy now\ncash flow\ncasino\ncheck this out\ncialis\nclaim your\nclick here\ncongratulations\ncrypto\ndon't miss out\nearn money\nearning money\nevaluation copy\nfacebook likes\nforex\ngain followers\ngambling\nget more followers\ngrow your business\nhundreds of dollars\nincrease followers\nincrease traffic\ninstagram followers\ninvestment opportunity\nlimited offer\nlimited time\nlink building\nloan\nmake money\nmaking money\nmoney back guarantee\nmoney flow\nmortgage\nno obligation\norder now\npassive income\npharmacy\npoker\nprescription\nreal deal\nrisk free\nseo boost\nseo service\nseo services\nskeptical at first\nspecial offer\nthis system\nthousands of dollars\nvisit now\nweight loss\nwork from home\nyou've been selected\nyoutube views",
        'message_field_names' => "your-message\nmessage\nyour-comment\ncomment\nyour-subject\nsubject"
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
    $sanitized['max_urls'] = absint($input['max_urls']);
    $sanitized['max_caps_percentage'] = absint($input['max_caps_percentage']);
    $sanitized['min_words'] = absint($input['min_words']);
    $sanitized['min_submit_time'] = absint($input['min_submit_time']);
    $sanitized['max_submit_time'] = absint($input['max_submit_time']);
    $sanitized['spam_keywords'] = sanitize_textarea_field($input['spam_keywords']);
    $sanitized['message_field_names'] = sanitize_textarea_field($input['message_field_names']);
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
            <p><code>[honeypot]</code> - <?php esc_html_e('Adds the hidden honeypot field', 'apiosys-honeypot-cf7'); ?></p>
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
                        <label for="honeypot_field_name"><?php esc_html_e('Honeypot Field Name', 'apiosys-honeypot-cf7'); ?></label>
                    </th>
                    <td>
                        <input type="text" id="honeypot_field_name" name="apiosys_honeypot_cf7_settings[honeypot_field_name]" value="<?php echo esc_attr($options['honeypot_field_name']); ?>" class="regular-text" />
                        <p class="description"><?php esc_html_e('The name of the hidden field. Use CF7-style names (e.g., your-website, your-company)', 'apiosys-honeypot-cf7'); ?></p>
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

// Handle the honeypot shortcode
function apiosys_honeypot_cf7_handler($tag) {
    $field_name = apiosys_honeypot_cf7_get_option('honeypot_field_name', 'your-website');
    $html = sprintf(
        '<span class="wpcf7-form-control-wrap apiosys-honeypot-wrap" data-name="%1$s">
            <label>Website (optional)</label>
            <input type="text" name="%1$s" value="" size="40" class="wpcf7-form-control" tabindex="-1" autocomplete="off" aria-hidden="true" />
        </span>',
        esc_attr($field_name)
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
    $field_name = apiosys_honeypot_cf7_get_option('honeypot_field_name', 'your-website');
    // Check if honeypot field exists and has a value
    if (isset($data[$field_name]) && !empty($data[$field_name])) {
        // Honeypot was filled - this is spam
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'honeypot',
            'reason' => __('Honeypot field was filled', 'apiosys-honeypot-cf7')
        ));
    }
    return $spam;
}

// Add time-based check
add_action('wpcf7_init', 'apiosys_honeypot_cf7_add_timestamp');
function apiosys_honeypot_cf7_add_timestamp() {
    wpcf7_add_form_tag('timestamp', 'apiosys_honeypot_cf7_timestamp_handler');
}

// Handle timestamp field
function apiosys_honeypot_cf7_timestamp_handler($tag) {
    $timestamp = time();
    $html = sprintf(
        '<input type="hidden" name="cf7_timestamp" value="%s" />',
        esc_attr($timestamp)
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
    if (!isset($data['cf7_timestamp'])) {
        // No timestamp found - mark as spam
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'timestamp',
            'reason' => __('Timestamp field missing', 'apiosys-honeypot-cf7')
        ));
        return $spam;
    }
    $timestamp = intval($data['cf7_timestamp']);
    $time_elapsed = time() - $timestamp;
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
    // 5. Check for repetitive patterns
    if (preg_match('/(.)\1{5,}/', $message) || preg_match('/(.{2,})\1{3,}/', $message)) {
        $spam = true;
        $submission->add_spam_log(array(
            'agent' => 'content-analysis',
            'reason' => __('Repetitive text pattern detected', 'apiosys-honeypot-cf7')
        ));
        return $spam;
    }
    // 6. Check for excessive special characters
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
    return $spam;
}

// Enqueue frontend styles using WordPress best practices
add_action('wp_enqueue_scripts', 'apiosys_honeypot_cf7_enqueue_styles');
function apiosys_honeypot_cf7_enqueue_styles() {
    // Register the style handle (no file needed for inline-only styles)
    wp_register_style('apiosys-honeypot-cf7', false, array(), '0.9.3');
    
    // Enqueue the registered style
    wp_enqueue_style('apiosys-honeypot-cf7');
    
    // Get the honeypot field name from settings
    $field_name = apiosys_honeypot_cf7_get_option('honeypot_field_name', 'your-website');
    
    // Build the inline CSS
    $inline_css = sprintf(
        '.wpcf7-form-control-wrap[data-name="%s"],
        .apiosys-honeypot-wrap {
            position: absolute !important;
            left: -9999px !important;
            width: 1px !important;
            height: 1px !important;
            overflow: hidden !important;
            opacity: 0 !important;
            pointer-events: none !important;
        }',
        esc_attr($field_name)
    );
    
    // Add inline CSS to the registered style
    wp_add_inline_style('apiosys-honeypot-cf7', $inline_css);
}
