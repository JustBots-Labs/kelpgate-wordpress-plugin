<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Intercepts WordPress uploads and triggers real-time malware scanning.
 * Implements a dual-layer defense:
 *  1. WordPress Core Filter Layer: wp_handle_upload_prefilter & wp_handle_sideload_prefilter.
 *  2. Deep Request Inspection Layer: Inspects $_FILES on 'init' before non-standard plugins can move files.
 */
class Kelpgate_Scanner {
    private $client;
    private static $scanned_files = array();

    public function __construct(Kelpgate_Client $client) {
        $this->client = $client;
    }

    public function init() {
        // Layer 1: Core WordPress Upload Pipelines (Media, REST API, Plugins, Themes, Forms)
        add_filter('wp_handle_upload_prefilter', array($this, 'scan_upload_prefilter'));
        add_filter('wp_handle_sideload_prefilter', array($this, 'scan_upload_prefilter'));

        // Layer 2: Early Request Defense for custom/legacy plugins bypassing wp_handle_upload
        add_action('init', array($this, 'deep_inspect_raw_files'), 1);
    }

    /**
     * Primary upload hook: Inspects files within the WordPress upload pipeline.
     *
     * @param array $file Array with keys 'name', 'type', 'tmp_name', 'error', 'size'.
     * @return array
     */
    public function scan_upload_prefilter($file) {
        if (!empty($file['error'])) {
            return $file;
        }

        // Check if file was already evaluated in the deep request inspection layer
        $cache_key = !empty($file['tmp_name']) ? hash('sha256', $file['tmp_name']) : '';
        if ($cache_key && isset(self::$scanned_files[$cache_key])) {
            $cached = self::$scanned_files[$cache_key];
            if (!$cached['clean']) {
                $file['error'] = __('Security check failed: This file cannot be accepted.', 'kelpgate-malware-scanner');
            }
            return $file;
        }

        if (empty($file['tmp_name']) || !file_exists($file['tmp_name'])) {
            return $file;
        }

        $filename = isset($file['name']) ? sanitize_file_name($file['name']) : 'upload.bin';
        $res = $this->client->scan_file($file['tmp_name'], $filename);
        self::$scanned_files[$cache_key] = $res;

        if (!$res['clean']) {
            $threat_name = self::format_threat_signature($res['signature']);
            $this->log_security_incident($filename, $threat_name, $res['sha256']);

            // Set the WordPress error string to abort the upload cleanly with a minimal, non-leaking message
            $file['error'] = __('Security check failed: This file cannot be accepted.', 'kelpgate-malware-scanner');
        }

        return $file;
    }

    /**
     * Secondary defense: Inspects $_FILES on early 'init' to catch direct move_uploaded_file calls.
     */
    public function deep_inspect_raw_files() {
        if (!$this->client->is_configured()) {
            return;
        }

        $uploads = self::collect_uploads();
        if (empty($uploads)) {
            return;
        }

        // Anonymous visitors can POST multipart data to any URL. Without a limit each file would
        // trigger a synchronous scan (worker exhaustion) and burn the shared scan quota.
        if ($this->raw_scan_limit_exceeded(count($uploads))) {
            foreach ($uploads as $upload) {
                $this->discard_tmp_file($upload['tmp_name']);
            }
            if (!wp_doing_ajax() && !defined('REST_REQUEST')) {
                wp_die(
                    '<h1>' . esc_html__('Too Many Uploads', 'kelpgate-malware-scanner') . '</h1>' .
                    '<p>' . esc_html__('Too many upload attempts. Please try again later.', 'kelpgate-malware-scanner') . '</p>',
                    esc_html__('Too Many Uploads', 'kelpgate-malware-scanner'),
                    array('response' => 429)
                );
            }
            return;
        }

        foreach ($uploads as $upload) {
            $this->inspect_single_tmp_file($upload['tmp_name'], $upload['name']);
        }
    }

    /**
     * Reads the posted files into a flat, validated list of temporary path and sanitized name.
     *
     * A scanner has to look at every upload whether or not the request carries a nonce, so $_FILES
     * is read here and nowhere else. Nothing from it is used until it has been reduced to a string
     * without control characters (tmp_name, which PHP itself generated) or passed through
     * sanitize_file_name() (the client-chosen name). Nested field names (a[b][]) are followed to a
     * fixed depth.
     *
     * @return array[] Each item: array('tmp_name' => string, 'name' => string).
     */
    private static function collect_uploads() {
        $uploads = array();
        if (empty($_FILES) || !is_array($_FILES)) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- see the method description.
            return $uploads;
        }

        foreach ($_FILES as $data) { // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- see the method description; values are validated in flatten_upload().
            if (!is_array($data) || !isset($data['tmp_name'])) {
                continue;
            }
            self::flatten_upload($data['tmp_name'], isset($data['name']) ? $data['name'] : '', $uploads, 0);
        }
        return $uploads;
    }

    /**
     * @param mixed   $tmp     A tmp_name value: a string, or an array of them for multi-file fields.
     * @param mixed   $name    The matching name value or array.
     * @param array[] $uploads Collected items (by reference).
     * @param int     $depth   Current nesting depth.
     */
    private static function flatten_upload($tmp, $name, array &$uploads, $depth) {
        if (is_array($tmp)) {
            if ($depth >= 4) {
                return;
            }
            foreach ($tmp as $key => $value) {
                $child_name = (is_array($name) && isset($name[$key])) ? $name[$key] : '';
                self::flatten_upload($value, $child_name, $uploads, $depth + 1);
            }
            return;
        }

        if (!is_string($tmp) || $tmp === '' || preg_match('/[\x00-\x1f]/', $tmp)) {
            return;
        }

        $clean_name = is_string($name) ? sanitize_file_name($name) : '';
        $uploads[]  = array(
            'tmp_name' => $tmp,
            'name'     => ($clean_name !== '') ? $clean_name : 'file.bin',
        );
    }

    /**
     * Per-IP limit on raw-upload scans for visitors who cannot upload through WordPress itself.
     * Users with the upload_files capability are exempt. Filter: kelpgate_raw_scan_limit_per_minute.
     */
    private function raw_scan_limit_exceeded($files) {
        if (is_user_logged_in() && current_user_can('upload_files')) {
            return false;
        }

        $limit = (int) apply_filters('kelpgate_raw_scan_limit_per_minute', 20);
        if ($limit <= 0) {
            return false;
        }

        $ip    = Kelpgate_Client_IP::get();
        $key   = 'kelpgate_rl_' . hash('sha256', $ip);
        $count = (int) get_transient($key);

        // $files counts files, not requests, so one request cannot carry an unbounded number of uploads.
        if ($count + $files > $limit) {
            return true;
        }

        set_transient($key, $count + $files, MINUTE_IN_SECONDS);
        return false;
    }

    private function discard_tmp_file($path) {
        if (is_string($path) && $path !== '' && file_exists($path)) {
            wp_delete_file($path);
        }
    }

    private function inspect_single_tmp_file($tmp_name, $original_name) {
        if (empty($tmp_name) || !file_exists($tmp_name) || !is_readable($tmp_name)) {
            return;
        }

        $cache_key = hash('sha256', $tmp_name);
        if (isset(self::$scanned_files[$cache_key])) {
            return;
        }

        $filename = sanitize_file_name($original_name);
        $res = $this->client->scan_file($tmp_name, $filename);
        self::$scanned_files[$cache_key] = $res;

        if (!$res['clean']) {
            $threat_name = self::format_threat_signature($res['signature']);
            $this->log_security_incident($filename, $threat_name, $res['sha256']);

            // If a rogue script is about to move this file, destroy the infected temp file immediately
            wp_delete_file($tmp_name);

            // Halt execution if this is a direct non-WordPress upload request
            if (!doing_action('wp_handle_upload_prefilter') && !wp_doing_ajax() && !defined('REST_REQUEST')) {
                wp_die(
                    '<h1>' . esc_html__('Upload Blocked', 'kelpgate-malware-scanner') . '</h1>' .
                    '<p>' . esc_html__('This file cannot be accepted because it violates security policies.', 'kelpgate-malware-scanner') . '</p>',
                    esc_html__('Upload Blocked', 'kelpgate-malware-scanner'),
                    array('response' => 403)
                );
            }
        }
    }

    /**
     * Turns the raw scanner signature into a short display name, dropping engine prefixes.
     *
     * @param string $raw Signature string returned by the API.
     * @return string
     */
    public static function format_threat_signature($raw) {
        if (empty($raw)) {
            return __('Threat Detected', 'kelpgate-malware-scanner');
        }

        // Test string detection
        if (stripos($raw, 'eicar') !== false) {
            return 'EICAR-Standard-AV-Test-Signature';
        }

        // Strip engine name prefixes
        $cleaned = preg_replace('/\b(ClamAV|YARA|Maldet|MalwareBazaar|Kelpgate_CoreSense|Kelpgate_PatternEngine|Kelpgate_WebShield|Kelpgate_CloudIntel|CoreSense|PatternEngine|WebShield|CloudIntel)\s*:\s*/i', '', $raw);
        $cleaned = str_ireplace('{HEX}', '', $cleaned);
        $cleaned = preg_replace('/\.UNOFFICIAL\b/i', '', $cleaned);
        $cleaned = preg_replace('/\.Hit\b/i', '', $cleaned);

        // Normalize multiple threats separated by pipe or comma
        $parts = array_map('trim', explode('|', $cleaned));
        $unique_parts = array();
        foreach ($parts as $p) {
            $sub = array_map('trim', explode(',', $p));
            foreach ($sub as $s) {
                if (!empty($s) && !in_array($s, $unique_parts, true)) {
                    $unique_parts[] = $s;
                }
            }
        }

        if (empty($unique_parts)) {
            return __('Threat Detected', 'kelpgate-malware-scanner');
        }

        return implode(', ', array_slice($unique_parts, 0, 2));
    }

    private function log_security_incident($filename, $signature, $sha256) {
        if (defined('WP_DEBUG') && WP_DEBUG && defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Only runs when WP_DEBUG and WP_DEBUG_LOG are both on.
            error_log(sprintf(
                '[Kelpgate] Security block: file=%s sha256=%s',
                $filename,
                substr($sha256, 0, 16)
            ));
        }

        $incidents = get_option('kelpgate_incidents', array());
        if (!is_array($incidents)) {
            $incidents = array();
        }

        array_unshift($incidents, array(
            'time'      => current_time('mysql'),
            'file'      => $filename,
            'signature' => $signature,
            'sha256'    => $sha256,
            'ip'        => Kelpgate_Client_IP::get(),
            'user_id'   => get_current_user_id(),
        ));

        if (count($incidents) > 50) {
            $incidents = array_slice($incidents, 0, 50);
        }

        update_option('kelpgate_incidents', $incidents, false);
    }
}
