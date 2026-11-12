<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Handles communication with the Kelpgate REST API and OAuth2 token service.
 * Zero hardcoded endpoints or credentials.
 */
class Kelpgate_Client {
    /** Fetch a new OAuth2 token when fewer than this many seconds of validity remain. */
    const REFRESH_AHEAD_SECONDS = 120;

    private $settings;

    public function __construct() {
        $this->refresh_settings();
    }

    public function refresh_settings() {
        $this->settings = get_option('kelpgate_settings', array());
    }

    public function get_api_url() {
        if (defined('KELPGATE_API_URL') && !empty(KELPGATE_API_URL)) {
            return untrailingslashit(trim(KELPGATE_API_URL));
        }
        return !empty($this->settings['api_url']) ? untrailingslashit(trim($this->settings['api_url'])) : '';
    }

    public function get_token_url() {
        if (defined('KELPGATE_TOKEN_URL') && !empty(KELPGATE_TOKEN_URL)) {
            return untrailingslashit(trim(KELPGATE_TOKEN_URL));
        }
        return !empty($this->settings['token_url']) ? untrailingslashit(trim($this->settings['token_url'])) : '';
    }

    public function get_auth_mode() {
        if (defined('KELPGATE_AUTH_MODE') && !empty(KELPGATE_AUTH_MODE)) {
            return KELPGATE_AUTH_MODE;
        }
        return !empty($this->settings['auth_mode']) ? $this->settings['auth_mode'] : 'oauth2';
    }

    public function get_client_id() {
        if (defined('KELPGATE_CLIENT_ID') && !empty(KELPGATE_CLIENT_ID)) {
            return trim(KELPGATE_CLIENT_ID);
        }
        return !empty($this->settings['client_id']) ? trim($this->settings['client_id']) : '';
    }

    public function get_client_secret() {
        if (defined('KELPGATE_CLIENT_SECRET') && !empty(KELPGATE_CLIENT_SECRET)) {
            return trim(KELPGATE_CLIENT_SECRET);
        }
        return !empty($this->settings['client_secret']) ? trim($this->settings['client_secret']) : '';
    }

    public function get_static_token() {
        if (defined('KELPGATE_TOKEN') && !empty(KELPGATE_TOKEN)) {
            return trim(KELPGATE_TOKEN);
        }
        return !empty($this->settings['api_token']) ? trim($this->settings['api_token']) : '';
    }

    public function get_fail_action() {
        if (defined('KELPGATE_FAIL_ACTION') && in_array(KELPGATE_FAIL_ACTION, array('block', 'allow'), true)) {
            return KELPGATE_FAIL_ACTION;
        }
        return !empty($this->settings['fail_action']) ? $this->settings['fail_action'] : 'block';
    }

    public function get_max_mb() {
        if (defined('KELPGATE_MAX_MB') && intval(KELPGATE_MAX_MB) > 0) {
            return max(1, intval(KELPGATE_MAX_MB));
        }
        return !empty($this->settings['max_mb']) ? max(1, intval($this->settings['max_mb'])) : 50;
    }

    /** Seconds to wait for a file scan. Constant KELPGATE_TIMEOUT_SECONDS wins over the saved setting. */
    public function get_timeout() {
        if (defined('KELPGATE_TIMEOUT_SECONDS') && intval(KELPGATE_TIMEOUT_SECONDS) > 0) {
            $seconds = intval(KELPGATE_TIMEOUT_SECONDS);
        } else {
            $seconds = !empty($this->settings['timeout_seconds']) ? intval($this->settings['timeout_seconds']) : 45;
        }
        return max(5, min(300, $seconds));
    }

    /**
     * Credentials and file contents travel to these endpoints, so they must use TLS. Plain http is
     * accepted only for loopback (local development).
     */
    public static function is_secure_url($url) {
        $parts = wp_parse_url($url);
        if (empty($parts['scheme']) || empty($parts['host'])) {
            return false;
        }
        if (strtolower($parts['scheme']) === 'https') {
            return true;
        }
        return strtolower($parts['scheme']) === 'http'
            && in_array(strtolower($parts['host']), array('localhost', '127.0.0.1', '[::1]', '::1'), true);
    }

    private function endpoints_secure() {
        $api = $this->get_api_url();
        if ($api === '' || !self::is_secure_url($api)) {
            return false;
        }
        if ($this->get_auth_mode() !== 'token') {
            $tok = $this->get_token_url();
            if ($tok === '' || !self::is_secure_url($tok)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Checks if all required settings are filled in.
     *
     * @return bool
     */
    public function is_configured() {
        $api_url = $this->get_api_url();
        if (empty($api_url)) {
            return false;
        }

        if ($this->get_auth_mode() === 'token') {
            return !empty($this->get_static_token());
        }

        // OAuth2 mode requires token_url, client_id, and client_secret
        return !empty($this->get_token_url()) && !empty($this->get_client_id()) && !empty($this->get_client_secret());
    }

    /**
     * Retrieves an active Bearer token.
     * Uses transient cache for OAuth2 access tokens and refreshes automatically when expired.
     *
     * @return string|WP_Error Bearer token string or WP_Error on failure.
     */
    public function get_access_token() {
        if ($this->get_auth_mode() === 'token') {
            $token = $this->get_static_token();
            if (empty($token)) {
                return new WP_Error('missing_token', __('No static API Bearer token configured.', 'kelpgate-malware-scanner'));
            }
            return $token;
        }

        // OAuth2 Client Credentials flow
        $token_url     = $this->get_token_url();
        $client_id     = $this->get_client_id();
        $client_secret = $this->get_client_secret();

        if (empty($token_url)) {
            return new WP_Error('missing_token_url', __('OAuth2 Token URL is missing.', 'kelpgate-malware-scanner'));
        }
        if (empty($client_id) || empty($client_secret)) {
            return new WP_Error('missing_credentials', __('OAuth2 Client ID or Client Secret is missing.', 'kelpgate-malware-scanner'));
        }

        $cache_key = 'kelpgate_oauth_token_' . md5($client_id);
        $lock_key  = 'kelpgate_oauth_lock_' . md5($client_id);

        // The cache holds the token plus its real expiry time. Older versions cached the bare token
        // string (treated as "valid, expiry unknown": it is used as before and replaced on expiry).
        $cached  = get_transient($cache_key);
        $token   = '';
        $expires = 0;
        if (is_array($cached) && !empty($cached['t'])) {
            $token   = (string) $cached['t'];
            $expires = isset($cached['e']) ? (int) $cached['e'] : 0;
        } elseif (is_string($cached) && $cached !== '') {
            $token = $cached;
        }

        if ($token !== '') {
            $remaining = $expires > 0 ? $expires - time() : PHP_INT_MAX;
            if ($remaining > self::REFRESH_AHEAD_SECONDS) {
                return $token;
            }
            // Refresh ahead: the token is about to expire, so get a new one now instead of letting an
            // upload hit a 401 at the boundary. Only one request refreshes; concurrent uploads keep
            // using the still-valid token meanwhile.
            if ($remaining > 0 && get_transient($lock_key)) {
                return $token;
            }
        }

        set_transient($lock_key, 1, 15);
        $fresh = $this->fetch_token($token_url, $client_id, $client_secret);
        delete_transient($lock_key);

        if (is_wp_error($fresh)) {
            // The refresh failed: a token that has not actually expired is still usable.
            if ($token !== '' && ($expires === 0 || $expires > time())) {
                return $token;
            }
            return $fresh;
        }

        // Keep the entry until the token really expires (the refresh-ahead window replaces the old
        // 60-second early expiry).
        set_transient($cache_key, array('t' => $fresh['token'], 'e' => $fresh['expires']), max(60, $fresh['ttl']));

        return $fresh['token'];
    }

    /**
     * Requests a new access token (client credentials). Returns array(token, expires, ttl) or WP_Error.
     */
    private function fetch_token($token_url, $client_id, $client_secret) {
        $response = wp_remote_post($token_url, array(
            'timeout'   => 15,
            'sslverify' => true,
            'headers'   => array(
                'Authorization' => 'Basic ' . base64_encode($client_id . ':' . $client_secret),
                'Content-Type'  => 'application/x-www-form-urlencoded',
            ),
            'body'      => array(
                'grant_type' => 'client_credentials',
                'scope'      => 'scan',
            ),
        ));
        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $data = json_decode(wp_remote_retrieve_body($response), true);

        if ($code !== 200 || !is_array($data) || empty($data['access_token'])) {
            $err_detail = isset($data['error_description']) ? $data['error_description'] : (isset($data['error']) ? $data['error'] : 'HTTP ' . $code);
            /* translators: %s: reason the token request failed. */
            return new WP_Error('oauth_failed', sprintf(__('OAuth2 authentication failed: %s', 'kelpgate-malware-scanner'), $err_detail));
        }

        $expires_in = isset($data['expires_in']) ? intval($data['expires_in']) : 900;
        return array(
            'token'   => $data['access_token'],
            'expires' => time() + $expires_in,
            'ttl'     => $expires_in,
        );
    }

    /**
     * Tests OAuth2 authentication and API health.
     *
     * @return array
     */
    public function test_connection() {
        if (!$this->is_configured()) {
            return array(
                'success' => false,
                'message' => __('Kelpgate is not configured. Please fill in the API Endpoint and OAuth2 credentials first.', 'kelpgate-malware-scanner'),
            );
        }

        if (!$this->endpoints_secure()) {
            return array(
                'success' => false,
                'message' => __('The API and token URLs must use https (http is only allowed for localhost).', 'kelpgate-malware-scanner'),
            );
        }

        $token = $this->get_access_token();
        if (is_wp_error($token)) {
            return array(
                'success' => false,
                'message' => $token->get_error_message(),
            );
        }

        $health_url = $this->get_api_url() . '/api/v1/health';
        $response = wp_remote_get($health_url, array(
            'timeout'   => 10,
            'sslverify' => true,
            'headers'   => array(
                'Authorization' => 'Bearer ' . $token,
            ),
        ));

        if (is_wp_error($response)) {
            return array(
                'success' => false,
                'message' => __('Scanner API unreachable: ', 'kelpgate-malware-scanner') . $response->get_error_message(),
            );
        }

        $code = wp_remote_retrieve_response_code($response);
        if ($code === 200) {
            return array(
                'success' => true,
                'message' => __('Authentication verified and threat scanning service is active.', 'kelpgate-malware-scanner'),
            );
        }

        return array(
            'success' => false,
            /* translators: %d: HTTP status code returned by the scanner API. */
            'message' => sprintf(__('Scanner API responded with HTTP code %d.', 'kelpgate-malware-scanner'), $code),
        );
    }

    /**
     * Scans a file on the local filesystem by streaming it to Kelpgate.
     *
     * @param string $file_path Local path to the file.
     * @param string $filename  Original client filename.
     * @return array Array with verdict: ['clean' => bool, 'signature' => string, 'sha256' => string, 'error' => string]
     */
    public function scan_file($file_path, $filename) {
        if (!$this->is_configured()) {
            // Not configured yet; bypass scan to prevent blocking site operations
            return array(
                'clean'     => true,
                'signature' => 'SKIPPED_NOT_CONFIGURED',
                'sha256'    => '',
                'error'     => '',
            );
        }

        if (!$this->endpoints_secure()) {
            return array(
                'clean'     => ($this->get_fail_action() === 'allow'),
                'signature' => 'INSECURE_ENDPOINT',
                'sha256'    => '',
                'error'     => __('The API and token URLs must use https.', 'kelpgate-malware-scanner'),
            );
        }

        if (!file_exists($file_path) || !is_readable($file_path)) {
            return array(
                'clean'     => false,
                'signature' => 'LOCAL_ERROR:FILE_NOT_READABLE',
                'sha256'    => '',
                'error'     => __('Local upload file cannot be read.', 'kelpgate-malware-scanner'),
            );
        }

        $file_size = filesize($file_path);
        $max_bytes = $this->get_max_mb() * 1024 * 1024;
        if ($file_size > $max_bytes) {
            // Oversized files must not be a scanner bypass: they follow the failure policy
            // (blocked by default; accepted only when the admin chose Fail-Open).
            return array(
                'clean'     => ($this->get_fail_action() === 'allow'),
                'signature' => 'FILE_TOO_LARGE',
                'sha256'    => '',
                'error'     => __('File exceeds the maximum scan size.', 'kelpgate-malware-scanner'),
            );
        }

        if (!$this->has_memory_for($file_size)) {
            return array(
                'clean'     => ($this->get_fail_action() === 'allow'),
                'signature' => 'MEMORY_LIMIT',
                'sha256'    => '',
                'error'     => __('Not enough PHP memory to buffer this file for scanning.', 'kelpgate-malware-scanner'),
            );
        }

        $token = $this->get_access_token();
        if (is_wp_error($token)) {
            $fail_action = $this->get_fail_action();
            return array(
                'clean'     => ($fail_action === 'allow'),
                'signature' => 'AUTH_FAILED',
                'sha256'    => '',
                'error'     => $token->get_error_message(),
            );
        }

        $boundary = wp_generate_password(24, false);
        $headers = array(
            'Content-Type'  => 'multipart/form-data; boundary=' . $boundary,
            'Authorization' => 'Bearer ' . $token,
        );

        $file_contents = file_get_contents($file_path);
        if ($file_contents === false) {
            return array(
                'clean'     => false,
                'signature' => 'LOCAL_ERROR:READ_FAILED',
                'sha256'    => '',
                'error'     => __('Failed to read file contents for transmission.', 'kelpgate-malware-scanner'),
            );
        }

        $payload = '';
        $payload .= "--" . $boundary . "\r\n";
        $payload .= 'Content-Disposition: form-data; name="file"; filename="' . esc_attr($filename) . "\"\r\n";
        $payload .= "Content-Type: application/octet-stream\r\n\r\n";
        $payload .= $file_contents . "\r\n";
        $payload .= "--" . $boundary . "--\r\n";

        $endpoint = '/api/v1/scan/file';
        $url = $this->get_api_url() . $endpoint;

        $response = wp_remote_post($url, array(
            'headers'   => $headers,
            'body'      => $payload,
            'timeout'   => $this->get_timeout(),
            'sslverify' => true,
        ));

        if (is_wp_error($response)) {
            $err_msg = $response->get_error_message();
            $fail_action = $this->get_fail_action();
            return array(
                'clean'     => ($fail_action === 'allow'),
                'signature' => 'SCANNER_UNAVAILABLE',
                'sha256'    => '',
                'error'     => 'Kelpgate scan request failed: ' . $err_msg,
            );
        }

        $status_code = wp_remote_retrieve_response_code($response);

        // A revoked or rotated token would otherwise keep failing until the cached copy expires:
        // drop it and retry once with a fresh one.
        if ($status_code === 401 && $this->get_auth_mode() !== 'token') {
            delete_transient('kelpgate_oauth_token_' . md5($this->get_client_id()));
            $fresh = $this->get_access_token();
            if (!is_wp_error($fresh)) {
                $headers['Authorization'] = 'Bearer ' . $fresh;
                $response = wp_remote_post($url, array(
                    'headers'   => $headers,
                    'body'      => $payload,
                    'timeout'   => $this->get_timeout(),
                    'sslverify' => true,
                ));
                if (!is_wp_error($response)) {
                    $status_code = wp_remote_retrieve_response_code($response);
                }
            }
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        // Synchronous scan success: 200 CLEAN
        if ($status_code === 200 && is_array($data) && isset($data['av-status']) && $data['av-status'] === 'CLEAN') {
            return array(
                'clean'     => true,
                'signature' => 'CLEAN',
                'sha256'    => isset($data['sha256']) ? $data['sha256'] : '',
                'error'     => '',
            );
        }

        // 202 means the scan was only queued, so there is no verdict yet. The plugin only uses
        // synchronous scanning; an unscanned file must not be reported as clean.
        if ($status_code === 202) {
            return array(
                'clean'     => ($this->get_fail_action() === 'allow'),
                'signature' => 'NO_VERDICT_ASYNC',
                'sha256'    => isset($data['sha256']) ? $data['sha256'] : '',
                'error'     => 'Kelpgate returned 202 (queued) without a verdict.',
            );
        }

        // Malware detected: INFECTED
        if (is_array($data) && isset($data['av-status']) && $data['av-status'] === 'INFECTED') {
            return array(
                'clean'     => false,
                'signature' => isset($data['av-signature']) ? $data['av-signature'] : 'INFECTED',
                'sha256'    => isset($data['sha256']) ? $data['sha256'] : '',
                'error'     => 'Malware detected: ' . (isset($data['av-signature']) ? $data['av-signature'] : 'INFECTED'),
            );
        }

        // Error or unexpected status code
        $sig = isset($data['av-signature']) ? $data['av-signature'] : ('HTTP_' . $status_code);
        $fail_action = $this->get_fail_action();
        return array(
            'clean'     => ($fail_action === 'allow'),
            'signature' => $sig,
            'sha256'    => isset($data['sha256']) ? $data['sha256'] : '',
            'error'     => 'Kelpgate scan error (HTTP ' . $status_code . '): ' . $body,
        );
    }

    /**
     * The request body is built in memory (file contents + multipart payload), so a scan needs
     * roughly 2x the file size plus headroom. Refuse up front instead of dying with a fatal error.
     */
    private function has_memory_for($file_size) {
        $limit = function_exists('wp_convert_hr_to_bytes') ? wp_convert_hr_to_bytes(ini_get('memory_limit')) : 0;
        if ($limit <= 0) {
            return true; // unlimited
        }
        return (memory_get_usage(true) + ($file_size * 2) + (4 * 1024 * 1024)) < $limit;
    }
}
