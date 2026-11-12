<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Handles WordPress admin menu, settings page, and connection verification.
 * Adheres strictly to the Kelpgate design system:
 *  - Zero gradients (solid surfaces only)
 *  - Zero emojis (real inline SVGs only)
 *  - Zero useless badges
 *  - Flattened cards with logical grouping
 *  - Mathematical radius matching (R_inner = R_outer - padding)
 *  - No looping animations (spin animation only while actively requesting)
 *  - Zero backend engine leaks (no ClamAV, YARA, Maldet, or Hydra exposed in UI)
 */
class Kelpgate_Admin {
    private $client;

    public function __construct(Kelpgate_Client $client) {
        $this->client = $client;
    }

    public function init() {
        add_action('admin_menu', array($this, 'add_menu_page'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_assets'));
        add_filter('plugin_action_links_' . KELPGATE_PLUGIN_BASENAME, array($this, 'add_action_links'));
        
        // AJAX Connection verification endpoint
        add_action('wp_ajax_kelpgate_test_connection', array($this, 'ajax_test_connection'));
    }

    public function enqueue_assets($hook) {
        if ($hook !== 'settings_page_kelpgate') {
            return;
        }
        $css_ver = defined('KELPGATE_VERSION') ? KELPGATE_VERSION : '0';
        $css_path = KELPGATE_PLUGIN_DIR . 'assets/admin.css';
        if (file_exists($css_path)) {
            $css_ver .= '.' . filemtime($css_path);
        }
        wp_enqueue_style(
            'kelpgate-admin-css',
            KELPGATE_PLUGIN_URL . 'assets/admin.css',
            array(),
            $css_ver
        );
    }

    public function add_action_links($links) {
        $settings_link = '<a href="' . admin_url('options-general.php?page=kelpgate') . '">' . __('Settings', 'kelpgate-malware-scanner') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    }

    public function add_menu_page() {
        add_options_page(
            __('Kelpgate Malware Scanner', 'kelpgate-malware-scanner'),
            __('Kelpgate Malware Scanner', 'kelpgate-malware-scanner'),
            'manage_options',
            'kelpgate',
            array($this, 'render_page')
        );
    }

    public function register_settings() {
        register_setting('kelpgate_settings_group', 'kelpgate_settings', array($this, 'sanitize_settings'));
    }

    public function sanitize_settings($input) {
        $clean = array();
        $clean['api_url']       = !empty($input['api_url']) ? esc_url_raw(rtrim($input['api_url'], '/')) : '';
        $clean['token_url']     = !empty($input['token_url']) ? esc_url_raw(rtrim($input['token_url'], '/')) : '';
        $clean['auth_mode']     = (!empty($input['auth_mode']) && $input['auth_mode'] === 'token') ? 'token' : 'oauth2';
        // Reject insecure endpoints on save (keep the previous value and tell the admin).
        $prev = get_option('kelpgate_settings', array());
        $prev = is_array($prev) ? $prev : array();
        foreach (array('api_url', 'token_url') as $key) {
            if ($clean[$key] !== '' && !Kelpgate_Client::is_secure_url($clean[$key])) {
                add_settings_error('kelpgate_settings', 'kelpgate_insecure_' . $key,
                    /* translators: %s: name of the setting that needs an https URL. */
                    sprintf(__('%s must use https (http is only allowed for localhost). The previous value was kept.', 'kelpgate-malware-scanner'), $key));
                $clean[$key] = isset($prev[$key]) ? $prev[$key] : '';
            }
        }
        $clean['client_id']     = !empty($input['client_id']) ? sanitize_text_field(trim($input['client_id'])) : '';
        $existing = get_option('kelpgate_settings', array());
        $existing = is_array($existing) ? $existing : array();
        // The form never contains the saved secret; blank means "keep what is stored".
        $clean['client_secret'] = !empty($input['client_secret'])
            ? sanitize_text_field(trim($input['client_secret']))
            : (isset($existing['client_secret']) ? $existing['client_secret'] : '');
        $clean['api_token']     = !empty($input['api_token'])
            ? sanitize_text_field(trim($input['api_token']))
            : (isset($existing['api_token']) ? $existing['api_token'] : '');
        $clean['fail_action']   = (!empty($input['fail_action']) && $input['fail_action'] === 'allow') ? 'allow' : 'block';
        $clean['max_mb']        = !empty($input['max_mb']) ? max(1, min(500, intval($input['max_mb']))) : 50;
        $clean['timeout_seconds'] = !empty($input['timeout_seconds']) ? max(5, min(300, intval($input['timeout_seconds']))) : 45;

        if (!empty($clean['client_id'])) {
            delete_transient('kelpgate_oauth_token_' . md5($clean['client_id']));
        }

        return $clean;
    }

    public function ajax_test_connection() {
        check_ajax_referer('kelpgate_admin_nonce', 'security');
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Unauthorized access.', 'kelpgate-malware-scanner')));
        }

        $this->client->refresh_settings();
        $res = $this->client->test_connection();
        if ($res['success']) {
            wp_send_json_success($res);
        } else {
            wp_send_json_error($res);
        }
    }

    public function render_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        $settings      = get_option('kelpgate_settings', array());
        $incidents     = get_option('kelpgate_incidents', array());
        if (!is_array($incidents)) {
            $incidents = array();
        }

        $is_configured = $this->client->is_configured();
        $auth_mode     = isset($settings['auth_mode']) ? $settings['auth_mode'] : 'oauth2';
        $api_url       = $this->client->get_api_url();
        $token_url     = $this->client->get_token_url();
        $client_id     = $this->client->get_client_id();
        // Saved secrets are never written into the page: the fields stay empty and an empty
        // submit keeps the stored value (see sanitize_settings).
        $has_secret    = $this->client->get_client_secret() !== '';
        $has_token     = !empty($settings['api_token']);
        $fail_action   = isset($settings['fail_action']) ? $settings['fail_action'] : 'block';
        $max_mb        = isset($settings['max_mb']) ? $settings['max_mb'] : 50;
        $timeout_seconds = isset($settings['timeout_seconds']) ? $settings['timeout_seconds'] : 45;
        ?>
        <div class="wrap kelpgate-wrap">
            <!-- Header Section -->
            <div class="kelpgate-header">
                <div class="kelpgate-header-brand">
                    <div class="kelpgate-logo-box">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        </svg>
                    </div>
                    <div>
                        <div style="display:flex; align-items:center; gap:10px;">
                            <h1><?php esc_html_e('Kelpgate Malware Scanner', 'kelpgate-malware-scanner'); ?></h1>
                            <?php if ($is_configured): ?>
                                <span class="kelpgate-pill good">
                                    <span class="kelpgate-dot good"></span>
                                    <span><?php esc_html_e('Connected', 'kelpgate-malware-scanner'); ?></span>
                                </span>
                            <?php else: ?>
                                <span class="kelpgate-pill warn">
                                    <span class="kelpgate-dot warn"></span>
                                    <span><?php esc_html_e('Setup Required', 'kelpgate-malware-scanner'); ?></span>
                                </span>
                            <?php endif; ?>
                        </div>
                        <p><?php esc_html_e('Real-time multi-engine malware scanning for every upload.', 'kelpgate-malware-scanner'); ?></p>
                    </div>
                </div>
                <div>
                    <a href="https://console.kelpgate.cloud" target="_blank" rel="noopener noreferrer" class="kelpgate-btn kelpgate-btn-secondary">
                        <svg class="kelpgate-ic" viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                        <span><?php esc_html_e('Kelpgate Console', 'kelpgate-malware-scanner'); ?></span>
                    </a>
                </div>
            </div>

            <!-- Dynamic Status Banner (Test connection result / Missing setup) -->
            <div id="kelpgate-banner" class="kelpgate-banner <?php echo $is_configured ? 'healthy' : 'unconfigured'; ?>" <?php echo $is_configured ? 'style="display:none;"' : ''; ?>>
                <svg class="kelpgate-ic" viewBox="0 0 24 24">
                    <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                <div id="kelpgate-banner-text">
                    <?php if (!$is_configured): ?>
                        <strong><?php esc_html_e('Setup Required:', 'kelpgate-malware-scanner'); ?></strong>
                        <?php esc_html_e('Enter your Scanner API Endpoint and authentication credentials below to activate upload protection.', 'kelpgate-malware-scanner'); ?>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Main Configuration Form -->
            <form method="post" action="options.php">
                <?php settings_fields('kelpgate_settings_group'); ?>

                <!-- Card 1: API & Authentication -->
                <div class="kelpgate-card">
                    <div class="kelpgate-card-header">
                        <h2>
                            <svg class="kelpgate-ic" viewBox="0 0 24 24"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
                            <span><?php esc_html_e('API & Authentication', 'kelpgate-malware-scanner'); ?></span>
                        </h2>
                        <button type="button" id="kelpgate-test-btn" class="kelpgate-btn kelpgate-btn-secondary">
                            <svg class="kelpgate-ic" id="kelpgate-test-icon" viewBox="0 0 24 24">
                                <polyline points="23 4 23 10 17 10"/>
                                <polyline points="1 20 1 14 7 14"/>
                                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
                            </svg>
                            <span><?php esc_html_e('Test Connection', 'kelpgate-malware-scanner'); ?></span>
                        </button>
                    </div>
                    <div class="kelpgate-card-body">
                        <div class="kelpgate-field-group">
                            <label for="kelpgate_api_url"><?php esc_html_e('Scanner API Endpoint', 'kelpgate-malware-scanner'); ?> *</label>
                            <input name="kelpgate_settings[api_url]" type="url" id="kelpgate_api_url" value="<?php echo esc_attr($api_url); ?>" placeholder="https://api.yourdomain.com" class="kelpgate-input mono" required>
                            <span class="kelpgate-hint"><?php esc_html_e('Base URL where the Kelpgate threat inspection service is reachable.', 'kelpgate-malware-scanner'); ?></span>
                        </div>

                        <div class="kelpgate-field-group">
                            <label for="kelpgate_auth_mode"><?php esc_html_e('Authentication Method', 'kelpgate-malware-scanner'); ?></label>
                            <select name="kelpgate_settings[auth_mode]" id="kelpgate_auth_mode" class="kelpgate-select">
                                <option value="oauth2" <?php selected($auth_mode, 'oauth2'); ?>><?php esc_html_e('OAuth 2.0 Client Credentials (Recommended)', 'kelpgate-malware-scanner'); ?></option>
                                <option value="token" <?php selected($auth_mode, 'token'); ?>><?php esc_html_e('Static Bearer Token', 'kelpgate-malware-scanner'); ?></option>
                            </select>
                            <span class="kelpgate-hint"><?php esc_html_e('OAuth 2.0 securely exchanges client credentials for short-lived access tokens with automatic renewal.', 'kelpgate-malware-scanner'); ?></span>
                        </div>

                        <div class="kelpgate-row-oauth2">
                            <div class="kelpgate-field-group">
                                <label for="kelpgate_token_url"><?php esc_html_e('OAuth 2.0 Token URL', 'kelpgate-malware-scanner'); ?> *</label>
                                <input name="kelpgate_settings[token_url]" type="url" id="kelpgate_token_url" value="<?php echo esc_attr($token_url); ?>" placeholder="https://auth.yourdomain.com/oauth2/token" class="kelpgate-input mono">
                                <span class="kelpgate-hint"><?php esc_html_e('OAuth 2.0 token endpoint for client credentials authentication.', 'kelpgate-malware-scanner'); ?></span>
                            </div>

                            <div class="kelpgate-grid-2">
                                <div class="kelpgate-field-group">
                                    <label for="kelpgate_client_id"><?php esc_html_e('Client ID', 'kelpgate-malware-scanner'); ?> *</label>
                                    <input name="kelpgate_settings[client_id]" type="text" id="kelpgate_client_id" value="<?php echo esc_attr($client_id); ?>" placeholder="e.g. 13ae94ca-d502-4f08-b7cd-a50a40faa504" class="kelpgate-input mono" autocomplete="off">
                                </div>
                                <div class="kelpgate-field-group">
                                    <label for="kelpgate_client_secret"><?php esc_html_e('Client Secret', 'kelpgate-malware-scanner'); ?> *</label>
                                    <input name="kelpgate_settings[client_secret]" type="password" id="kelpgate_client_secret" value="" placeholder="<?php echo $has_secret ? esc_attr__('Saved — leave blank to keep', 'kelpgate-malware-scanner') : ''; ?>" class="kelpgate-input mono" autocomplete="new-password">
                                </div>
                            </div>
                        </div>

                        <div class="kelpgate-row-token" style="display:none;">
                            <div class="kelpgate-field-group">
                                <label for="kelpgate_api_token"><?php esc_html_e('Static Bearer Token', 'kelpgate-malware-scanner'); ?> *</label>
                                <input name="kelpgate_settings[api_token]" type="password" id="kelpgate_api_token" value="" placeholder="<?php echo $has_token ? esc_attr__('Saved — leave blank to keep', 'kelpgate-malware-scanner') : ''; ?>" class="kelpgate-input mono">
                                <span class="kelpgate-hint"><?php esc_html_e('Pre-generated bearer token authorized for scan operations.', 'kelpgate-malware-scanner'); ?></span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Card 2: Scanning Policy & Enforcement -->
                <div class="kelpgate-card">
                    <div class="kelpgate-card-header">
                        <h2>
                            <svg class="kelpgate-ic" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                            <span><?php esc_html_e('Scanning Policy & Enforcement', 'kelpgate-malware-scanner'); ?></span>
                        </h2>
                    </div>
                    <div class="kelpgate-card-body">
                        <div class="kelpgate-grid-2">
                            <div class="kelpgate-field-group">
                                <label for="kelpgate_fail_action"><?php esc_html_e('Scanner Failure Action', 'kelpgate-malware-scanner'); ?></label>
                                <select name="kelpgate_settings[fail_action]" id="kelpgate_fail_action" class="kelpgate-select">
                                    <option value="block" <?php selected($fail_action, 'block'); ?>><?php esc_html_e('Fail-Closed (Block upload if scanner is unreachable)', 'kelpgate-malware-scanner'); ?></option>
                                    <option value="allow" <?php selected($fail_action, 'allow'); ?>><?php esc_html_e('Fail-Open (Allow upload if scanner is unreachable)', 'kelpgate-malware-scanner'); ?></option>
                                </select>
                                <span class="kelpgate-hint"><?php esc_html_e('Determines upload behavior if the scanning service is temporarily unavailable.', 'kelpgate-malware-scanner'); ?></span>
                            </div>

                            <div class="kelpgate-field-group">
                                <label for="kelpgate_max_mb"><?php esc_html_e('Maximum Scan File Size (MB)', 'kelpgate-malware-scanner'); ?></label>
                                <input name="kelpgate_settings[max_mb]" type="number" id="kelpgate_max_mb" value="<?php echo esc_attr($max_mb); ?>" min="1" max="500" class="kelpgate-input">
                                <span class="kelpgate-hint"><?php esc_html_e('Files larger than this are not sent to the scanner. They are rejected under Fail-Closed and accepted unscanned only under Fail-Open.', 'kelpgate-malware-scanner'); ?></span>
                            </div>

                            <div class="kelpgate-field-group">
                                <label for="kelpgate_timeout_seconds"><?php esc_html_e('Scan Timeout (seconds)', 'kelpgate-malware-scanner'); ?></label>
                                <input name="kelpgate_settings[timeout_seconds]" type="number" id="kelpgate_timeout_seconds" value="<?php echo esc_attr($timeout_seconds); ?>" min="5" max="300" class="kelpgate-input">
                                <span class="kelpgate-hint"><?php esc_html_e('How long to wait for the scanner before treating the file as unscannable (see Scanner Failure Action).', 'kelpgate-malware-scanner'); ?></span>
                            </div>
                        </div>
                    </div>

                    <div class="kelpgate-card-footer" style="justify-content:flex-end;">
                        <button type="submit" class="kelpgate-btn kelpgate-btn-primary">
                            <svg class="kelpgate-ic" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>
                            <span><?php esc_html_e('Save Changes', 'kelpgate-malware-scanner'); ?></span>
                        </button>
                    </div>
                </div>
            </form>

            <!-- Card 3: Blocked Threats Log -->
            <div class="kelpgate-card">
                <div class="kelpgate-card-header">
                    <h2>
                        <svg class="kelpgate-ic" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                        <span><?php esc_html_e('Blocked Threats Log', 'kelpgate-malware-scanner'); ?></span>
                    </h2>
                    <?php if (!empty($incidents)): ?>
                        <span class="kelpgate-pill crit">
                            <?php
                            /* translators: %d: number of blocked threats. */
                            echo esc_html(sprintf(_n('%d threat blocked', '%d threats blocked', count($incidents), 'kelpgate-malware-scanner'), count($incidents)));
                            ?>
                        </span>
                    <?php endif; ?>
                </div>
                <?php if (empty($incidents)): ?>
                    <div class="kelpgate-card-body" style="text-align:center; padding: 40px 20px; color: var(--kg-text-3);">
                        <svg class="kelpgate-ic" viewBox="0 0 24 24" style="width:24px; height:24px; stroke: var(--kg-good); margin-bottom: 8px;"><polyline points="20 6 9 17 4 12"/></svg>
                        <p style="margin:0; font-weight:500; color: var(--kg-text);"><?php esc_html_e('No Threats Detected', 'kelpgate-malware-scanner'); ?></p>
                        <p style="margin-top:4px; font-size:12.5px;"><?php esc_html_e('All uploaded files have passed security inspection.', 'kelpgate-malware-scanner'); ?></p>
                    </div>
                <?php else: ?>
                    <table class="kelpgate-table">
                        <thead>
                            <tr>
                                <th style="width:160px;"><?php esc_html_e('Timestamp (UTC)', 'kelpgate-malware-scanner'); ?></th>
                                <th><?php esc_html_e('File Name', 'kelpgate-malware-scanner'); ?></th>
                                <th><?php esc_html_e('Threat Detection', 'kelpgate-malware-scanner'); ?></th>
                                <th><?php esc_html_e('SHA-256 Digest', 'kelpgate-malware-scanner'); ?></th>
                                <th style="width:120px;"><?php esc_html_e('Client IP', 'kelpgate-malware-scanner'); ?></th>
                            </tr>
                        </thead>
                        <tbody id="kelpgate-incidents-body">
                            <?php foreach ($incidents as $idx => $inc): ?>
                                <?php
                                $display_sig = Kelpgate_Scanner::format_threat_signature($inc['signature']);
                                ?>
                                <tr style="<?php echo $idx >= 10 ? 'display:none;' : ''; ?>">
                                    <td><?php echo esc_html($inc['time']); ?></td>
                                    <td><strong><?php echo esc_html($inc['file']); ?></strong></td>
                                    <td><span style="color:var(--kg-crit); font-weight:600;"><?php echo esc_html($display_sig); ?></span></td>
                                    <td><code><?php echo esc_html(substr($inc['sha256'], 0, 16)); ?>...</code></td>
                                    <td><?php echo esc_html($inc['ip']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php if (count($incidents) > 10): ?>
                        <div class="kelpgate-pagination-bar" style="display:flex;align-items:center;justify-content:space-between;padding:10px 16px;background:var(--kg-surface-2);border-top:1px solid var(--kg-border);font-size:12.5px;gap:12px;">
                            <div class="kelpgate-pagination-info" style="font-weight:500;color:var(--kg-text-2);font-size:12px;white-space:nowrap;">
                                <span id="kelpgate-page-info">
                                    <?php
                                    /* translators: 1: number of threats shown on this page, 2: total number of threats. */
                                    printf(esc_html__('Showing 1–%1$d of %2$d threats', 'kelpgate-malware-scanner'), absint(min(10, count($incidents))), absint(count($incidents)));
                                    ?>
                                </span>
                            </div>
                            <div class="kelpgate-pagination-controls" style="display:inline-flex;align-items:center;gap:6px;">
                                <button type="button" class="kelpgate-page-btn" id="kelpgate-prev-btn" disabled style="display:inline-flex;align-items:center;gap:5px;height:30px;padding:5px 12px;margin:0;">
                                    <svg class="kelpgate-ic" viewBox="0 0 24 24"><polyline points="15 18 9 12 15 6"/></svg>
                                    <span><?php esc_html_e('Previous', 'kelpgate-malware-scanner'); ?></span>
                                </button>
                                <span id="kelpgate-page-numbers" class="kelpgate-page-numbers" style="display:inline-flex;align-items:center;gap:4px;"></span>
                                <button type="button" class="kelpgate-page-btn" id="kelpgate-next-btn" style="display:inline-flex;align-items:center;gap:5px;height:30px;padding:5px 12px;margin:0;">
                                    <span><?php esc_html_e('Next', 'kelpgate-malware-scanner'); ?></span>
                                    <svg class="kelpgate-ic" viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg>
                                </button>
                            </div>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>

        <script>
        document.addEventListener('DOMContentLoaded', function() {
            var authMode = document.getElementById('kelpgate_auth_mode');
            function toggleAuthRows() {
                var isOAuth = authMode.value === 'oauth2';
                document.querySelectorAll('.kelpgate-row-oauth2').forEach(function(el) { el.style.display = isOAuth ? '' : 'none'; });
                document.querySelectorAll('.kelpgate-row-token').forEach(function(el) { el.style.display = isOAuth ? 'none' : ''; });
            }
            if (authMode) {
                authMode.addEventListener('change', toggleAuthRows);
                toggleAuthRows();
            }

            var btn = document.getElementById('kelpgate-test-btn');
            var icon = document.getElementById('kelpgate-test-icon');
            var banner = document.getElementById('kelpgate-banner');
            var bannerText = document.getElementById('kelpgate-banner-text');

            // Build the banner with text nodes only: the message can contain text returned by the
            // token/scan endpoints, which must never be interpreted as HTML.
            function setBanner(label, text) {
                bannerText.textContent = '';
                var strong = document.createElement('strong');
                strong.textContent = label;
                bannerText.appendChild(strong);
                bannerText.appendChild(document.createTextNode(String(text)));
            }

            if (btn) {
                btn.addEventListener('click', function() {
                    btn.disabled = true;
                    icon.classList.add('kelpgate-spinning');

                    var data = new FormData();
                    data.append('action', 'kelpgate_test_connection');
                    data.append('security', '<?php echo esc_js(wp_create_nonce('kelpgate_admin_nonce')); ?>');

                    fetch(ajaxurl, {
                        method: 'POST',
                        body: data
                    })
                    .then(function(r) { return r.json(); })
                    .then(function(json) {
                        btn.disabled = false;
                        icon.classList.remove('kelpgate-spinning');
                        banner.style.display = 'flex';

                        if (json.success && json.data && json.data.success) {
                            banner.className = 'kelpgate-banner healthy';
                            setBanner('<?php echo esc_js(__('Connected: ', 'kelpgate-malware-scanner')); ?>', json.data.message);
                        } else {
                            var msg = (json.data && json.data.message) ? json.data.message : '<?php echo esc_js(__('Connection test failed.', 'kelpgate-malware-scanner')); ?>';
                            banner.className = 'kelpgate-banner error';
                            setBanner('<?php echo esc_js(__('Error: ', 'kelpgate-malware-scanner')); ?>', msg);
                        }
                    })
                    .catch(function(err) {
                        btn.disabled = false;
                        icon.classList.remove('kelpgate-spinning');
                        banner.style.display = 'flex';
                        banner.className = 'kelpgate-banner error';
                        setBanner('<?php echo esc_js(__('Network Error: ', 'kelpgate-malware-scanner')); ?>', err.message);
                    });
                });
            }

            // Incident Log Dynamic Pagination
            var incidentsBody = document.getElementById('kelpgate-incidents-body');
            if (incidentsBody) {
                var PAGE_SIZE = 10;
                var rows = Array.prototype.slice.call(incidentsBody.querySelectorAll('tr'));
                var totalRows = rows.length;
                var totalPages = Math.ceil(totalRows / PAGE_SIZE);
                var currentPage = 1;

                function updateIncidentPagination(page) {
                    currentPage = page;
                    var start = (page - 1) * PAGE_SIZE;
                    var end = start + PAGE_SIZE;

                    rows.forEach(function(row, idx) {
                        row.style.display = (idx >= start && idx < end) ? '' : 'none';
                    });

                    var infoEl = document.getElementById('kelpgate-page-info');
                    if (infoEl) {
                        var displayEnd = Math.min(end, totalRows);
                        infoEl.textContent = 'Showing ' + (start + 1) + '–' + displayEnd + ' of ' + totalRows + ' threats';
                    }

                    var prevBtn = document.getElementById('kelpgate-prev-btn');
                    if (prevBtn) prevBtn.disabled = (currentPage <= 1);

                    var nextBtn = document.getElementById('kelpgate-next-btn');
                    if (nextBtn) nextBtn.disabled = (currentPage >= totalPages);

                    var pageNums = document.getElementById('kelpgate-page-numbers');
                    if (pageNums) {
                        pageNums.innerHTML = '';
                        for (var i = 1; i <= totalPages; i++) {
                            var pBtn = document.createElement('button');
                            pBtn.type = 'button';
                            var isActive = (i === currentPage);
                            pBtn.className = 'kelpgate-page-num' + (isActive ? ' active' : '');
                            pBtn.style.cssText = 'min-width:30px;height:30px;padding:0 6px;font-size:12px;font-weight:500;display:inline-flex;align-items:center;justify-content:center;border-radius:6px;cursor:pointer;margin:0;box-sizing:border-box;' +
                                (isActive ? 'background:var(--kg-accent,#0284C7);color:#ffffff;border:1px solid var(--kg-accent,#0284C7);' : 'background:var(--kg-surface,#ffffff);color:var(--kg-text-2,#475569);border:1px solid var(--kg-border,#E2E8F0);');
                            pBtn.textContent = i;
                            pBtn.setAttribute('data-page', i);
                            pBtn.addEventListener('click', function(e) {
                                updateIncidentPagination(parseInt(e.currentTarget.getAttribute('data-page'), 10));
                            });
                            pageNums.appendChild(pBtn);
                        }
                    }
                }

                if (totalRows > PAGE_SIZE) {
                    updateIncidentPagination(1);
                    var prevBtn = document.getElementById('kelpgate-prev-btn');
                    if (prevBtn) {
                        prevBtn.addEventListener('click', function() {
                            if (currentPage > 1) updateIncidentPagination(currentPage - 1);
                        });
                    }
                    var nextBtn = document.getElementById('kelpgate-next-btn');
                    if (nextBtn) {
                        nextBtn.addEventListener('click', function() {
                            if (currentPage < totalPages) updateIncidentPagination(currentPage + 1);
                        });
                    }
                }
            }
        });
        </script>
        <?php
    }
}
