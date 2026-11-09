<?php
/**
 * Plugin Name:       Kelpgate Malware Scanner
 * Plugin URI:        https://github.com/amithalder21/kelpgate-wordpress-plugin
 * Description:       Scan every upload for malware before it reaches your site. Infected files are blocked in real time by the Kelpgate multi-engine scanner. Connect your Kelpgate account to activate.
 * Version:           1.0.11
 * Requires at least: 5.8
 * Tested up to:      6.9
 * Requires PHP:      7.4
 * Author:            Kelpgate Security Team
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       kelpgate-wordpress-plugin
 * Update URI:        false
 */

if (!defined('ABSPATH')) {
    exit;
}

// Do not load twice: a second copy would redeclare the classes and constants below.
// The check is on a constant because PHP registers top-level classes at compile time, so
// class_exists() is already true for the first copy as well.
if (defined('KELPGATE_VERSION')) {
    add_action('admin_notices', function () {
        echo '<div class="notice notice-warning"><p><strong>Kelpgate Malware Scanner</strong> is installed more than once. '
            . 'This copy was not loaded; deactivate and delete the duplicate under Plugins.</p></div>';
    });
    return;
}

define('KELPGATE_VERSION', '1.0.11');
define('KELPGATE_PLUGIN_URI', 'https://github.com/amithalder21/kelpgate-wordpress-plugin');
define('KELPGATE_CONSOLE_URL', 'https://console.kelpgate.cloud');
define('KELPGATE_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('KELPGATE_PLUGIN_URL', plugin_dir_url(__FILE__));
define('KELPGATE_PLUGIN_BASENAME', plugin_basename(__FILE__));

require_once KELPGATE_PLUGIN_DIR . 'includes/class-kelpgate-client.php';
require_once KELPGATE_PLUGIN_DIR . 'includes/class-kelpgate-client-ip.php';
require_once KELPGATE_PLUGIN_DIR . 'includes/class-kelpgate-scanner.php';
require_once KELPGATE_PLUGIN_DIR . 'includes/class-kelpgate-admin.php';
require_once KELPGATE_PLUGIN_DIR . 'includes/class-kelpgate-plugin-meta.php';

/**
 * Main plugin singleton.
 */
class Kelpgate_Plugin {
    private static $instance = null;
    private $client;
    private $scanner;
    private $admin;
    private $meta;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->client  = new Kelpgate_Client();
        $this->scanner = new Kelpgate_Scanner($this->client);
        $this->admin   = new Kelpgate_Admin($this->client);
        $this->meta    = new Kelpgate_Plugin_Meta();

        add_action('plugins_loaded', array($this, 'init'));
        register_activation_hook(__FILE__, array($this, 'activate'));
    }

    public function init() {
        $this->scanner->init();
        if (is_admin()) {
            $this->admin->init();
            $this->meta->init();
        }
    }

    public function activate() {
        $defaults = array(
            'api_url'       => '',
            'token_url'     => '',
            'auth_mode'     => 'oauth2',
            'client_id'     => '',
            'client_secret' => '',
            'api_token'     => '',
            'fail_action'   => 'block', // 'block' or 'allow'
            'max_mb'        => 50,
        );
        if (!get_option('kelpgate_settings')) {
            update_option('kelpgate_settings', $defaults);
        }
    }
}

Kelpgate_Plugin::instance();
