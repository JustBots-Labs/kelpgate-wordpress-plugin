<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * What the Plugins screen shows for this plugin beyond the header: a "View details" panel and a link to
 * get API credentials, like a vendor plugin. This plugin is not on wordpress.org, so WordPress cannot
 * look its details up; they are provided here.
 */
class Kelpgate_Plugin_Meta {
    const SLUG = 'kelpgate-wordpress-plugin';

    public function init() {
        add_filter('plugin_row_meta', array($this, 'row_meta'), 10, 2);
        add_filter('plugins_api', array($this, 'plugin_information'), 10, 3);
    }

    /** Links after "Version | By ..." on the Plugins screen. */
    public function row_meta($links, $file) {
        if ($file !== KELPGATE_PLUGIN_BASENAME) {
            return $links;
        }

        $details = add_query_arg(
            array('tab' => 'plugin-information', 'plugin' => self::SLUG, 'TB_iframe' => 'true', 'width' => '600', 'height' => '550'),
            self_admin_url('plugin-install.php')
        );
        $links[] = sprintf(
            '<a href="%s" class="thickbox open-plugin-details-modal" aria-label="%s" data-title="%s">%s</a>',
            esc_url($details),
            esc_attr__('More information about Kelpgate Malware Scanner', 'kelpgate-wordpress-plugin'),
            esc_attr__('Kelpgate Malware Scanner', 'kelpgate-wordpress-plugin'),
            esc_html__('View details', 'kelpgate-wordpress-plugin')
        );
        $links[] = sprintf(
            '<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>',
            esc_url(KELPGATE_CONSOLE_URL),
            esc_html__('Get your API credentials', 'kelpgate-wordpress-plugin')
        );

        return $links;
    }

    /** Answers the "View details" panel for this plugin only; every other request is left alone. */
    public function plugin_information($result, $action, $args) {
        if ($action !== 'plugin_information' || !is_object($args) || empty($args->slug) || $args->slug !== self::SLUG) {
            return $result;
        }

        $info                = new stdClass();
        $info->name          = 'Kelpgate Malware Scanner';
        $info->slug          = self::SLUG;
        $info->version       = KELPGATE_VERSION;
        $info->author        = 'Kelpgate Security Team';
        $info->homepage      = KELPGATE_PLUGIN_URI;
        $info->requires      = '5.8';
        $info->requires_php  = '7.4';
        $info->tested        = '6.9';
        $info->short_description = 'Scan every upload for malware before it reaches your site.';
        $info->sections      = array(
            'description'  => '<p>Kelpgate Malware Scanner checks every file uploaded to your WordPress site with the Kelpgate multi-engine scanner and blocks infected files before they are saved.</p>'
                . '<ul>'
                . '<li>Scans uploads from the Media Library, themes, plugins, forms and REST API clients.</li>'
                . '<li>Multiple detection engines run together on every file.</li>'
                . '<li>You choose what happens if the scanner cannot be reached: block uploads (safest) or allow them.</li>'
                . '<li>A log shows the files that were blocked, with time, threat name and the visitor\'s IP address.</li>'
                . '</ul>'
                . '<h4>Privacy</h4>'
                . '<p>To scan a file, the plugin sends its contents to the Kelpgate API you configure. Nothing is sent until you connect an account. Files that are clean are kept briefly and infected files are quarantined, according to your Kelpgate plan.</p>',
            'installation' => '<ol>'
                . '<li>Upload the zip under <strong>Plugins &rarr; Add New &rarr; Upload Plugin</strong> and activate it.</li>'
                . '<li>Get your API credentials in the Kelpgate console (link on this page).</li>'
                . '<li>Open <strong>Settings &rarr; Kelpgate Antivirus</strong>, enter the API address and credentials, and press <strong>Test Connection</strong>.</li>'
                . '</ol>',
            'changelog'    => '<h4>' . esc_html(KELPGATE_VERSION) . '</h4><ul>'
                . '<li>Plugin listing: working links, description and this details panel.</li>'
                . '<li>Installable release zip, clean removal of stored credentials on delete.</li>'
                . '<li>Records the visitor\'s real IP address behind proxies; refreshes API tokens before they expire; requires https.</li>'
                . '</ul>',
        );

        return $info;
    }
}
