<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * A link on the Plugins screen to get API credentials. The plugin's details panel comes from
 * wordpress.org, which builds it from readme.txt.
 */
class Kelpgate_Plugin_Meta {
    public function init() {
        add_filter('plugin_row_meta', array($this, 'row_meta'), 10, 2);
    }

    /** Link after "Version | By ..." on the Plugins screen. */
    public function row_meta($links, $file) {
        if ($file !== KELPGATE_PLUGIN_BASENAME) {
            return $links;
        }

        $links[] = sprintf(
            '<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>',
            esc_url(KELPGATE_CONSOLE_URL),
            esc_html__('Get your API credentials', 'kelpgate-malware-scanner')
        );

        return $links;
    }
}
