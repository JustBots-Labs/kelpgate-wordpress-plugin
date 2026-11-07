<?php
/**
 * Runs when the plugin is deleted from Plugins in WordPress admin (not on deactivation).
 * Removes everything the plugin stored, including the OAuth client secret / API token and the
 * blocked-threats log, so credentials do not stay behind in the database.
 */
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

function kelpgate_wordpress_plugin_uninstall_site() {
    delete_option('kelpgate_settings');
    delete_option('kelpgate_incidents');

    global $wpdb;
    // Cached OAuth tokens, their refresh locks and the per-IP rate-limit counters are transients.
    $like = $wpdb->esc_like('_transient_kelpgate_') . '%';
    $like_timeout = $wpdb->esc_like('_transient_timeout_kelpgate_') . '%';
    $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $like, $like_timeout));
}

if (is_multisite()) {
    foreach (get_sites(array('fields' => 'ids', 'number' => 0)) as $blog_id) {
        switch_to_blog($blog_id);
        kelpgate_wordpress_plugin_uninstall_site();
        restore_current_blog();
    }
} else {
    kelpgate_wordpress_plugin_uninstall_site();
}
