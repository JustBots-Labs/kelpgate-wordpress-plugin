<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Determines the real client IP behind reverse proxies, load balancers and CDNs.
 *
 * X-Forwarded-For is controlled by the visitor, so it is only read when the direct connection
 * (REMOTE_ADDR) comes from a trusted proxy, and it is read from the right: the first entry that is
 * not itself a trusted proxy is the address our own proxy saw. Trusted by default: loopback and
 * private ranges (Docker, Kubernetes ingress, an nginx on the same host). If a public CDN or load
 * balancer sits in front, add its networks with the KELPGATE_TRUSTED_PROXIES constant
 * (comma-separated IPs/CIDRs) or the `kelpgate_trusted_proxies` filter.
 */
class Kelpgate_Client_IP {
    private static $defaults = array(
        '127.0.0.0/8', '::1/128', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
        '169.254.0.0/16', 'fc00::/7', 'fe80::/10',
    );

    public static function get() {
        $peer = isset($_SERVER['REMOTE_ADDR']) ? trim(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        if (filter_var($peer, FILTER_VALIDATE_IP) === false) {
            return 'unknown';
        }
        $trusted = self::trusted_networks();
        if (!self::in_networks($peer, $trusted)) {
            return $peer; // direct visitor: ignore any forwarded headers they sent
        }

        $xff = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR']) : '';
        $parts = array_reverse(array_map('trim', explode(',', $xff)));
        foreach ($parts as $candidate) {
            if (filter_var($candidate, FILTER_VALIDATE_IP) !== false && !self::in_networks($candidate, $trusted)) {
                return $candidate;
            }
        }

        $real = isset($_SERVER['HTTP_X_REAL_IP']) ? trim(wp_unslash($_SERVER['HTTP_X_REAL_IP'])) : '';
        if (filter_var($real, FILTER_VALIDATE_IP) !== false && !self::in_networks($real, $trusted)) {
            return $real;
        }

        return $peer;
    }

    private static function trusted_networks() {
        $nets = self::$defaults;
        if (defined('KELPGATE_TRUSTED_PROXIES') && KELPGATE_TRUSTED_PROXIES) {
            $nets = array_merge($nets, array_map('trim', explode(',', KELPGATE_TRUSTED_PROXIES)));
        }
        $filtered = apply_filters('kelpgate_trusted_proxies', $nets);
        return is_array($filtered) ? $filtered : $nets;
    }

    private static function in_networks($ip, $networks) {
        foreach ($networks as $net) {
            if (is_string($net) && $net !== '' && self::in_cidr($ip, $net)) {
                return true;
            }
        }
        return false;
    }

    private static function in_cidr($ip, $cidr) {
        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }
        list($subnet, $bits) = explode('/', $cidr, 2);
        $ip_bin  = @inet_pton($ip);
        $net_bin = @inet_pton($subnet);
        if ($ip_bin === false || $net_bin === false || strlen($ip_bin) !== strlen($net_bin)) {
            return false;
        }
        $bits  = (int) $bits;
        $bytes = intdiv($bits, 8);
        if ($bytes > 0 && substr($ip_bin, 0, $bytes) !== substr($net_bin, 0, $bytes)) {
            return false;
        }
        $rem = $bits % 8;
        if ($rem === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rem)) & 0xFF;
        return (ord($ip_bin[$bytes]) & $mask) === (ord($net_bin[$bytes]) & $mask);
    }
}
