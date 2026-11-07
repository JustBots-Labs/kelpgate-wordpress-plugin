# Kelpgate Malware Scanner for WordPress

Scans files uploaded to WordPress with the [Kelpgate](https://console.strapiorbit.cloud) scanning API and blocks infected ones before they are saved.

Requires WordPress 5.8+, PHP 7.4+, and a Kelpgate account (client ID and secret from the Kelpgate Console).

## Compatibility

Each combination was installed on a real WordPress and checked: a clean upload is accepted, an EICAR upload is rejected, and both failure policies behave as set. The scanner API was simulated for these runs.

| WordPress | PHP |
| --- | --- |
| 5.8 | 7.4, 8.0 |
| 6.1 | 7.4 |
| 6.4 | 8.0, 8.1, 8.2 |
| 6.9 | 8.1, 8.2, 8.3, 8.4 |

All source files also lint cleanly on PHP 7.4 through 8.4. Combinations not listed have not been tested.

## Install

1. Download `kelpgate-wordpress-plugin.zip` from the [latest release](https://github.com/amithalder21/kelpgate-wordpress-plugin/releases/latest).
2. In WordPress admin go to **Plugins > Add New > Upload Plugin**, choose the zip, install and activate.
3. Open **Settings > Kelpgate Antivirus**, enter the API URL, token URL, client ID and client secret, and use **Test connection**.

## What it checks

- Uploads through the Media Library and any code that uses `wp_handle_upload`.
- Raw `$_FILES` uploads sent to other endpoints (form plugins, custom handlers). Infected temp files are deleted and the request is stopped.
- A file is rejected only when the API reports it as infected (HTTP 406). Blocked files are listed in the settings page (last 50 incidents).

If the scanner cannot be reached, the **failure policy** decides: `block` rejects the upload, `allow` lets it through. Files larger than the configured maximum (default 50 MB) are handled the same way. Each file is read into memory for the upload, so size the PHP memory limit accordingly.

Access tokens are cached and renewed shortly before they expire. Requests to the API and token endpoints must use HTTPS. The per-IP raw-upload scan rate is limited to 20 files per minute.

## Configuration in `wp-config.php`

Constants override the values saved in the settings page, which keeps credentials out of the database.

```php
define('KELPGATE_API_URL',       'https://api.example.com');
define('KELPGATE_TOKEN_URL',     'https://auth.example.com/oauth2/token');
define('KELPGATE_CLIENT_ID',     '...');
define('KELPGATE_CLIENT_SECRET', '...');

// Behind a load balancer or CDN: comma-separated IPs/CIDRs whose X-Forwarded-For is trusted.
define('KELPGATE_TRUSTED_PROXIES', '10.0.0.0/8');
```

The client IP stored with each incident is taken from `X-Forwarded-For` only when the request arrives from a trusted proxy (loopback and private ranges by default).

## Try it

Save the standard EICAR test string as `eicar.txt` and upload it through the Media Library:

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

The upload is refused and an entry appears in the incident list.

## Uninstall

Deleting the plugin removes its settings, incident log and cached tokens.

## Build a release zip

```bash
./package.sh
```

Produces `kelpgate-wordpress-plugin.zip` with a single top-level `kelpgate-wordpress-plugin/` folder. Pushing a `vX.Y.Z` tag that matches the plugin version publishes it as a GitHub release.

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).
