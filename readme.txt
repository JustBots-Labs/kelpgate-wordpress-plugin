=== Kelpgate Malware Scanner ===
Contributors: kelpgate
Tags: malware, security, scanner, uploads, antivirus
Requires at least: 5.8
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.12
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Scan every upload for malware before it reaches your site. Infected files are blocked before they are saved.

== Description ==

Kelpgate Malware Scanner checks every file uploaded to WordPress against the Kelpgate scanning service and blocks infected files before they are saved. It covers the Media Library, form plugins and custom upload handlers, and keeps a record of what was blocked.

**Why use it**

* **Blocks at the door.** Files are scanned during the upload. An infected file is rejected and never lands in `wp-content/uploads`.
* **Broad coverage.** Hooks WordPress's own upload pipeline and also inspects raw file uploads sent to other endpoints, such as form plugins and custom handlers.
* **You choose the failure behavior.** If the scanner cannot be reached or a file is too large, either reject the upload (safest) or accept it.
* **Credentials stay out of the database.** Define the API address and credentials as constants in `wp-config.php`. Saved secrets are never shown again on the settings page.
* **Accurate client addresses.** Incident records store the visitor's IP address, trusting `X-Forwarded-For` only from proxies you list.
* **Clean removal.** Deleting the plugin removes its settings, incident log and cached tokens.

**This plugin needs a Kelpgate account.** The plugin is open source (GPL-2.0-or-later). It is a client for the Kelpgate scanning service, a hosted commercial product that is not part of this plugin. Nothing is sent until you connect an account.

== Installation ==

1. Upload the plugin zip under **Plugins > Add New > Upload Plugin**, then activate it.
2. Get your API credentials in the Kelpgate Console at https://console.kelpgate.cloud.
3. Open **Settings > Kelpgate Malware Scanner**, enter the API URL, token URL, client ID and client secret, and select **Test connection**.

To keep credentials out of the database, define them in `wp-config.php`:

`define('KELPGATE_API_URL', 'https://api.example.com');`
`define('KELPGATE_TOKEN_URL', 'https://auth.example.com/oauth2/token');`
`define('KELPGATE_CLIENT_ID', 'your-client-id');`
`define('KELPGATE_CLIENT_SECRET', 'your-client-secret');`

== Frequently Asked Questions ==

= Does it cost anything? =

The plugin is free and open source. Scanning is provided by the Kelpgate service under your Kelpgate plan.

= What happens when the scanner is down? =

You choose. With the default "block" policy, uploads are rejected while the scanner cannot give a verdict. With "allow", they are accepted.

= Is the file stored anywhere? =

Files that scan clean are kept briefly and infected files are quarantined, according to your Kelpgate plan. The plugin itself keeps only an incident record for the last 50 blocked uploads (time, file name, detection name, SHA-256, client IP and user ID). It is removed when you delete the plugin.

= How can I test it? =

Upload a file containing the standard EICAR test string through the Media Library. The upload is rejected and an incident appears on the settings page.

= How do I report a security problem? =

Privately: email security@kelpgate.cloud or follow the security policy at https://github.com/KelpGate/.github/blob/main/SECURITY.md. For other help, email support@kelpgate.cloud.

== External services ==

This plugin sends files to the Kelpgate scanning service, an external hosted service operated by JustBots Labs, to check them for malware. This is the plugin's core function.

* **What is sent:** each uploaded file and its name, to the API URL you configure, over HTTPS. Your OAuth client ID and secret are sent to the token URL you configure, to obtain an access token.
* **When:** during each upload, once an account is connected. Nothing is sent before that.
* **Service:** https://kelpgate.cloud (API and console under kelpgate.cloud).

== Changelog ==

= 1.0.12 =
* Prepare for the WordPress.org plugin directory: new plugin slug and text domain (kelpgate-malware-scanner), plugin details now come from this readme.
* Add directory icon and banner.

= 1.0.11 =
* Point the plugin at console.kelpgate.cloud.

= 1.0.10 =
* Document tested WordPress and PHP versions.

= 1.0.9 =
* Initial public release.
