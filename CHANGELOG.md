# Changelog

The same history appears in `readme.txt`, which WordPress.org displays. Keep the two in step.

## 1.0.13

- Every scan now sends an `Idempotency-Key`, so a repeated request (for example the retry after a refreshed token) is not counted against your plan's quota twice. One key is made per scan; there is nothing to configure. See the [Kelpgate client standard](https://github.com/KelpGate/.github/blob/main/docs/client-standard.md#idempotency).

## 1.0.12

- Prepare for the WordPress.org plugin directory: new plugin slug and text domain (kelpgate-malware-scanner), plugin details now come from this readme.
- Add directory icon and banner.

## 1.0.11

- Point the plugin at console.kelpgate.cloud.

## 1.0.10

- Document tested WordPress and PHP versions.

## 1.0.9

- Initial public release.
