# MK Security Shield 2.1.0

This release repairs the shipped v2.0 repository and adds verified public AI browsing through country restrictions. It does not deploy itself or grant AI agents WordPress access.

## Before installation

1. Back up the site's database and current plugin folder. Record its installed version and existing security settings. The screenshot's missing-readme email differs from the v2.0 repository implementation; the deployed version has not been verified.
2. Check PHP compatibility: minimum PHP 8.0. Use a currently supported PHP version in production.
3. Check 2FA separately. The source repository references `class-mkss-two-factor.php` but never shipped it. This release avoids that fatal include and warns administrators if its 2FA option is enabled without the module. It does not implement 2FA. If the deployed plugin has a separately supplied module, a WordPress ZIP replacement can remove that file: verify and back it up, and establish working 2FA before replacing it.
4. Test a staging copy first. The local tests mock WordPress APIs and cannot prove compatibility with the site's hosting, other plugins, caches or CDN.

## Installation and validation

Upload the installable `mk-security-shield-2.1.0.zip` using Plugins > Add New > Upload Plugin. Use WordPress's replacement flow for an existing installation. Retain the backup for rollback.

In MK Security > Geo Restriction, confirm the mode and country lists, enable **Allow Verified AI Browsing**, and save. Legacy geo-enable names and `whitelist`/`blacklist` modes migrate once; an existing explicit current setting takes precedence. Saving one tab preserves the others.

Verify all of the following on staging, then on one live pilot site before expanding the rollout:

- Plugin activation, dashboard, settings save/reload, manual scan, login, logout and password reset.
- India-only allowlist still blocks an ordinary visitor from a disallowed known country.
- Actual Claude/ChatGPT requests reach a public page. Verification requires the source IP and bot token; changing a browser's user-agent alone is intentionally insufficient.
- A forged bot name from an unrelated IP receives no AI exception.
- Application integrations still authenticate normally. The existing REST exemption is preserved; AI browsing adds no REST/admin/login privileges. Application passwords remain disabled by the existing hardening module.
- A missing `readme.html` creates no integrity email. A present but modified readme or modified/missing executable core file remains a finding.
- A checksum-service failure displays an unverified/error result, rather than a clean scan or a compromise claim.

Purge relevant page/CDN caches after the change. A CDN, host firewall, robots.txt restriction or cached response can still prevent AI access before WordPress executes. Check those layers if actual provider requests do not arrive at the plugin.

## Proxy configuration

The plugin accepts `CF-Connecting-IP` only when `REMOTE_ADDR` is in Cloudflare's official IPv4/IPv6 ranges, verified on 2026-10-09. These defaults cover direct Cloudflare-to-origin connections. Do not add entire provider networks or all-address ranges to gain access.

If your host restores the visitor IP into `REMOTE_ADDR`, no forwarded-header configuration is needed. For a different trusted proxy chain, set the host's exact documented proxy networks and chosen header in `wp-config.php` before WordPress loads:

```php
// Example only: replace with the actual proxy network supplied by your host.
define( 'MKSS_TRUSTED_PROXIES', [ '10.20.30.0/24' ] );
define( 'MKSS_CLIENT_IP_HEADER', 'HTTP_X_FORWARDED_FOR' );
```

These custom ranges replace the Cloudflare defaults. For X-Forwarded-For, the plugin walks right-to-left past trusted proxies to find the first untrusted address. The proxy must overwrite or correctly append the header and the origin should be restricted to the trusted ingress. Cloudflare Workers or other intermediaries that rewrite client-IP headers need host-specific validation.

Sources: https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6.

## AI access policy

Allowed provider identities are Claude-User, Claude-SearchBot, ChatGPT-User and OAI-SearchBot. Verification fetches only their hard-coded official HTTPS IP feeds, validates CIDR entries, caches successful data for six hours, and caches failures for five minutes. If verification fails, the ordinary geo policy applies. Geo lookup failure itself retains the intended availability behavior: unknown countries are allowed. IP blocks and WAF checks always run first.

Only public GET/HEAD paths qualify. POST requests, login, admin, PHP scripts, REST/MCP/OAuth routes and authentication/action query parameters get no crawler exception. This is not an authorization mechanism; normal WordPress permissions still determine access. Training crawlers ClaudeBot and GPTBot are not given an exception. The plugin does not change robots.txt.

Provider documentation:

- https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler
- https://developers.openai.com/api/docs/bots

## Integrity and notifications

Missing `readme.html`, `license.txt` and `wp-config-sample.php` are ignored by default. Custom exclusions also apply only to absence. All present manifest files are verified. `wp-trackback.php` is executable core and is no longer a built-in exclusion.

The checker uses the installed core package locale, validates checksum paths and hashes, defers during an active core update, stores service failures as unverified, and suppresses identical notifications for 24 hours. A changed finding alerts immediately, and a clean scan resets the cooldown. Notification state records dispatch attempts; it cannot guarantee email or Slack delivery. Core checksum differences require investigation and are not proof of malware.

The pattern scanner is a heuristic review aid. Ordinary calls such as file writes and base64 decoding can be legitimate. Alerts now say explicitly that a match is not a confirmed infection. It scans configured plugin/theme scope, not every possible infection location; a no-match result does not prove a clean site.

Slack notifications accept HTTPS Slack incoming-webhook hosts only and use safe HTTP requests without redirects. Existing non-Slack webhook URLs need replacement. Existing block expiry checks now compare UTC times consistently; WAF URL checks inspect decoded raw input before display sanitization.

## Remaining security work

- Configure and test a maintained 2FA implementation independently.
- Protect static sensitive files, backups, uploads and directory listings at the web server/CDN. PHP hooks cannot protect files served before WordPress runs.
- Keep WordPress, themes and plugins updated, use least-privilege accounts, and retain off-site recoverable backups.
- Use a maintained malware scanner and review suspicious code against trusted originals. Broader scanning, stronger password policy and rate-limit concurrency are separate follow-up work.
- Review proxy trust and actual AI request logs on each website. Do not assume one site's hosting configuration applies to every site.

## Tests and rollback

```sh
php tests/regression.php
node tests/admin.test.js
```

The offline PHP suite covers bootstrap, migrations, country parsing, proxy spoofing, CIDRs, geo outages, verified/spoofed AI, protected routes, WAF enforcement, integrity cases and scoped settings saves. The JavaScript suite checks the actual form selector, nonce and nested tab-scoped payload. CI runs PHP 8.0 and 8.4.

To roll back, restore the prior plugin folder and database backup. Migration preserves legacy enable keys but updates the current geo mode and country representation. Review geo settings after rollback instead of assuming the older version understands the migrated values.
