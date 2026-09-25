=== MK Security Shield ===
Contributors: mkdhawan
Tags: security, firewall, login protection, malware scanner, geo blocking
Requires at least: 6.0
Tested up to: 6.7
Stable tag: 2.0.0
Requires PHP: 8.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Advanced security plugin with firewall, login protection, file integrity monitoring, geo blocking, malware scanning, and real-time alerts.

== Description ==

MK Security Shield is a comprehensive WordPress security plugin that protects your website from attacks, unauthorised access, and malicious code.

**Key Features:**

* **Web Application Firewall (WAF)** — Blocks SQL injection, XSS, directory traversal, and bad bots before they reach WordPress.
* **Login Protection** — Limits failed login attempts and auto-blocks brute-force IPs. Configurable lockout threshold, duration, and admin email alerts.
* **File Integrity Monitoring** — Compares WordPress core files against the official WordPress.org checksums API. False positives for intentionally-removed files (readme.html, license.txt) are automatically excluded.
* **Malware Scanner** — Scans active plugins and theme PHP files for suspicious patterns including eval(), base64_decode(), shell_exec(), remote file inclusions, and known backdoor signatures.
* **Geo Restriction** — Block or allow visitors by country using ipapi.co. Supports both blocklist and allowlist modes with 2-letter ISO country codes.
* **Security Hardening** — Disables file editing in admin, removes WordPress version leaks, blocks direct access to sensitive files, enforces strong passwords for administrators.
* **Activity Log** — Records all security events (login attempts, IP blocks, firewall triggers, file issues) with severity levels. Exportable and searchable.
* **Real-time Alerts** — Email and Slack webhook notifications for critical events. Daily summary email with 24-hour event counts.
* **WordPress Dashboard Widget** — At-a-glance security overview on the main WP dashboard.
* **HTTP Security Headers** — Adds X-Content-Type-Options, X-Frame-Options, HSTS (when on HTTPS), Referrer-Policy, and Permissions-Policy headers automatically.
* **Cloudflare Compatible** — Correctly detects real visitor IPs behind Cloudflare and other reverse proxies.

== Installation ==

1. Upload the `mk-security-shield` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Navigate to **Security Shield** in the admin menu.
4. Configure settings per tab: Firewall, Login, Hardening, Files, Geo, Notifications.
5. Run an initial file integrity scan from the **Files** tab.

== Frequently Asked Questions ==

= Why am I not getting alerts for readme.html? =

readme.html, license.txt, wp-config-sample.php, and wp-trackback.php are intentionally excluded from file integrity checks. These files are commonly removed during WordPress hardening and their absence should not trigger a security alert. This is by design in v2.0.

= Can I add more files to the exclusion list? =

Yes. Go to **Security Shield → Files** and add relative file paths (one per line) to the custom exclusion list.

= Does the malware scanner check all files? =

The malware scanner checks all PHP files in your currently active plugins and active theme. It looks for common obfuscation and backdoor patterns.

= What happens when an IP is blocked? =

Blocked IPs are stored in the database with an expiry timestamp. They receive an HTTP 403 error. You can view and manually unblock IPs from the **Blocked IPs** tab.

= Is Cloudflare supported? =

Yes. The plugin checks CF-Connecting-IP first to get the real visitor IP when your site is behind Cloudflare.

= Will geo blocking affect my admin access? =

Geo blocking skips the WordPress admin area, cron jobs, and REST API internal requests by default.

== Screenshots ==

1. Security Dashboard — overview cards and quick scan button.
2. Firewall Settings — WAF patterns, XML-RPC control, security headers.
3. Login Protection — attempt limits, lockout duration, alert settings.
4. File Integrity — scan results with exclusions management.
5. Activity Log — filterable event log with severity levels.
6. Blocked IPs — list of currently blocked IPs with one-click unblock.

== Changelog ==

= 2.0.0 =
* Complete rewrite with PSR-4-style class architecture.
* Added malware scanner for active plugins and themes.
* Added geo restriction with blocklist/allowlist mode.
* Added Slack webhook notifications.
* Added daily email summary report.
* Added WordPress dashboard widget.
* Added HTTP security headers.
* Added custom DB table for IP blocks with automatic expiry.
* Fixed false-positive file integrity alerts for intentionally-removed files (readme.html, license.txt, wp-config-sample.php, wp-trackback.php).
* Improved WAF with expanded bad-bot list and user enumeration blocking.
* Added configurable security exclusions list.
* Minimum PHP version raised to 8.0 (uses typed properties, named args, match expressions).

= 1.2.4 =
* Minor bug fixes.
* Updated file integrity check against WordPress 6.x checksums.

= 1.2.0 =
* Added file integrity monitoring.
* Added activity log.

= 1.0.0 =
* Initial release: login protection, basic firewall, email alerts.

== Upgrade Notice ==

= 2.0.0 =
Major upgrade — back up your site before upgrading. After activation, visit Security Shield settings to review and configure the new features. Existing blocked IPs and activity logs are preserved.
