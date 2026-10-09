=== MK Security Shield ===
Contributors: mkdhawan
Tags: security, firewall, login protection, integrity, geo blocking
Requires at least: 5.8
Stable tag: 2.1.0
Requires PHP: 8.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress login protection, URL firewall, core integrity monitoring, code pattern review, and country restrictions with verified public AI browsing.

== Description ==

* Login attempt limits with expiring IP lockouts and activity logging.
* URL/query rules for common SQL injection, XSS and traversal patterns. These rules supplement normal application validation and server/CDN protection.
* Core integrity comparisons against official WordPress checksums. Missing optional documentation is ignored; present files are still verified.
* Country blocklist/allowlist using ipapi.co. Unknown countries are allowed when lookup fails.
* Verified Claude and ChatGPT user/search bots can read public pages despite country restrictions. Verification requires the official source IP and recognized user-agent; IP blocks and WAF checks still apply.
* Configurable email and HTTPS Slack incoming-webhook alerts.
* File-editor disabling, version hiding, security response headers and a WordPress dashboard widget.
* Heuristic PHP pattern scanning for manual review. Pattern matches are not confirmed infections; a no-match result does not prove the site is malware-free.

The original source repository referenced a two-factor module that it did not include. This release does not implement 2FA. It avoids the missing-file fatal error and displays an administrator warning when 2FA is configured without a module. Use a maintained independent 2FA solution.

== Installation ==

1. Back up the database and current plugin folder. Read UPGRADE.md, especially the 2FA and proxy notes.
2. Test the ZIP on a staging copy before replacing a live installation.
3. Upload the mk-security-shield folder to wp-content/plugins, or use WordPress's plugin ZIP replacement flow.
4. Open MK Security and review each settings tab.
5. In Geo Restriction, confirm mode/countries and Allow Verified AI Browsing. Save and reload to verify persistence.
6. Run an integrity scan and validate actual provider requests on a pilot site before installing on further websites.

== Frequently Asked Questions ==

= Why does missing readme.html no longer send an alarm? =

readme.html, license.txt and wp-config-sample.php are optional for the running site. Only their absence is ignored. If present, they are checked against official checksums. wp-trackback.php is executable core and is checked by default.

= Can I add exclusions? =

The Files tab accepts relative paths, one per line. Custom exclusions also ignore absence only. Use exclusions only for reviewed intentional removals.

= Which AI bots get the country exception? =

Claude-User, Claude-SearchBot, ChatGPT-User and OAI-SearchBot, after IP verification using their official HTTPS feeds. Successful feeds are cached for six hours and failed verification for five minutes. The exception applies to public GET/HEAD paths, not protected admin/login/API routes or writes. It grants no WordPress permissions. Training bots ClaudeBot and GPTBot are not included.

= Will this guarantee Claude/ChatGPT access? =

No. The provider must send a matching identity from its published IP ranges. Hosting/CDN rules, robots.txt and cached blocks can prevent the request before WordPress runs. Check actual request logs and validate each site's layers independently.

= What happens if geolocation or the bot feed is unavailable? =

An unknown country is allowed, retaining availability during geo-service failure. A bot that cannot be verified receives no special exception and follows ordinary country rules.

= Is Cloudflare supported? =

CF-Connecting-IP is trusted only when the connected peer is within the published Cloudflare IPv4/IPv6 networks. Other proxies require explicit configuration in wp-config.php; see UPGRADE.md. Directly supplied forwarded headers cannot override the peer IP.

= Does a scan finding mean malware? =

No. Core checksum differences require investigation. Code pattern matches can occur in legitimate plugins and must be reviewed before deleting or changing files. Service failures are recorded as unverified, not as confirmed compromise.

= What is outside this plugin's protection? =

Static files served before WordPress, full-site malware detection, application authorization and CDN behavior need separate controls. The existing hardening module disables application passwords, which may affect integrations. See UPGRADE.md for deployment checks and remaining security work.

== Changelog ==

= 2.1.0 =
* Repair startup when the unshipped optional two-factor module is absent; report unavailable protection honestly.
* Add verified public Claude/ChatGPT browsing through country restrictions.
* Unify geo enable keys, migrate legacy modes and normalize array/text country lists.
* Run front-end geo checks after route parsing and handle geo outages as unknown countries.
* Repair settings JavaScript and tab-scoped saves; preserve unrelated settings.
* Limit file exclusions to absence; restore wp-trackback.php checks.
* Use installed core package locale, validate manifests, defer scans during core updates and distinguish scan errors from findings.
* Suppress identical integrity notifications for 24 hours while alerting on new changes.
* Trust forwarded IP headers only from configured proxies; include verified Cloudflare networks.
* Inspect decoded raw URLs in the firewall, preserve prior REST auth results, and compare IP-block expiry in UTC.
* Restrict Slack delivery to HTTPS Slack webhook hosts without redirects.
* Clarify heuristic scanner wording and remove unsupported feature claims.
* Add offline PHP/JavaScript regressions and CI.

= 2.0.0 =
* Initial source repository import with login protection, firewall, integrity monitor, geo restrictions and code-pattern scanning.

== Upgrade Notice ==

= 2.1.0 =
Back up and test on staging. Verify any separately supplied 2FA module before ZIP replacement. Review geo settings and proxy trust on each site. Read UPGRADE.md for checks and rollback.
