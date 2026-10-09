# MK Security Shield 2.1.2

The expansion-joints.in pilot was found running 1.2.4, whose source and settings differ substantially from the GitHub 2.0.0 import. This package uses the verified deployed 1.2.x interfaces and incorporates the integrity and verified-public-AI fixes. It retains the settings array, activity-log table, AI service account, application-password behavior, per-user TOTP, login math challenge, daily monitoring, firewall log-only mode and existing Apache rules.

## Install and roll back

Back up the existing plugin folder and database first. PHP 8.0 or newer is required. Use WordPress Plugins > Add Plugin > Upload Plugin to upload the ZIP, then replace the current version. Do not delete/uninstall the plugin: uninstall intentionally removes its settings and revokes its AI account credentials. For rollback, upload the saved 1.2.4 ZIP and replace the newer files; the legacy option and database formats are retained.

This release is prepared for the verified 1.2.x deployment. A site using the imported 2.0 standalone option/table format needs a separate migration review before installing it. Do not deploy the earlier 2.1.0 ZIP on the 1.2.4 pilot.

## What changes

- Missing readme.html, license.txt and wp-config-sample.php no longer trigger core-change alerts. If present, they are still checksum-verified. Executable core files remain covered. Theme/plugin files stay outside the core comparison and have their own pattern scan.
- Checksum scans use the installed package locale, validate API status and paths, defer during core updates, show unverified/error status accurately and deduplicate an unchanged finding for 24 hours. Pattern matches require human review and are not proof of infection.
- The new verified-AI setting applies only to public GET/HEAD pages. Both provider bot identity and source IP must match the official provider feed. A user-agent string or forged forwarding header alone grants no exception. Training bots, login, admin, PHP scripts, OAuth, MCP, REST routes and write requests receive no AI exemption. Existing authentication/capability checks remain required for connectors.
- Country rules retain their existing Cloudflare confirmation and country allowlist. Authenticated REST users retain their existing capabilities; authenticated administrators retain recovery access. Unknown countries and direct-origin requests remain denied when geo enforcement applies.
- Geo decisions are marked non-cacheable through WordPress and LiteSpeed. Settings changes purge LiteSpeed. Any separate Cloudflare/CDN page cache must also bypass PHP-protected pages when geo restrictions are enabled; a request served entirely by a CDN cannot be evaluated by a WordPress plugin.
- Proxy IP headers are accepted only from configured trusted peers. Search-crawler DNS verification is retained with IPv4/IPv6 forward verification. The firewall retains its configured log/block mode and now inspects twice-decoded request data, returning HTTP 403 for a block.

## Verify the pilot

Confirm the active version; compare prior settings; open the front page and a product page; verify login form and authenticated connector reads; run the integrity and malware scans; temporarily enable geo rules with administrator recovery available, purge caches, verify public requests and authenticated access, then restore the original geo-enabled state. A real Claude/ChatGPT-origin request is needed to prove live provider verification. Spoofing a bot user agent is a negative test, not proof of successful AI access.

Offline tests cover IPv4/IPv6 and proxy boundaries, provider-feed failures, spoofed bots, public/protected paths, geo enforcement, preserved login and scan schedules, encoded firewall inputs, missing-only exclusions, changed-file notifications, checksum failures, update deferral and settings compatibility. They do not prove a site is free of malware.

The live pilot identified valid comma/at-sign paths in the WordPress checksum manifest and a self-match in the malware signature declaration. Version 2.1.2 corrects both. Regression coverage includes valid modern manifests, the scanner source itself and retained detection of all four marker strings.
