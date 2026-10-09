=== MK Security Shield ===
Contributors: mkdhawan
Tags: security, firewall, login security, two-factor, hardening
Requires at least: 5.8
Tested up to: 6.6
Requires PHP: 8.0
Stable tag: 2.1.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Hardens WordPress against common attack vectors: brute-force logins, XML-RPC abuse, user enumeration, malicious requests, and file tampering.

== Description ==

MK Security Shield is a self-contained WordPress hardening plugin. Security checks run on your server. Core integrity checks contact WordPress.org; verified AI browsing optionally fetches official provider IP ranges over HTTPS and caches them locally. These requests do not send visitor content or credentials.

**No plugin can honestly promise protection against "all" hacking threats.** Attackers exploit weak or reused passwords, outdated plugins and themes, vulnerable hosting configurations, and social engineering — none of which any WordPress plugin can fully control. This plugin closes off the most common WordPress-specific attack surfaces and gives you visibility into suspicious activity. Treat it as one layer in a broader practice that also includes:

* Keeping WordPress core, your theme, and all plugins updated
* Using strong, unique passwords (a password manager helps)
* Taking regular off-site backups
* Using a reputable host with a server-level firewall

= Features =

**Login security**
* Login attempt rate limiting with a configurable lockout duration, keyed by IP address
* Generic login error messages (prevents "wrong username" vs "wrong password" enumeration)
* Simple math challenge on the login form to slow down basic bots
* Optional per-user Two-Factor Authentication (TOTP, compatible with Google Authenticator / Authy / 1Password — no external service required)

**Hardening**
* Disables XML-RPC (a common brute-force and DDoS amplification target)
* Disables the theme/plugin file editor
* Hides the WordPress version number from public output
* Blocks `?author=N` username enumeration and restricts the REST API users endpoint for logged-out visitors
* Adds recommended security response headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS on HTTPS sites, optional Content-Security-Policy)
* Hardens `.htaccess` on Apache hosts: blocks direct access to `wp-config.php` and log/backup files, disables directory listing, and blocks PHP execution inside the uploads folder

**Firewall (beta)**
* Lightweight request filter that flags common SQL injection, path traversal, and code-injection patterns in the request URI, query string, and POST body — starts in log-only mode so you can review before enforcing blocks

**Monitoring**
* Daily WordPress core file integrity check against the official WordPress.org checksums, with email alerts on modified or missing files
* Daily scan of theme/plugin PHP files for common malware signatures, flagged for manual review (never auto-deletes files)
* Full activity log of failed logins, lockouts, firewall matches, and scan results, viewable from the dashboard

**Geo Restriction (optional, off by default)**
* Restricts the whole site — including wp-login.php and wp-admin — to visitors from a chosen list of countries (defaults to India, Nepal, Sri Lanka, UAE)
* Requires the site to be proxied through Cloudflare (free plan is enough); the plugin refuses to activate this feature until you explicitly confirm that, so it never silently trusts a header nobody is actually setting
* Verifies the connecting request actually came from a genuine Cloudflare edge IP before trusting anything it says, closing the common "attacker finds the origin server IP and bypasses the CDN entirely" hole (you should still firewall your origin server to Cloudflare's IP ranges for the durable fix — see FAQ)
* Optionally allowlists Googlebot/Bingbot/DuckDuckBot via verified reverse-DNS (not just User-Agent, which is trivially spoofable) so you don't accidentally get de-indexed from search results
* Ships with a personal emergency bypass link (a secret URL you visit once to grant your own browser a 1-year bypass cookie) so you're never locked out of your own site while traveling

**Connect AI Assistant (optional, off by default)**
* An explicit, Jetpack-style consent screen for letting an AI assistant (Claude, via an MCP client) manage this site — not a hidden or automatic connection, and not a hardcoded credential shipped in code
* Access is issued to a dedicated, purpose-created WordPress account — never your own admin login — so AI-driven changes are attributable in revision history and separate from your own edits
* You choose the access level (Content Editor / Content + Design / Full Control) before anything is created; Full Control requires an extra explicit confirmation
* Uses WordPress core's own built-in Application Passwords (5.6+) for the actual credential — shown once, revocable with one click, never stored in plaintext by this plugin
* The service account is blocked from ever logging in interactively via wp-login.php — enforced at two independent layers, so it can only ever be used through its Application Password
* Every connect, revoke, and authenticated use is written to the Activity Log
* Does not bundle an MCP server — that's WordPress core's own official `WordPress/mcp-adapter` plugin's job (linked from the connection screen); this module only handles authorization and audit, which is what a security plugin should own

= What this plugin does NOT do =

* It is not a cloud WAF and does not maintain a live-updated threat signature database
* It cannot patch vulnerabilities in your theme or other plugins — keep everything updated
* The malware scanner flags *patterns*, not confirmed infections — always review matches manually before deleting anything
* The bundled math challenge is a basic bot deterrent, not a substitute for a real CAPTCHA or for Two-Factor Authentication
* IP-based lockouts trust `REMOTE_ADDR` by default; only enable `MKSS_TRUST_PROXY_HEADERS` if you are certain your site sits behind a trusted reverse proxy/CDN

== Installation ==

1. Upload the `mk-security-shield` folder to `/wp-content/plugins/`
2. Activate the plugin through the "Plugins" menu in WordPress
3. Go to **Security Shield → Settings** to review the defaults (sensible security settings are enabled out of the box; the firewall starts in log-only mode)
4. Check the **Activity Log** for a few days, switch the firewall to "Block" once you're confident there are no false positives
5. Optionally enable Two-Factor Authentication for your own account from **Users → Profile**

== Frequently Asked Questions ==

= Will this break my site? =

The Content-Security-Policy header and firewall request filter are the two features most likely to interfere with functionality if your site relies on inline scripts, third-party embeds, or unusual request formats. CSP is disabled by default; the firewall defaults to "log only" so you can monitor the Activity Log for false positives before switching to enforcement.

= Does this work on Nginx? =

Most features work on any server. The `.htaccess` hardening only applies to Apache; Nginx users should apply equivalent rules directly in their server block.

= I'm locked out after enabling 2FA, what do I do? =

An administrator can go to **Users**, edit the affected account, and use "Disable two-factor authentication for this user" under the Two-Factor Authentication section. If no other administrator has access, you will need direct database access to delete the `mkss_2fa_enabled` and `mkss_2fa_secret` user meta rows for that user.

= Why is the firewall skipping logged-in administrators? =

To avoid blocking legitimate site management (for example, editing content that legitimately contains a `<script>` tag or SQL-like text). It fully inspects all other traffic, including anonymous visitors and lower-privileged logged-in users.

= How do I set up Geo Restriction? =

1. Point your domain's DNS through Cloudflare (free plan works) and make sure the relevant DNS record is "proxied" (orange cloud, not grey/DNS-only).
2. In **Security Shield → Settings**, under Geo Restriction, **copy your emergency bypass link and save/bookmark it first** — you will need it if you're ever traveling outside the allowed countries.
3. Check "I confirm this domain is proxied through Cloudflare" and "Enable geo-restriction", set your allowed country codes, and save.
4. For the strongest version of this protection, also configure your hosting/server firewall to only accept inbound connections from Cloudflare's published IP ranges (https://www.cloudflare.com/ips/) — without this, someone who discovers your origin server's real IP address can connect to it directly and skip Cloudflare (and this restriction) entirely. This plugin verifies the request came from a Cloudflare edge IP as a mitigation, but a server-level firewall rule is the durable fix and isn't something a WordPress plugin can configure for you.
5. Geo IP data is approximate, and anyone using a VPN/proxy located in an allowed country bypasses this trivially — treat it as attack-noise reduction for a site with a defined regional audience, not a hard perimeter.

= I'm sure Cloudflare is set up correctly, but every request shows "geo_blocked_origin_direct" in the Activity Log — why? =

First, verify your domain actually resolves to a Cloudflare IP (not your origin server's real IP) — e.g. `nslookup yourdomain.com` should return an address Cloudflare owns. If that checks out, the likely cause is your host: many managed hosts (Hostinger, Kinsta, WP Engine, SiteGround, and others) automatically rewrite the visitor's IP back to their real address at the web-server level before WordPress ever runs, as a normal, usually-desirable feature. That's good for logging and comment-spam protection, but it also erases the evidence this plugin needs to independently confirm a request actually came through Cloudflare's edge network. If you've confirmed your DNS is correct, enable **"My host restores the real visitor IP"** under Geo Restriction settings — this tells the plugin to trust that your host only performs that rewrite for genuine Cloudflare connections (which is how those hosting features are designed to work) rather than re-verifying it itself.

= How do I let Claude (or another AI assistant) manage this site? =

1. Go to **Security Shield → Connect AI Assistant**.
2. Pick an access level — Content Editor is enough for writing/editing posts, pages, and media; only pick Full Control if you specifically need plugin/theme/user management, and expect the extra confirmation it requires.
3. Click Generate Connection and copy the password shown — it is never shown again, matching how WordPress's own Application Passwords work everywhere else.
4. Install WordPress core's official [MCP Adapter plugin](https://github.com/WordPress/mcp-adapter) — this plugin issues the credential but deliberately does not implement its own MCP server, since that's WordPress core's job to maintain, not a hardening plugin's.
5. Point your MCP client (Claude Desktop, Claude Code, etc.) at the adapter using the site URL and the generated Application Password.
6. To cut off access at any time, come back to this screen and click Revoke Connection — this deletes every Application Password for the service account immediately, not just the most recent one.

== Changelog ==

= 2.1.1 =
* Preserve the deployed 1.2.x settings, AI service account, per-user TOTP, login math challenge, database format and daily monitoring.
* Ignore only absent optional core documentation; check present files, executable core files, official package locale and checksum manifest safety. Persist unverified scans accurately and deduplicate unchanged alerts.
* Allow source-IP-verified public browsing by ChatGPT-User, OAI-SearchBot, Claude-User and Claude-SearchBot through geo restrictions, without granting login or API access.
* Delay REST country enforcement until authentication, keep authenticated administrator recovery, prevent shared caching of geo decisions, validate proxy headers and inspect encoded firewall inputs.


= 1.2.4 =
* Connect AI Assistant diagnostics: stop assuming HTTPS is always the cause when Application Passwords are unavailable — separately check and report whether another active plugin is hooking wp_is_application_passwords_available()/_for_user() to disable the feature outright, and list which callback if so.

= 1.2.3 =
* Connect AI Assistant: show an HTTPS-detection diagnostics panel when Application Passwords aren't available, so sites behind a CDN/proxy that doesn't clearly forward the original protocol to PHP can be debugged from the actual server values instead of guessing header names.

= 1.2.2 =
* Malware Scanner: reword internal signature labels so they no longer spell out exact obfuscation call syntax (e.g. "eval(base64_decode(") verbatim — other scanners (Jetpack Protect, Wordfence) that do naive substring matching over every PHP file on a site were flagging the scanner's own signature list as the malware it exists to detect. Detection patterns are unchanged; only display labels were reworded.

= 1.2.1 =
* Geo Restriction: add "My host restores the real visitor IP" option for hosts (Hostinger, Kinsta, WP Engine, SiteGround, and others) that rewrite REMOTE_ADDR to the real visitor IP before WordPress runs, which otherwise made the Cloudflare-origin verification fail closed even on correctly configured sites.

= 1.2.0 =
* Add optional "Connect AI Assistant" module — Jetpack-style explicit consent flow issuing a scoped WordPress Application Password to a dedicated, least-privilege service account, with revocation and full audit logging. No bundled MCP server or embedded credentials.

= 1.1.0 =
* Add optional Geo Restriction module (Cloudflare country header, verified crawler allowlist, emergency bypass link)

= 1.0.0 =
* Initial release
