<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MKSS_Settings {

	const OPTION_KEY = 'mkss_settings';

	private static $instance = null;
	private $options = array();

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->options = wp_parse_args( get_option( self::OPTION_KEY, array() ), self::default_settings() );

		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
	}

	public static function default_settings() {
		return array(
			'login_max_attempts'       => 5,
			'login_lockout_minutes'    => 20,
			'login_generic_errors'     => 1,
			'login_math_captcha'       => 1,
			'disable_xmlrpc'           => 1,
			'disable_file_edit'        => 1,
			'hide_wp_version'          => 1,
			'disable_user_enumeration' => 1,
			'restrict_rest_users'      => 1,
			'security_headers'         => 1,
			'csp_enabled'              => 0,
			'csp_value'                => "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: https:;",
			'firewall_enabled'         => 1,
			'firewall_mode'            => 'log',
			'harden_htaccess'          => 1,
			'file_monitor_enabled'     => 1,
			'malware_scan_enabled'     => 1,
			'notify_email'             => get_option( 'admin_email' ),
			'geo_restriction_enabled'     => 0,
			'geo_confirmed_cloudflare'    => 0,
			'geo_host_restores_real_ip'   => 0,
			'geo_allowed_countries'       => 'IN,NP,LK,AE',
			'geo_allow_verified_crawlers' => 1,
            'geo_allow_verified_ai' => 1,
			'geo_bypass_key'              => wp_generate_password( 32, false ),
			'geo_block_message'           => __( 'This website is only available to visitors from India, Nepal, Sri Lanka, and the United Arab Emirates. If you believe you are seeing this message in error, please contact the site owner.', 'mk-security-shield' ),
		);
	}

	public function get( $key, $default = null ) {
		return array_key_exists( $key, $this->options ) ? $this->options[ $key ] : $default;
	}

	public function add_menu() {
		add_menu_page(
			__( 'Security Shield', 'mk-security-shield' ),
			__( 'Security Shield', 'mk-security-shield' ),
			'manage_options',
			'mkss-settings',
			array( $this, 'render_settings_page' ),
			'dashicons-shield',
			80
		);

		add_submenu_page(
			'mkss-settings',
			__( 'Settings', 'mk-security-shield' ),
			__( 'Settings', 'mk-security-shield' ),
			'manage_options',
			'mkss-settings',
			array( $this, 'render_settings_page' )
		);
	}

	public function register_settings() {
		register_setting(
			'mkss_settings_group',
			self::OPTION_KEY,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize' ),
			)
		);
	}

	public function sanitize( $input ) {
		$clean = self::default_settings();

		$bool_fields = array(
			'login_generic_errors',
			'login_math_captcha',
			'disable_xmlrpc',
			'disable_file_edit',
			'hide_wp_version',
			'disable_user_enumeration',
			'restrict_rest_users',
			'security_headers',
			'csp_enabled',
			'firewall_enabled',
			'harden_htaccess',
			'file_monitor_enabled',
			'malware_scan_enabled',
			'geo_restriction_enabled',
			'geo_confirmed_cloudflare',
			'geo_host_restores_real_ip',
			'geo_allow_verified_crawlers',
            'geo_allow_verified_ai',
		);

		foreach ( $bool_fields as $field ) {
			$clean[ $field ] = ! empty( $input[ $field ] ) ? 1 : 0;
		}

		$clean['login_max_attempts']    = max( 3, min( 20, (int) ( $input['login_max_attempts'] ?? 5 ) ) );
		$clean['login_lockout_minutes'] = max( 1, min( 1440, (int) ( $input['login_lockout_minutes'] ?? 20 ) ) );
		$clean['firewall_mode']         = in_array( $input['firewall_mode'] ?? 'log', array( 'block', 'log' ), true ) ? ( $input['firewall_mode'] ?? 'log' ) : 'log';
		$clean['csp_value']             = isset( $input['csp_value'] ) ? sanitize_text_field( wp_unslash( $input['csp_value'] ) ) : $clean['csp_value'];
		$clean['notify_email']          = is_email( $input['notify_email'] ?? '' ) ? sanitize_email( $input['notify_email'] ) : get_option( 'admin_email' );

		$codes = array_filter(
			array_map(
				function ( $c ) {
					$c = strtoupper( trim( $c ) );
					return preg_match( '/^[A-Z]{2}$/', $c ) ? $c : '';
				},
				explode( ',', (string) ( $input['geo_allowed_countries'] ?? '' ) )
			)
		);
		$clean['geo_allowed_countries'] = $codes ? implode( ',', array_unique( $codes ) ) : 'IN,NP,LK,AE';

		if ( ! empty( $input['geo_bypass_key_regenerate'] ) ) {
			$clean['geo_bypass_key'] = wp_generate_password( 32, false );
		} else {
			$submitted_key           = isset( $input['geo_bypass_key'] ) ? sanitize_text_field( wp_unslash( $input['geo_bypass_key'] ) ) : '';
			$previous_key            = isset( $this->options['geo_bypass_key'] ) ? $this->options['geo_bypass_key'] : '';
			$clean['geo_bypass_key'] = ( strlen( $submitted_key ) >= 12 ) ? $submitted_key : ( $previous_key ?: wp_generate_password( 32, false ) );
		}

		$clean['geo_block_message'] = isset( $input['geo_block_message'] ) && strlen( trim( $input['geo_block_message'] ) ) > 0
			? sanitize_textarea_field( wp_unslash( $input['geo_block_message'] ) )
			: $clean['geo_block_message'];

		if ( ! empty( $clean['harden_htaccess'] ) ) {
			MKSS_Hardening::write_htaccess_rules();
		} else {
			MKSS_Hardening::remove_htaccess_rules();
		}

		do_action( 'litespeed_purge_all' );
		return $clean;
	}

	public function render_settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$o = $this->options;
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'MK Security Shield', 'mk-security-shield' ); ?> <small><?php echo esc_html( MKSS_VERSION ); ?></small></h1>
			<p>
				<?php esc_html_e( 'Hardens common WordPress attack surfaces. No plugin can guarantee protection against every threat — keep WordPress, your theme, and all plugins updated, use strong unique passwords, and maintain off-site backups.', 'mk-security-shield' ); ?>
			</p>

			<form method="post" action="options.php">
				<?php settings_fields( 'mkss_settings_group' ); ?>

				<h2><?php esc_html_e( 'Login Security', 'mk-security-shield' ); ?></h2>
				<table class="form-table">
					<tr>
						<th><?php esc_html_e( 'Max failed attempts', 'mk-security-shield' ); ?></th>
						<td><input type="number" min="3" max="20" name="mkss_settings[login_max_attempts]" value="<?php echo esc_attr( $o['login_max_attempts'] ); ?>" /></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Lockout duration (minutes)', 'mk-security-shield' ); ?></th>
						<td><input type="number" min="1" max="1440" name="mkss_settings[login_lockout_minutes]" value="<?php echo esc_attr( $o['login_lockout_minutes'] ); ?>" /></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Generic login errors', 'mk-security-shield' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="mkss_settings[login_generic_errors]" value="1" <?php checked( $o['login_generic_errors'], 1 ); ?> />
								<?php esc_html_e( 'Hide whether the username or password was wrong (prevents user enumeration via login errors)', 'mk-security-shield' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Math challenge on login', 'mk-security-shield' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="mkss_settings[login_math_captcha]" value="1" <?php checked( $o['login_math_captcha'], 1 ); ?> />
								<?php esc_html_e( 'Adds a simple arithmetic question to the login form. This is a basic bot deterrent, not a substitute for a real CAPTCHA or Two-Factor Authentication.', 'mk-security-shield' ); ?>
							</label>
						</td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Hardening', 'mk-security-shield' ); ?></h2>
				<table class="form-table">
					<tr>
						<th><?php esc_html_e( 'Disable XML-RPC', 'mk-security-shield' ); ?></th>
						<td><label><input type="checkbox" name="mkss_settings[disable_xmlrpc]" value="1" <?php checked( $o['disable_xmlrpc'], 1 ); ?> /> <?php esc_html_e( 'Blocks xmlrpc.php, a common brute-force and DDoS amplification target', 'mk-security-shield' ); ?></label></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Disable theme/plugin file editor', 'mk-security-shield' ); ?></th>
						<td><label><input type="checkbox" name="mkss_settings[disable_file_edit]" value="1" <?php checked( $o['disable_file_edit'], 1 ); ?> /></label></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Hide WordPress version', 'mk-security-shield' ); ?></th>
						<td><label><input type="checkbox" name="mkss_settings[hide_wp_version]" value="1" <?php checked( $o['hide_wp_version'], 1 ); ?> /></label></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Prevent username enumeration', 'mk-security-shield' ); ?></th>
						<td><label><input type="checkbox" name="mkss_settings[disable_user_enumeration]" value="1" <?php checked( $o['disable_user_enumeration'], 1 ); ?> /> <?php esc_html_e( 'Blocks ?author=N probing', 'mk-security-shield' ); ?></label></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Restrict REST API user data', 'mk-security-shield' ); ?></th>
						<td><label><input type="checkbox" name="mkss_settings[restrict_rest_users]" value="1" <?php checked( $o['restrict_rest_users'], 1 ); ?> /> <?php esc_html_e( 'Blocks /wp-json/wp/v2/users for logged-out visitors', 'mk-security-shield' ); ?></label></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Security headers', 'mk-security-shield' ); ?></th>
						<td><label><input type="checkbox" name="mkss_settings[security_headers]" value="1" <?php checked( $o['security_headers'], 1 ); ?> /></label></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Content-Security-Policy', 'mk-security-shield' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="mkss_settings[csp_enabled]" value="1" <?php checked( $o['csp_enabled'], 1 ); ?> />
								<?php esc_html_e( 'Enable (test thoroughly — an incorrect policy can break page assets, embeds, and third-party scripts)', 'mk-security-shield' ); ?>
							</label><br/>
							<input type="text" class="large-text" name="mkss_settings[csp_value]" value="<?php echo esc_attr( $o['csp_value'] ); ?>" />
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Harden .htaccess (Apache only)', 'mk-security-shield' ); ?></th>
						<td><label><input type="checkbox" name="mkss_settings[harden_htaccess]" value="1" <?php checked( $o['harden_htaccess'], 1 ); ?> /> <?php esc_html_e( 'Blocks direct access to wp-config.php and log/backup files, disables directory listing, and blocks PHP execution inside the uploads folder. Nginx users must apply equivalent rules manually.', 'mk-security-shield' ); ?></label></td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Firewall (beta)', 'mk-security-shield' ); ?></h2>
				<table class="form-table">
					<tr>
						<th><?php esc_html_e( 'Enable request filtering', 'mk-security-shield' ); ?></th>
						<td><label><input type="checkbox" name="mkss_settings[firewall_enabled]" value="1" <?php checked( $o['firewall_enabled'], 1 ); ?> /> <?php esc_html_e( 'Blocks requests containing common SQL injection / path traversal / code injection patterns in the URL, query string, or POST body', 'mk-security-shield' ); ?></label></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Mode', 'mk-security-shield' ); ?></th>
						<td>
							<select name="mkss_settings[firewall_mode]">
								<option value="log" <?php selected( $o['firewall_mode'], 'log' ); ?>><?php esc_html_e( 'Log only (recommended to start — review Activity Log for false positives)', 'mk-security-shield' ); ?></option>
								<option value="block" <?php selected( $o['firewall_mode'], 'block' ); ?>><?php esc_html_e( 'Block matching requests', 'mk-security-shield' ); ?></option>
							</select>
						</td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Monitoring', 'mk-security-shield' ); ?></h2>
				<table class="form-table">
					<tr>
						<th><?php esc_html_e( 'Core file integrity monitoring', 'mk-security-shield' ); ?></th>
						<td><label><input type="checkbox" name="mkss_settings[file_monitor_enabled]" value="1" <?php checked( $o['file_monitor_enabled'], 1 ); ?> /> <?php esc_html_e( 'Daily check of WordPress core files against official WordPress.org checksums', 'mk-security-shield' ); ?></label></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Malware pattern scanning', 'mk-security-shield' ); ?></th>
						<td><label><input type="checkbox" name="mkss_settings[malware_scan_enabled]" value="1" <?php checked( $o['malware_scan_enabled'], 1 ); ?> /> <?php esc_html_e( 'Daily scan of theme/plugin PHP files for common malware signatures (flags for manual review; never auto-deletes)', 'mk-security-shield' ); ?></label></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Alert email', 'mk-security-shield' ); ?></th>
						<td><input type="email" class="regular-text" name="mkss_settings[notify_email]" value="<?php echo esc_attr( $o['notify_email'] ); ?>" /></td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Geo Restriction (Country Access Control)', 'mk-security-shield' ); ?></h2>
				<p>
					<?php esc_html_e( 'Restrict the entire site to visitors from specific countries. This only works if your site\'s DNS is proxied through Cloudflare (the "orange cloud" setting) — Cloudflare stamps every request with the visitor\'s country for free. This feature refuses to activate until you confirm that below.', 'mk-security-shield' ); ?>
				</p>
				<table class="form-table">
					<tr>
						<th><?php esc_html_e( 'Enable geo-restriction', 'mk-security-shield' ); ?></th>
						<td><label><input type="checkbox" name="mkss_settings[geo_restriction_enabled]" value="1" <?php checked( $o['geo_restriction_enabled'], 1 ); ?> /></label></td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Confirm Cloudflare', 'mk-security-shield' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="mkss_settings[geo_confirmed_cloudflare]" value="1" <?php checked( $o['geo_confirmed_cloudflare'], 1 ); ?> />
								<?php esc_html_e( 'I confirm this domain\'s DNS is proxied through Cloudflare (orange-clouded). For real protection, your origin server should also be firewalled to only accept connections from Cloudflare\'s published IP ranges (cloudflare.com/ips) — otherwise an attacker who finds your real server IP can bypass this entirely.', 'mk-security-shield' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'My host restores the real visitor IP', 'mk-security-shield' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="mkss_settings[geo_host_restores_real_ip]" value="1" <?php checked( $o['geo_host_restores_real_ip'], 1 ); ?> />
								<?php esc_html_e( 'Enable ONLY if you see "geo_blocked_origin_direct" in the Activity Log for requests you know came through Cloudflare (verify your domain actually resolves to a Cloudflare IP first). Many managed hosts — Hostinger, Kinsta, WP Engine, SiteGround, and others — automatically rewrite the visitor IP back to the real one at the server level before WordPress runs, which is normally desirable but means this plugin cannot independently re-verify the request came through Cloudflare. Checking this trusts that your host only performs that rewrite for genuine Cloudflare connections.', 'mk-security-shield' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Allowed countries', 'mk-security-shield' ); ?></th>
						<td>
							<input type="text" class="regular-text" name="mkss_settings[geo_allowed_countries]" value="<?php echo esc_attr( $o['geo_allowed_countries'] ); ?>" />
							<p class="description"><?php esc_html_e( 'Comma-separated 2-letter ISO country codes. Default: IN (India), NP (Nepal), LK (Sri Lanka), AE (UAE).', 'mk-security-shield' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Allow verified search engine crawlers', 'mk-security-shield' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="mkss_settings[geo_allow_verified_crawlers]" value="1" <?php checked( $o['geo_allow_verified_crawlers'], 1 ); ?> />
								<?php esc_html_e( 'Recommended — Googlebot/Bingbot/DuckDuckBot mostly crawl from outside these countries. Leaving this off will likely get your site de-indexed from search results. Verified via reverse-DNS, not just User-Agent (which is easily spoofed).', 'mk-security-shield' ); ?>
							</label>
						</td>
					</tr>
                    <tr><th><?php esc_html_e( 'Allow verified AI public browsing', 'mk-security-shield' ); ?></th>
                    <td><label><input type="checkbox" name="mkss_settings[geo_allow_verified_ai]" value="1" <?php checked( $o['geo_allow_verified_ai'], 1 ); ?> />
                    <?php esc_html_e( 'Allow ChatGPT-User, OAI-SearchBot, Claude-User and Claude-SearchBot on public GET/HEAD pages only after checking their source IP against official provider ranges. This does not grant login or API access.', 'mk-security-shield' ); ?></label></td></tr>
					<tr>
						<th><?php esc_html_e( 'Your emergency bypass link', 'mk-security-shield' ); ?></th>
						<td>
							<input type="text" class="large-text" readonly onclick="this.select();" value="<?php echo esc_url( add_query_arg( 'mkss_bypass', $o['geo_bypass_key'], home_url( '/' ) ) ); ?>" />
							<p class="description"><?php esc_html_e( 'Bookmark this link before enabling the restriction. Visiting it once, from anywhere, grants your browser a 1-year bypass cookie — including for wp-login.php and wp-admin.', 'mk-security-shield' ); ?></p>
							<input type="text" class="regular-text" name="mkss_settings[geo_bypass_key]" value="<?php echo esc_attr( $o['geo_bypass_key'] ); ?>" />
							<label style="display:block;margin-top:6px;">
								<input type="checkbox" name="mkss_settings[geo_bypass_key_regenerate]" value="1" />
								<?php esc_html_e( 'Generate a new random key on save (invalidates the link above and any saved bypass cookies)', 'mk-security-shield' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Message shown to blocked visitors', 'mk-security-shield' ); ?></th>
						<td><textarea class="large-text" rows="3" name="mkss_settings[geo_block_message]"><?php echo esc_textarea( $o['geo_block_message'] ); ?></textarea></td>
					</tr>
				</table>

				<?php submit_button(); ?>
			</form>

			<p>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=mkss-activity-log' ) ); ?>"><?php esc_html_e( 'View Activity Log →', 'mk-security-shield' ); ?></a>
				&nbsp;|&nbsp;
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=mkss-scan-results' ) ); ?>"><?php esc_html_e( 'View Scan Results →', 'mk-security-shield' ); ?></a>
			</p>
		</div>
		<?php
	}
}
