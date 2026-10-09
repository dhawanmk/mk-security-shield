<?php
/**
 * Admin Settings Page for MK Security Shield v2.0.
 *
 * @package MK_Security_Shield
 */

defined( 'ABSPATH' ) || exit;

class MKSS_Settings {

	public function __construct() {
		add_action( 'admin_menu', [ $this, 'add_menu' ] );
		add_action( 'admin_init', [ $this, 'register_settings' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );
		add_action( 'wp_ajax_mkss_save_settings', [ $this, 'ajax_save' ] );
		add_action( 'wp_ajax_mkss_dismiss_notice', [ $this, 'ajax_dismiss_notice' ] );
		add_action( 'admin_notices', [ $this, 'admin_notices' ] );
	}

	/**
	 * Register admin menu.
	 */
	public function add_menu(): void {
		add_menu_page(
			__( 'MK Security Shield', 'mk-security-shield' ),
			__( 'MK Security', 'mk-security-shield' ),
			'manage_options',
			'mk-security-shield',
			[ $this, 'render_page' ],
			'dashicons-shield-alt',
			80
		);
	}

	/**
	 * Register all settings.
	 */
	public function register_settings(): void {
		$options = [
			// Firewall
			'mkss_block_sql_injection'        => 'bool',
			'mkss_block_xss'                  => 'bool',
			'mkss_block_directory_traversal'  => 'bool',
			'mkss_block_bad_bots'             => 'bool',
			'mkss_block_xmlrpc'               => 'bool',
			'mkss_block_user_enum'            => 'bool',
			'mkss_disable_pingback'           => 'bool',
			'mkss_enable_rest_api_protection' => 'bool',
			// Login
			'mkss_max_login_attempts'         => 'int',
			'mkss_lockout_duration'           => 'int',
			'mkss_hide_login_errors'          => 'bool',
			'mkss_notify_on_login_fail'       => 'bool',
			// Hardening
			'mkss_remove_wp_version'          => 'bool',
			'mkss_disable_file_editor'        => 'bool',
			// File monitor
			'mkss_notify_on_file_change'      => 'bool',
			'mkss_security_exclusions'        => 'array_text',
			// Notifications
			'mkss_notify_email'               => 'email',
			'mkss_notify_slack_webhook'       => 'url',
			// Geo restriction
			'mkss_geo_restriction_enabled'    => 'bool',
			'mkss_geo_allow_verified_ai'      => 'bool',
			'mkss_geo_allowed_countries'      => 'array_text',
			'mkss_geo_blocked_countries'      => 'array_text',
			'mkss_geo_mode'                   => 'text',
		];

		foreach ( $options as $key => $type ) {
			register_setting(
				'mkss_settings',
				$key,
				[ 'sanitize_callback' => fn( $v ) => MKSS_Helper::sanitize_option( $v, $type ) ]
			);
		}
	}

	/**
	 * Enqueue admin CSS/JS only on our page.
	 */
	public function enqueue_assets( string $hook ): void {
		if ( strpos( $hook, 'mk-security-shield' ) === false ) {
			return;
		}
		wp_enqueue_style(
			'mkss-admin',
			MKSS_PLUGIN_URL . 'assets/css/admin.css',
			[],
			MKSS_VERSION
		);
		wp_enqueue_script(
			'mkss-admin',
			MKSS_PLUGIN_URL . 'assets/js/admin.js',
			[ 'jquery' ],
			MKSS_VERSION,
			true
		);
		wp_localize_script( 'mkss-admin', 'mkssData', [
			'nonce'       => wp_create_nonce( 'mkss_ajax_nonce' ),
			'ajaxUrl'     => admin_url( 'admin-ajax.php' ),
			'savedText'   => __( 'Settings saved!', 'mk-security-shield' ),
			'errorText'   => __( 'Error saving settings.', 'mk-security-shield' ),
			'scanRunning' => __( 'Scanning…', 'mk-security-shield' ),
		] );
	}

	/**
	 * Admin notices for scan results, unlock messages, etc.
	 */
	public function admin_notices(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$screen = get_current_screen();
		if ( ! $screen || strpos( $screen->id, 'mk-security-shield' ) === false ) {
			return;
		}

		// File scan result notice
		if ( isset( $_GET['mkss_scan'] ) ) { // phpcs:ignore
			$status = sanitize_text_field( wp_unslash( $_GET['mkss_scan'] ) ); // phpcs:ignore
			$count  = isset( $_GET['mkss_count'] ) ? (int) $_GET['mkss_count'] : 0; // phpcs:ignore
			if ( 'ok' === $status ) {
				echo '<div class="notice notice-success is-dismissible"><p><strong>' . esc_html__( 'File Integrity OK', 'mk-security-shield' ) . '</strong> — ' . esc_html__( 'No issues found.', 'mk-security-shield' ) . '</p></div>';
			} elseif ( in_array( $status, [ 'error', 'deferred' ], true ) ) {
				$result = get_option( 'mkss_last_file_check_result', [] );
				echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html( implode( ' ', $result['errors'] ?? [ 'Integrity check did not complete.' ] ) ) . '</p></div>';
			} else {
				echo '<div class="notice notice-error is-dismissible"><p><strong>' . esc_html__( 'File Integrity Issues Found', 'mk-security-shield' ) . '</strong> — ' . sprintf( esc_html__( '%d file(s) modified or missing. Check the activity log.', 'mk-security-shield' ), $count ) . '</p></div>';
			}
		}

		// IP unlock notice
		if ( isset( $_GET['mkss_msg'] ) && 'ip_unlocked' === $_GET['mkss_msg'] ) { // phpcs:ignore
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'IP address has been unblocked.', 'mk-security-shield' ) . '</p></div>';
		}
	}

	/**
	 * AJAX save handler.
	 */
	public function ajax_save(): void {
		check_ajax_referer( 'mkss_ajax_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$posted = isset( $_POST['settings'] ) ? wp_unslash( $_POST['settings'] ) : []; // phpcs:ignore
		if ( ! is_array( $posted ) ) {
			wp_send_json_error( 'Invalid data' );
		}
		foreach ( $posted as $value ) {
			if ( ! is_scalar( $value ) ) {
				wp_send_json_error( 'Invalid setting value' );
			}
		}
		if ( ! empty( $posted['mkss_notify_slack_webhook'] ) ) {
			$url = esc_url_raw( $posted['mkss_notify_slack_webhook'] );
			if ( 'https' !== wp_parse_url( $url, PHP_URL_SCHEME ) || ! in_array( wp_parse_url( $url, PHP_URL_HOST ), [ 'hooks.slack.com', 'hooks.slack-gov.com' ], true ) ) {
				wp_send_json_error( 'Use an HTTPS Slack incoming webhook URL.' );
			}
		}

		$bool_fields = [
			'mkss_block_sql_injection', 'mkss_block_xss', 'mkss_block_directory_traversal',
			'mkss_block_bad_bots', 'mkss_block_xmlrpc', 'mkss_block_user_enum',
			'mkss_disable_pingback', 'mkss_enable_rest_api_protection',
			'mkss_hide_login_errors', 'mkss_notify_on_login_fail',
			'mkss_remove_wp_version', 'mkss_disable_file_editor',
			'mkss_notify_on_file_change', 'mkss_geo_restriction_enabled', 'mkss_geo_allow_verified_ai',
		];
		foreach ( $bool_fields as $field ) {
			if ( array_key_exists( $field, $posted ) ) {
				update_option( $field, in_array( $posted[$field], [ true, 1, '1' ], true ) );
			}
		}

		$int_fields = [ 'mkss_max_login_attempts' => 5, 'mkss_lockout_duration' => 30 ];
		foreach ( $int_fields as $field => $default ) {
			if ( isset( $posted[$field] ) ) {
				$maximum = 'mkss_max_login_attempts' === $field ? 20 : 10080;
				update_option( $field, min( $maximum, max( 1, (int) $posted[$field] ) ) );
			}
		}

		if ( ! empty( $posted['mkss_notify_email'] ) ) {
			update_option( 'mkss_notify_email', sanitize_email( $posted['mkss_notify_email'] ) );
		}
		if ( isset( $posted['mkss_notify_slack_webhook'] ) ) {
			update_option( 'mkss_notify_slack_webhook', esc_url_raw( $posted['mkss_notify_slack_webhook'] ) );
		}

		// Array fields (newline separated)
		foreach ( [ 'mkss_security_exclusions', 'mkss_geo_allowed_countries', 'mkss_geo_blocked_countries' ] as $field ) {
			if ( isset( $posted[ $field ] ) ) {
				$lines = 'mkss_security_exclusions' === $field
					? array_filter( array_map( 'trim', array_map( 'sanitize_text_field', preg_split( '/[\r\n,]+/', (string) $posted[$field] ) ) ) )
					: MKSS_Helper::country_codes( $posted[$field] );
				update_option( $field, array_values( $lines ) );
			}
		}
		if ( isset( $posted['mkss_geo_mode'] ) ) {
			update_option( 'mkss_geo_mode', in_array( $posted['mkss_geo_mode'], [ 'allowlist', 'blocklist' ], true ) ? $posted['mkss_geo_mode'] : 'blocklist' );
		}

		MKSS_Activity_Log::log( 'settings_saved', 'Admin saved plugin settings.', 0 );
		wp_send_json_success( __( 'Settings saved.', 'mk-security-shield' ) );
	}

	/**
	 * Dismiss admin notice via AJAX.
	 */
	public function ajax_dismiss_notice(): void {
		check_ajax_referer( 'mkss_ajax_nonce', 'nonce' );
		wp_send_json_success();
	}

	/**
	 * Render the main admin page.
	 */
	public function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$active_tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'dashboard'; // phpcs:ignore
		?>
		<div class="wrap mkss-wrap">
			<h1 class="mkss-title">
				<span class="dashicons dashicons-shield-alt"></span>
				<?php esc_html_e( 'MK Security Shield', 'mk-security-shield' ); ?>
				<span class="mkss-version">v<?php echo esc_html( MKSS_VERSION ); ?></span>
			</h1>

			<nav class="mkss-tabs nav-tab-wrapper">
				<?php
				$tabs = [
					'dashboard'  => __( '🛡 Dashboard', 'mk-security-shield' ),
					'firewall'   => __( '🔥 Firewall', 'mk-security-shield' ),
					'login'      => __( '🔐 Login Protection', 'mk-security-shield' ),
					'hardening'  => __( '🔩 Hardening', 'mk-security-shield' ),
					'files'      => __( '📁 File Monitor', 'mk-security-shield' ),
					'geo'        => __( '🌍 Geo Restriction', 'mk-security-shield' ),
					'notify'     => __( '🔔 Notifications', 'mk-security-shield' ),
					'activity'   => __( '📋 Activity Log', 'mk-security-shield' ),
					'blocked'    => __( '🚫 Blocked IPs', 'mk-security-shield' ),
				];
				foreach ( $tabs as $slug => $label ) {
					$class = ( $active_tab === $slug ) ? 'nav-tab nav-tab-active' : 'nav-tab';
					printf(
						'<a href="%s" class="%s">%s</a>',
						esc_url( admin_url( 'admin.php?page=mk-security-shield&tab=' . $slug ) ),
						esc_attr( $class ),
						esc_html( $label )
					);
				}
				?>
			</nav>

			<div class="mkss-content">
				<?php
				switch ( $active_tab ) {
					case 'dashboard':
						$this->render_dashboard();
						break;
					case 'firewall':
						$this->render_firewall();
						break;
					case 'login':
						$this->render_login();
						break;
					case 'hardening':
						$this->render_hardening();
						break;
					case 'files':
						$this->render_files();
						break;
					case 'geo':
						$this->render_geo();
						break;
					case 'notify':
						$this->render_notify();
						break;
					case 'activity':
						$this->render_activity();
						break;
					case 'blocked':
						$this->render_blocked();
						break;
				}
				?>
			</div>
		</div>
		<?php
	}

	/* ---------------------------------------------------------------
	 * TAB RENDERERS
	 * ------------------------------------------------------------- */

	private function render_dashboard(): void {
		$last_check  = get_option( 'mkss_last_file_check', '' );
		$last_result = get_option( 'mkss_last_file_check_result', [] );
		$log_counts  = $this->get_log_counts_24h();
		?>
		<div class="mkss-dashboard-grid">

			<div class="mkss-card mkss-card-<?php echo ( ! empty( $last_result['ok'] ) ) ? 'ok' : ( empty( $last_result ) ? 'neutral' : 'warn' ); ?>">
				<h3><?php esc_html_e( 'File Integrity', 'mk-security-shield' ); ?></h3>
				<?php if ( empty( $last_result ) ) : ?>
					<p><?php esc_html_e( 'No scan run yet.', 'mk-security-shield' ); ?></p>
				<?php elseif ( ! empty( $last_result['errors'] ) ) : ?>
					<p class="mkss-warn"><?php echo esc_html( implode( ' ', $last_result['errors'] ) ); ?></p>
				<?php elseif ( $last_result['ok'] ) : ?>
					<p class="mkss-ok">✅ <?php esc_html_e( 'All core files intact.', 'mk-security-shield' ); ?></p>
				<?php else : ?>
					<p class="mkss-warn">⚠️ <?php echo esc_html( count( $last_result['issues'] ) ); ?> <?php esc_html_e( 'issue(s) found.', 'mk-security-shield' ); ?></p>
				<?php endif; ?>
				<?php if ( $last_check ) : ?>
					<p class="mkss-sub"><?php esc_html_e( 'Last check:', 'mk-security-shield' ); ?> <?php echo esc_html( $last_check ); ?></p>
				<?php endif; ?>
				<form method="post" action="">
					<?php wp_nonce_field( 'mkss_run_file_check' ); ?>
					<button type="submit" name="mkss_run_file_check" value="1" class="button button-secondary mkss-scan-btn">
						<?php esc_html_e( 'Run Scan Now', 'mk-security-shield' ); ?>
					</button>
				</form>
			</div>

			<div class="mkss-card">
				<h3><?php esc_html_e( 'Last 24 Hours', 'mk-security-shield' ); ?></h3>
				<ul class="mkss-stats">
					<li>🔐 <?php echo esc_html( $log_counts['login_failed'] ); ?> <?php esc_html_e( 'Failed logins', 'mk-security-shield' ); ?></li>
					<li>🚫 <?php echo esc_html( $log_counts['ip_blocked'] ); ?> <?php esc_html_e( 'IPs blocked', 'mk-security-shield' ); ?></li>
					<li>🔥 <?php echo esc_html( $log_counts['firewall_block'] ); ?> <?php esc_html_e( 'Firewall blocks', 'mk-security-shield' ); ?></li>
					<li>✅ <?php echo esc_html( $log_counts['login_success'] ); ?> <?php esc_html_e( 'Successful logins', 'mk-security-shield' ); ?></li>
				</ul>
			</div>

			<div class="mkss-card">
				<h3><?php esc_html_e( 'Plugin Status', 'mk-security-shield' ); ?></h3>
				<ul class="mkss-stats">
					<li>🔥 <?php esc_html_e( 'Firewall:', 'mk-security-shield' ); ?> <strong><?php echo get_option( 'mkss_block_sql_injection', true ) ? '✅ ON' : '❌ OFF'; ?></strong></li>
					<li>🔐 <?php esc_html_e( 'Login Protection:', 'mk-security-shield' ); ?> <strong>✅ ON</strong></li>
					<li>📁 <?php esc_html_e( 'File Monitor:', 'mk-security-shield' ); ?> <strong>✅ ON</strong></li>
					<li>🌍 <?php esc_html_e( 'Geo Block:', 'mk-security-shield' ); ?> <strong><?php echo get_option( 'mkss_geo_restriction_enabled', false ) ? '✅ ON' : '⬜ OFF'; ?></strong></li>
				</ul>
			</div>

			<div class="mkss-card">
				<h3><?php esc_html_e( 'Quick Info', 'mk-security-shield' ); ?></h3>
				<ul class="mkss-stats">
					<li>🌐 <?php esc_html_e( 'PHP:', 'mk-security-shield' ); ?> <strong><?php echo esc_html( PHP_VERSION ); ?></strong></li>
					<li>⚙️ <?php esc_html_e( 'WordPress:', 'mk-security-shield' ); ?> <strong><?php echo esc_html( get_bloginfo( 'version' ) ); ?></strong></li>
					<li>🔒 <?php esc_html_e( 'HTTPS:', 'mk-security-shield' ); ?> <strong><?php echo is_ssl() ? '✅' : '⚠️ No'; ?></strong></li>
					<li>🛡 <?php esc_html_e( 'Plugin:', 'mk-security-shield' ); ?> <strong>v<?php echo esc_html( MKSS_VERSION ); ?></strong></li>
				</ul>
			</div>

		</div>
		<?php
	}

	private function render_firewall(): void {
		?>
		<form id="mkss-form-firewall" class="mkss-settings-form">
			<h2><?php esc_html_e( 'Web Application Firewall', 'mk-security-shield' ); ?></h2>

			<table class="form-table">
				<?php
				$this->toggle_row( 'mkss_block_sql_injection', __( 'Block SQL Injection', 'mk-security-shield' ), __( 'Block common SQL injection patterns in URLs and query strings.', 'mk-security-shield' ) );
				$this->toggle_row( 'mkss_block_xss', __( 'Block XSS Attacks', 'mk-security-shield' ), __( 'Block cross-site scripting attempts in request data.', 'mk-security-shield' ) );
				$this->toggle_row( 'mkss_block_directory_traversal', __( 'Block Directory Traversal', 'mk-security-shield' ), __( 'Prevent <code>../</code> path traversal attacks.', 'mk-security-shield' ) );
				$this->toggle_row( 'mkss_block_bad_bots', __( 'Block Malicious Bots', 'mk-security-shield' ), __( 'Block known scanner user-agents: sqlmap, nikto, masscan, etc.', 'mk-security-shield' ) );
				$this->toggle_row( 'mkss_block_xmlrpc', __( 'Disable XML-RPC', 'mk-security-shield' ), __( 'Block all XML-RPC access (recommended unless you use Jetpack).', 'mk-security-shield' ) );
				$this->toggle_row( 'mkss_block_user_enum', __( 'Block User Enumeration', 'mk-security-shield' ), __( 'Prevent <code>?author=1</code> username discovery.', 'mk-security-shield' ) );
				$this->toggle_row( 'mkss_disable_pingback', __( 'Disable Pingback', 'mk-security-shield' ), __( 'Remove X-Pingback header and disable pingback functionality.', 'mk-security-shield' ) );
				$this->toggle_row( 'mkss_enable_rest_api_protection', __( 'Restrict REST API', 'mk-security-shield' ), __( 'Require authentication for all REST API requests (may break some plugins).', 'mk-security-shield' ) );
				?>
			</table>

			<?php $this->save_button( 'firewall' ); ?>
		</form>
		<?php
	}

	private function render_login(): void {
		$max      = (int) get_option( 'mkss_max_login_attempts', 5 );
		$duration = (int) get_option( 'mkss_lockout_duration', 30 );
		?>
		<form id="mkss-form-login" class="mkss-settings-form">
			<h2><?php esc_html_e( 'Login Protection', 'mk-security-shield' ); ?></h2>

			<table class="form-table">
				<tr>
					<th><?php esc_html_e( 'Max Login Attempts', 'mk-security-shield' ); ?></th>
					<td>
						<input type="number" name="mkss_max_login_attempts" value="<?php echo esc_attr( $max ); ?>" min="1" max="20" class="small-text" />
						<p class="description"><?php esc_html_e( 'Number of failures before IP is locked out.', 'mk-security-shield' ); ?></p>
					</td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Lockout Duration (minutes)', 'mk-security-shield' ); ?></th>
					<td>
						<input type="number" name="mkss_lockout_duration" value="<?php echo esc_attr( $duration ); ?>" min="1" max="10080" class="small-text" />
						<p class="description"><?php esc_html_e( 'How long to block an IP after too many failures.', 'mk-security-shield' ); ?></p>
					</td>
				</tr>
				<?php
				$this->toggle_row( 'mkss_hide_login_errors', __( 'Hide Login Errors', 'mk-security-shield' ), __( 'Replace specific login errors with a generic message.', 'mk-security-shield' ) );
				$this->toggle_row( 'mkss_notify_on_login_fail', __( 'Email on Repeated Failures', 'mk-security-shield' ), __( 'Send an email alert when repeated login failures are detected.', 'mk-security-shield' ) );
				?>
			</table>

			<?php $this->save_button( 'login' ); ?>
		</form>
		<?php
	}

	private function render_hardening(): void {
		?>
		<form id="mkss-form-hardening" class="mkss-settings-form">
			<h2><?php esc_html_e( 'WordPress Hardening', 'mk-security-shield' ); ?></h2>

			<table class="form-table">
				<?php
				$this->toggle_row( 'mkss_remove_wp_version', __( 'Remove WordPress Version', 'mk-security-shield' ), __( 'Remove the WP version from head, RSS feed, and footer.', 'mk-security-shield' ) );
				$this->toggle_row( 'mkss_disable_file_editor', __( 'Disable Theme/Plugin Editor', 'mk-security-shield' ), __( 'Prevent editing theme/plugin files from wp-admin.', 'mk-security-shield' ) );
				?>
			</table>

			<p class="description"><?php esc_html_e( 'Additional hardening (HTTP security headers, noindex on login, application passwords disabled) are always enabled.', 'mk-security-shield' ); ?></p>

			<?php $this->save_button( 'hardening' ); ?>
		</form>
		<?php
	}

	private function render_files(): void {
		$exclusions = (array) get_option( 'mkss_security_exclusions', [] );
		?>
		<form id="mkss-form-files" class="mkss-settings-form">
			<h2><?php esc_html_e( 'File Integrity Monitor', 'mk-security-shield' ); ?></h2>

			<table class="form-table">
				<?php $this->toggle_row( 'mkss_notify_on_file_change', __( 'Email on File Change', 'mk-security-shield' ), __( 'Send email alert when core file modifications are detected.', 'mk-security-shield' ) ); ?>
				<tr>
					<th><?php esc_html_e( 'Security Exclusions', 'mk-security-shield' ); ?></th>
					<td>
						<textarea name="mkss_security_exclusions" rows="6" cols="40" class="large-text code"><?php echo esc_textarea( implode( "\n", $exclusions ) ); ?></textarea>
						<p class="description">
							<?php esc_html_e( 'Files intentionally removed for security (one per line). These will never trigger a missing-file alert.', 'mk-security-shield' ); ?><br>
							<strong><?php esc_html_e( 'Missing-only exclusions (present files are still verified):', 'mk-security-shield' ); ?></strong> readme.html, license.txt, wp-config-sample.php
						</p>
					</td>
				</tr>
			</table>

			<?php $this->save_button( 'files' ); ?>
		</form>
		<?php
	}

	private function render_geo(): void {
		$allowed  = (array) get_option( 'mkss_geo_allowed_countries', [] );
		$blocked  = (array) get_option( 'mkss_geo_blocked_countries', [] );
		$mode     = get_option( 'mkss_geo_mode', 'blocklist' );
		?>
		<form id="mkss-form-geo" class="mkss-settings-form">
			<h2><?php esc_html_e( 'Geo Restriction', 'mk-security-shield' ); ?></h2>

			<table class="form-table">
				<?php $this->toggle_row( 'mkss_geo_restriction_enabled', __( 'Enable Geo Restriction', 'mk-security-shield' ), __( 'Block or allow visitors based on country.', 'mk-security-shield' ) ); ?>
				<?php $this->toggle_row( 'mkss_geo_allow_verified_ai', __( 'Allow Verified AI Browsing', 'mk-security-shield' ), __( 'Allow Claude-User, Claude-SearchBot, ChatGPT-User and OAI-SearchBot on public GET/HEAD pages after checking official IP ranges. Firewall and login protections still apply. Training crawlers are not included. Unknown countries are allowed if geolocation is unavailable.', 'mk-security-shield' ) ); ?>
				<tr>
					<th><?php esc_html_e( 'Mode', 'mk-security-shield' ); ?></th>
					<td>
						<select name="mkss_geo_mode">
							<option value="blocklist" <?php selected( $mode, 'blocklist' ); ?>><?php esc_html_e( 'Blocklist — block specific countries', 'mk-security-shield' ); ?></option>
							<option value="allowlist" <?php selected( $mode, 'allowlist' ); ?>><?php esc_html_e( 'Allowlist — only allow specific countries', 'mk-security-shield' ); ?></option>
						</select>
					</td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Blocked Countries', 'mk-security-shield' ); ?></th>
					<td>
						<textarea name="mkss_geo_blocked_countries" rows="5" cols="30" class="code"><?php echo esc_textarea( implode( "\n", $blocked ) ); ?></textarea>
						<p class="description"><?php esc_html_e( 'Two-letter country codes, one per line (e.g. CN, RU, KP).', 'mk-security-shield' ); ?></p>
					</td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Allowed Countries', 'mk-security-shield' ); ?></th>
					<td>
						<textarea name="mkss_geo_allowed_countries" rows="5" cols="30" class="code"><?php echo esc_textarea( implode( "\n", $allowed ) ); ?></textarea>
						<p class="description"><?php esc_html_e( 'Used in Allowlist mode — only these countries can access the site.', 'mk-security-shield' ); ?></p>
					</td>
				</tr>
			</table>

			<?php $this->save_button( 'geo' ); ?>
		</form>
		<?php
	}

	private function render_notify(): void {
		$email   = get_option( 'mkss_notify_email', get_bloginfo( 'admin_email' ) );
		$slack   = get_option( 'mkss_notify_slack_webhook', '' );
		?>
		<form id="mkss-form-notify" class="mkss-settings-form">
			<h2><?php esc_html_e( 'Notifications', 'mk-security-shield' ); ?></h2>

			<table class="form-table">
				<tr>
					<th><?php esc_html_e( 'Alert Email', 'mk-security-shield' ); ?></th>
					<td>
						<input type="email" name="mkss_notify_email" value="<?php echo esc_attr( $email ); ?>" class="regular-text" />
						<p class="description"><?php esc_html_e( 'Security alerts will be sent here.', 'mk-security-shield' ); ?></p>
					</td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Slack Webhook URL', 'mk-security-shield' ); ?></th>
					<td>
						<input type="url" name="mkss_notify_slack_webhook" value="<?php echo esc_attr( $slack ); ?>" class="regular-text" placeholder="https://hooks.slack.com/services/..." />
						<p class="description"><?php esc_html_e( 'Optional: paste your Slack Incoming Webhook URL for real-time alerts.', 'mk-security-shield' ); ?></p>
					</td>
				</tr>
			</table>

			<?php $this->save_button( 'notify' ); ?>
		</form>
		<?php
	}

	private function render_activity(): void {
		$min_sev = isset( $_GET['sev'] ) ? (int) $_GET['sev'] : -1; // phpcs:ignore
		$logs    = MKSS_Activity_Log::get_logs( 100, '', $min_sev );
		$sev_labels = [ 0 => 'Info', 1 => 'Low', 2 => 'High', 3 => 'Critical' ];
		$sev_colors = [ 0 => '#aaa', 1 => '#f39c12', 2 => '#e67e22', 3 => '#e74c3c' ];
		?>
		<h2><?php esc_html_e( 'Activity Log', 'mk-security-shield' ); ?></h2>
		<p>
			<?php esc_html_e( 'Filter:', 'mk-security-shield' ); ?>
			<?php foreach ( [ -1 => 'All', 2 => 'High+', 3 => 'Critical' ] as $v => $l ) : ?>
				<a href="<?php echo esc_url( add_query_arg( [ 'tab' => 'activity', 'sev' => $v ] ) ); ?>" class="button button-small <?php echo $min_sev === $v ? 'button-primary' : ''; ?>"><?php echo esc_html( $l ); ?></a>
			<?php endforeach; ?>
		</p>
		<?php if ( empty( $logs ) ) : ?>
			<p><?php esc_html_e( 'No log entries found.', 'mk-security-shield' ); ?></p>
		<?php else : ?>
			<table class="wp-list-table widefat fixed striped mkss-log-table">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Time', 'mk-security-shield' ); ?></th>
						<th><?php esc_html_e( 'Event', 'mk-security-shield' ); ?></th>
						<th><?php esc_html_e( 'Description', 'mk-security-shield' ); ?></th>
						<th><?php esc_html_e( 'IP', 'mk-security-shield' ); ?></th>
						<th><?php esc_html_e( 'Severity', 'mk-security-shield' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $logs as $log ) : ?>
					<tr>
						<td><?php echo esc_html( $log['created_at'] ); ?></td>
						<td><code><?php echo esc_html( $log['event_type'] ); ?></code></td>
						<td><?php echo esc_html( $log['description'] ); ?></td>
						<td><?php echo esc_html( $log['ip_address'] ); ?></td>
						<td>
							<span style="color:<?php echo esc_attr( $sev_colors[ $log['severity'] ] ?? '#aaa' ); ?>; font-weight:bold;">
								<?php echo esc_html( $sev_labels[ $log['severity'] ] ?? '?' ); ?>
							</span>
						</td>
					</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
		<?php
	}

	private function render_blocked(): void {
		global $wpdb;
		$table = $wpdb->prefix . 'mkss_ip_blocks';
		$rows  = $wpdb->get_results( "SELECT * FROM `{$table}` WHERE blocked_until > NOW() ORDER BY id DESC LIMIT 100", ARRAY_A ); // phpcs:ignore
		?>
		<h2><?php esc_html_e( 'Currently Blocked IPs', 'mk-security-shield' ); ?></h2>
		<?php if ( empty( $rows ) ) : ?>
			<p><?php esc_html_e( 'No IPs currently blocked.', 'mk-security-shield' ); ?></p>
		<?php else : ?>
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'IP Address', 'mk-security-shield' ); ?></th>
						<th><?php esc_html_e( 'Reason', 'mk-security-shield' ); ?></th>
						<th><?php esc_html_e( 'Blocked Until', 'mk-security-shield' ); ?></th>
						<th><?php esc_html_e( 'Attempts', 'mk-security-shield' ); ?></th>
						<th><?php esc_html_e( 'Action', 'mk-security-shield' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $rows as $row ) : ?>
					<tr>
						<td><strong><?php echo esc_html( $row['ip_address'] ); ?></strong></td>
						<td><?php echo esc_html( $row['reason'] ); ?></td>
						<td><?php echo esc_html( $row['blocked_until'] ); ?></td>
						<td><?php echo esc_html( $row['attempts'] ); ?></td>
						<td>
							<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=mkss_unlock_ip&ip=' . urlencode( $row['ip_address'] ) ), 'mkss_unlock_ip' ) ); ?>" class="button button-small">
								<?php esc_html_e( 'Unblock', 'mk-security-shield' ); ?>
							</a>
						</td>
					</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
		<?php
	}

	/* ---------------------------------------------------------------
	 * HELPERS
	 * ------------------------------------------------------------- */

	private function toggle_row( string $option, string $label, string $desc ): void {
		$val = get_option( $option, ! in_array( $option, [ 'mkss_geo_restriction_enabled', 'mkss_enable_rest_api_protection' ], true ) );
		?>
		<tr>
			<th><?php echo esc_html( $label ); ?></th>
			<td>
				<label class="mkss-toggle">
					<input type="checkbox" name="<?php echo esc_attr( $option ); ?>" value="1" <?php checked( $val, true ); ?> />
					<span class="mkss-toggle-slider"></span>
				</label>
				<p class="description"><?php echo wp_kses_post( $desc ); ?></p>
			</td>
		</tr>
		<?php
	}

	private function save_button( string $section ): void {
		?>
		<p class="submit">
			<button type="button" class="button button-primary mkss-save-btn" data-section="<?php echo esc_attr( $section ); ?>">
				<?php esc_html_e( 'Save Settings', 'mk-security-shield' ); ?>
			</button>
			<span class="mkss-save-msg" style="display:none;margin-left:12px;color:green;font-weight:bold;"></span>
		</p>
		<?php
	}

	private function get_log_counts_24h(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'mkss_activity_log';
		$types = [ 'login_failed', 'ip_blocked', 'firewall_block', 'login_success' ];
		$out   = array_fill_keys( $types, 0 );

		$rows = $wpdb->get_results( // phpcs:ignore
			"SELECT event_type, COUNT(*) as cnt FROM `{$table}` WHERE created_at >= NOW() - INTERVAL 1 DAY GROUP BY event_type",
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			if ( isset( $out[ $row['event_type'] ] ) ) {
				$out[ $row['event_type'] ] = (int) $row['cnt'];
			}
		}
		return $out;
	}
}
