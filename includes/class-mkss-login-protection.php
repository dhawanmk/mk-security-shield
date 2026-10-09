<?php
/**
 * Login Protection for MK Security Shield v2.0.
 *
 * @package MK_Security_Shield
 */

defined( 'ABSPATH' ) || exit;

class MKSS_Login_Protection {

	public function __construct() {
		add_action( 'wp_login_failed', [ $this, 'on_login_failed' ] );
		add_filter( 'authenticate', [ $this, 'check_lockout' ], 30, 3 );
		add_action( 'wp_login', [ $this, 'on_login_success' ], 10, 2 );
		add_action( 'wp_logout', [ $this, 'on_logout' ] );

		// Hide login error messages
		if ( get_option( 'mkss_hide_login_errors', true ) ) {
			add_filter( 'login_errors', [ $this, 'hide_login_errors' ] );
		}

		// Admin-triggered unlock
		add_action( 'admin_post_mkss_unlock_ip', [ $this, 'admin_unlock_ip' ] );
	}

	/**
	 * Handle a failed login attempt.
	 */
	public function on_login_failed( string $username ): void {
		$ip       = MKSS_Helper::get_ip();
		$max      = (int) get_option( 'mkss_max_login_attempts', 5 );
		$duration = (int) get_option( 'mkss_lockout_duration', 30 );

		$key      = 'mkss_fails_' . md5( $ip );
		$attempts = (int) get_transient( $key );
		$attempts++;

		if ( $attempts >= $max ) {
			$this->lock_ip( $ip, $duration, $username );
		} else {
			set_transient( $key, $attempts, $duration * MINUTE_IN_SECONDS );
		}

		// Log
		MKSS_Activity_Log::log(
			'login_failed',
			"Failed login for '{$username}' from {$ip} (attempt {$attempts}/{$max})",
			1
		);

		// Notify on repeated fails
		if ( $attempts >= max( 3, intval( $max / 2 ) ) && get_option( 'mkss_notify_on_login_fail', true ) ) {
			MKSS_Helper::send_alert(
				'Repeated Login Failures',
				"<p>Multiple failed login attempts detected.</p>
				<ul>
					<li><strong>Username tried:</strong> " . esc_html( $username ) . "</li>
					<li><strong>IP Address:</strong> " . esc_html( $ip ) . "</li>
					<li><strong>Attempt count:</strong> {$attempts}/{$max}</li>
				</ul>"
			);
		}
	}

	/**
	 * Block login if IP is locked out.
	 */
	public function check_lockout( $user, string $username, string $password ) {
		$ip = MKSS_Helper::get_ip();

		global $wpdb;
		$table = $wpdb->prefix . 'mkss_ip_blocks';
		$row   = $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM `{$table}` WHERE ip_address = %s AND blocked_until > UTC_TIMESTAMP()",
			$ip
		) );

		if ( $row ) {
			$remaining = human_time_diff( time(), strtotime( $row->blocked_until ) );
			return new WP_Error(
				'mkss_lockout',
				sprintf(
					/* translators: %s: time remaining */
					__( 'Too many failed login attempts. Try again in %s.', 'mk-security-shield' ),
					$remaining
				)
			);
		}

		return $user;
	}

	/**
	 * Log successful login.
	 */
	public function on_login_success( string $username, WP_User $user ): void {
		$ip = MKSS_Helper::get_ip();

		// Clear fail counter for this IP
		delete_transient( 'mkss_fails_' . md5( $ip ) );

		MKSS_Activity_Log::log(
			'login_success',
			"Successful login: '{$username}' from {$ip}",
			0
		);
	}

	/**
	 * Log logout event.
	 */
	public function on_logout(): void {
		$user = wp_get_current_user();
		if ( $user->exists() ) {
			MKSS_Activity_Log::log( 'logout', "User '{$user->user_login}' logged out from " . MKSS_Helper::get_ip(), 0 );
		}
	}

	/**
	 * Replace login error messages with a generic one.
	 */
	public function hide_login_errors( string $error ): string {
		return __( 'Incorrect login details.', 'mk-security-shield' );
	}

	/**
	 * Lock an IP address for a given number of minutes.
	 */
	private function lock_ip( string $ip, int $minutes, string $username ): void {
		global $wpdb;
		$table        = $wpdb->prefix . 'mkss_ip_blocks';
		$blocked_until = gmdate( 'Y-m-d H:i:s', time() + $minutes * MINUTE_IN_SECONDS );

		$wpdb->replace( $table, [
			'ip_address'    => $ip,
			'reason'        => "Too many failed logins for '{$username}'",
			'blocked_until' => $blocked_until,
			'attempts'      => (int) get_option( 'mkss_max_login_attempts', 5 ),
		], [ '%s', '%s', '%s', '%d' ] );

		MKSS_Activity_Log::log(
			'ip_blocked',
			"IP {$ip} blocked for {$minutes} minutes after repeated login failures for '{$username}'",
			2
		);

		MKSS_Helper::send_alert(
			'IP Address Blocked',
			"<p>An IP has been blocked after too many failed login attempts.</p>
			<ul>
				<li><strong>IP:</strong> " . esc_html( $ip ) . "</li>
				<li><strong>Username:</strong> " . esc_html( $username ) . "</li>
				<li><strong>Blocked until:</strong> " . esc_html( $blocked_until ) . "</li>
			</ul>
			<p><a href='" . esc_url( admin_url( 'admin.php?page=mk-security-shield&tab=activity' ) ) . "'>View Activity Log</a></p>"
		);
		MKSS_Helper::send_slack( "🚫 IP {$ip} blocked for {$minutes} min after failed logins for '{$username}'" );
	}

	/**
	 * Admin action to manually unlock an IP.
	 */
	public function admin_unlock_ip(): void {
		if ( ! current_user_can( 'manage_options' ) || ! isset( $_GET['ip'] ) ) {
			wp_die( 'Unauthorized' );
		}
		check_admin_referer( 'mkss_unlock_ip' );

		$ip = sanitize_text_field( wp_unslash( $_GET['ip'] ) );
		global $wpdb;
		$wpdb->delete( $wpdb->prefix . 'mkss_ip_blocks', [ 'ip_address' => $ip ] );
		delete_transient( 'mkss_fails_' . md5( $ip ) );

		MKSS_Activity_Log::log( 'ip_unblocked', "Admin manually unblocked IP: {$ip}", 0 );

		wp_safe_redirect( admin_url( 'admin.php?page=mk-security-shield&tab=activity&mkss_msg=ip_unlocked' ) );
		exit;
	}
}
