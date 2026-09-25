<?php
/**
 * Helper utilities for MK Security Shield.
 *
 * @package MK_Security_Shield
 */

defined( 'ABSPATH' ) || exit;

class MKSS_Helper {

	/**
	 * Default plugin options for v2.0.
	 */
	public static function set_default_options(): void {
		$defaults = [
			// Login protection
			'mkss_max_login_attempts'      => 5,
			'mkss_lockout_duration'        => 30,        // minutes
			'mkss_enable_login_log'        => true,
			'mkss_enable_captcha'          => false,

			// Firewall
			'mkss_block_xmlrpc'            => true,
			'mkss_block_user_enum'         => true,
			'mkss_block_bad_bots'          => true,
			'mkss_block_sql_injection'     => true,
			'mkss_block_xss'               => true,
			'mkss_block_directory_traversal' => true,
			'mkss_enable_rest_api_protection' => false,

			// Hardening
			'mkss_remove_wp_version'       => true,
			'mkss_disable_file_editor'     => true,
			'mkss_disable_pingback'        => true,
			'mkss_hide_login_errors'       => true,
			'mkss_disable_directory_listing' => true,
			'mkss_remove_readme'           => false,    // user handles this manually

			// File monitor
			'mkss_enable_file_monitor'     => true,
			'mkss_file_monitor_email'      => get_option( 'admin_email' ),
			'mkss_security_exclusions'     => [
				'readme.html',
				'license.txt',
				'wp-config-sample.php',
			],

			// Geo restriction
			'mkss_enable_geo'              => false,
			'mkss_geo_allowed_countries'   => [ 'IN' ],
			'mkss_geo_mode'                => 'whitelist',

			// Notifications
			'mkss_notify_on_login_fail'    => true,
			'mkss_notify_on_file_change'   => true,
			'mkss_notify_on_new_admin'     => true,
			'mkss_notify_email'            => get_option( 'admin_email' ),
			'mkss_notify_slack_webhook'    => '',

			// 2FA
			'mkss_enable_2fa'              => false,
			'mkss_2fa_roles'               => [ 'administrator' ],
		];

		foreach ( $defaults as $key => $value ) {
			if ( false === get_option( $key ) ) {
				add_option( $key, $value );
			}
		}
	}

	/**
	 * Create custom DB tables for v2.0.
	 */
	public static function create_db_tables(): void {
		global $wpdb;
		$charset_collate = $wpdb->get_charset_collate();

		$sql_activity = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}mkss_activity_log (
			id            BIGINT(20)   UNSIGNED NOT NULL AUTO_INCREMENT,
			event_type    VARCHAR(60)  NOT NULL DEFAULT '',
			user_id       BIGINT(20)   UNSIGNED NOT NULL DEFAULT 0,
			ip_address    VARCHAR(45)  NOT NULL DEFAULT '',
			user_agent    TEXT,
			description   TEXT,
			severity      TINYINT(1)   NOT NULL DEFAULT 1,
			created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY   (id),
			KEY           event_type (event_type),
			KEY           ip_address (ip_address),
			KEY           severity (severity),
			KEY           created_at (created_at)
		) {$charset_collate};";

		$sql_ip_blocks = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}mkss_ip_blocks (
			id            BIGINT(20)   UNSIGNED NOT NULL AUTO_INCREMENT,
			ip_address    VARCHAR(45)  NOT NULL DEFAULT '',
			reason        VARCHAR(255) NOT NULL DEFAULT '',
			blocked_until DATETIME     NOT NULL,
			attempts      INT(11)      NOT NULL DEFAULT 0,
			created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY   (id),
			UNIQUE KEY    ip_address (ip_address)
		) {$charset_collate};";

		$sql_file_hashes = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}mkss_file_hashes (
			id            BIGINT(20)   UNSIGNED NOT NULL AUTO_INCREMENT,
			file_path     VARCHAR(512) NOT NULL DEFAULT '',
			file_hash     VARCHAR(64)  NOT NULL DEFAULT '',
			file_size     BIGINT(20)   UNSIGNED NOT NULL DEFAULT 0,
			checked_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY   (id),
			UNIQUE KEY    file_path (file_path(191))
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql_activity );
		dbDelta( $sql_ip_blocks );
		dbDelta( $sql_file_hashes );

		update_option( 'mkss_db_version', MKSS_DB_VERSION );
	}

	/**
	 * Get the real visitor IP address.
	 */
	public static function get_ip(): string {
		$headers = [
			'HTTP_CF_CONNECTING_IP',   // Cloudflare
			'HTTP_X_REAL_IP',
			'HTTP_X_FORWARDED_FOR',
			'REMOTE_ADDR',
		];

		foreach ( $headers as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$ip = trim( explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) ) )[0] );
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}
		return '0.0.0.0';
	}

	/**
	 * Get country code for an IP via ipapi.co (free, no key needed).
	 */
	public static function get_country( string $ip ): string {
		if ( '127.0.0.1' === $ip || '::1' === $ip ) {
			return 'LOCAL';
		}
		$cached = get_transient( 'mkss_geo_' . md5( $ip ) );
		if ( $cached ) {
			return $cached;
		}
		$response = wp_remote_get(
			'https://ipapi.co/' . rawurlencode( $ip ) . '/country/',
			[ 'timeout' => 3, 'user-agent' => 'MK-Security-Shield/' . MKSS_VERSION ]
		);
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return 'XX';
		}
		$country = strtoupper( trim( wp_remote_retrieve_body( $response ) ) );
		if ( preg_match( '/^[A-Z]{2}$/', $country ) ) {
			set_transient( 'mkss_geo_' . md5( $ip ), $country, DAY_IN_SECONDS );
			return $country;
		}
		return 'XX';
	}

	/**
	 * Send security email notification.
	 */
	public static function send_alert( string $subject, string $body, string $to = '' ): void {
		if ( empty( $to ) ) {
			$to = get_option( 'mkss_notify_email', get_option( 'admin_email' ) );
		}
		$site    = get_bloginfo( 'name' );
		$headers = [ 'Content-Type: text/html; charset=UTF-8' ];
		$html    = sprintf(
			'<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;border:1px solid #ddd;border-radius:6px;overflow:hidden;">
				<div style="background:#c0392b;padding:16px 24px;">
					<h2 style="color:#fff;margin:0;">🔒 MK Security Shield Alert</h2>
					<p style="color:#f8d7da;margin:4px 0 0;">Site: %s</p>
				</div>
				<div style="padding:24px;">
					<p>%s</p>
					<hr style="border:none;border-top:1px solid #eee;">
					<p style="color:#999;font-size:12px;">Time: %s &nbsp;|&nbsp; IP: %s</p>
				</div>
			</div>',
			esc_html( $site ),
			wp_kses_post( $body ),
			esc_html( current_time( 'mysql' ) ),
			esc_html( self::get_ip() )
		);
		wp_mail( $to, '[' . $site . '] ' . $subject, $html, $headers );
	}

	/**
	 * Send Slack notification if webhook is configured.
	 */
	public static function send_slack( string $message ): void {
		$webhook = get_option( 'mkss_notify_slack_webhook', '' );
		if ( empty( $webhook ) ) {
			return;
		}
		wp_remote_post( $webhook, [
			'body'    => wp_json_encode( [ 'text' => '🔒 *MK Security Shield* | ' . get_bloginfo( 'name' ) . "\n" . $message ] ),
			'headers' => [ 'Content-Type' => 'application/json' ],
			'timeout' => 5,
		] );
	}

	/**
	 * Check if current user is admin.
	 */
	public static function is_admin_user(): bool {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Sanitize and validate an option value.
	 */
	public static function sanitize_option( $value, string $type = 'text' ) {
		switch ( $type ) {
			case 'bool':
				return (bool) $value;
			case 'int':
				return absint( $value );
			case 'email':
				return sanitize_email( $value );
			case 'url':
				return esc_url_raw( $value );
			case 'array_text':
				if ( ! is_array( $value ) ) {
					return [];
				}
				return array_map( 'sanitize_text_field', $value );
			default:
				return sanitize_text_field( $value );
		}
	}
}
