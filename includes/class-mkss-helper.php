<?php
/**
 * Helper utilities for MK Security Shield.
 *
 * @package MK_Security_Shield
 */

defined( 'ABSPATH' ) || exit;

class MKSS_Helper {
	/** Cloudflare's published proxy ranges, verified 2026-10-09. */
	private const CLOUDFLARE_PROXIES = [
		'173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
		'141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
		'197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
		'104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22', '2400:cb00::/32',
		'2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
		'2a06:98c0::/29', '2c0f:f248::/32',
	];

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
			'mkss_geo_restriction_enabled' => false,
			'mkss_geo_allowed_countries'   => [ 'IN' ],
			'mkss_geo_blocked_countries'   => [],
			'mkss_geo_mode'                => 'blocklist',
			'mkss_geo_allow_verified_ai'   => true,

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

	/** Migrate legacy geo keys once; an explicit current setting wins. */
	public static function migrate_options(): void {
		if ( '2.1.0' === get_option( 'mkss_options_version' ) ) {
			return;
		}
		if ( null === get_option( 'mkss_geo_restriction_enabled', null ) ) {
			$enabled = get_option( 'mkss_geo_enabled', get_option( 'mkss_enable_geo', false ) );
			add_option( 'mkss_geo_restriction_enabled', (bool) $enabled );
		}
		$mode = get_option( 'mkss_geo_mode', 'blocklist' );
		if ( in_array( $mode, [ 'whitelist', 'blacklist' ], true ) ) {
			update_option( 'mkss_geo_mode', 'whitelist' === $mode ? 'allowlist' : 'blocklist' );
		}
		foreach ( [ 'mkss_geo_allowed_countries', 'mkss_geo_blocked_countries' ] as $key ) {
			update_option( $key, self::country_codes( get_option( $key, [] ) ) );
		}
		add_option( 'mkss_geo_allow_verified_ai', true );
		update_option( 'mkss_options_version', '2.1.0', false );
	}

	/** Accept legacy text lists and current arrays without array-to-string warnings. */
	public static function country_codes( $raw ): array {
		$parts = is_array( $raw ) ? $raw : preg_split( '/[\s,]+/', (string) $raw );
		$codes = [];
		foreach ( $parts as $part ) {
			if ( ! is_scalar( $part ) ) {
				continue;
			}
			$code = strtoupper( trim( (string) $part ) );
			if ( preg_match( '/^[A-Z]{2}$/D', $code ) && ! in_array( $code, [ 'XX', 'ZZ' ], true ) ) {
				$codes[] = $code;
			}
		}
		return array_values( array_unique( $codes ) );
	}

	/** Match IPv4/IPv6 networks; malformed or all-address prefixes are rejected. */
	public static function ip_in_cidr( string $ip, string $cidr ): bool {
		$parts = explode( '/', $cidr );
		$address = @inet_pton( $ip );
		$network = @inet_pton( $parts[0] );
		if ( false === $address || false === $network || strlen( $address ) !== strlen( $network ) || count( $parts ) > 2 ) {
			return false;
		}
		$bits = $parts[1] ?? (string) ( strlen( $address ) * 8 );
		if ( ! ctype_digit( $bits ) || (int) $bits < 1 || (int) $bits > strlen( $address ) * 8 ) {
			return false;
		}
		$bytes = intdiv( (int) $bits, 8 );
		$remaining = (int) $bits % 8;
		return substr( $address, 0, $bytes ) === substr( $network, 0, $bytes )
			&& ( 0 === $remaining || ( ord( $address[$bytes] ) & ( 255 << ( 8 - $remaining ) ) ) === ( ord( $network[$bytes] ) & ( 255 << ( 8 - $remaining ) ) ) );
	}

	/** Forwarded headers are authoritative only from explicitly trusted proxy peers. */
	public static function get_ip(): string {
		$peer = $_SERVER['REMOTE_ADDR'] ?? '';
		if ( ! is_string( $peer ) || ! filter_var( $peer, FILTER_VALIDATE_IP ) ) {
			return '0.0.0.0';
		}
		// Set these constants in wp-config.php using the host's documented proxy ranges/header.
		$ranges = defined( 'MKSS_TRUSTED_PROXIES' ) ? (array) MKSS_TRUSTED_PROXIES : self::CLOUDFLARE_PROXIES;
		$trusted = static function ( string $candidate ) use ( $ranges ): bool {
			foreach ( $ranges as $range ) {
				if ( is_string( $range ) && self::ip_in_cidr( $candidate, $range ) ) {
					return true;
				}
			}
			return false;
		};
		$header = defined( 'MKSS_CLIENT_IP_HEADER' ) ? MKSS_CLIENT_IP_HEADER : 'HTTP_CF_CONNECTING_IP';
		if ( ! $trusted( $peer ) || ! in_array( $header, [ 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR' ], true ) ) {
			return $peer;
		}
		$value = $_SERVER[$header] ?? '';
		if ( ! is_string( $value ) || strlen( $value ) > 2048 ) {
			return $peer;
		}
		$chain = array_map( 'trim', explode( ',', $value ) );
		if ( 'HTTP_X_FORWARDED_FOR' !== $header && count( $chain ) !== 1 ) {
			return $peer;
		}
		foreach ( array_reverse( $chain ) as $candidate ) {
			if ( ! filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
				return $peer;
			}
			if ( ! $trusted( $candidate ) ) {
				return $candidate;
			}
		}
		return $peer;
	}

	/**
	 * Get country code for an IP via ipapi.co (free, no key needed).
	 */
	public static function get_country( string $ip ): string {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return '';
		}
		$cached = get_transient( 'mkss_geo_' . md5( $ip ) );
		if ( 'XX' === $cached ) {
			return '';
		}
		if ( is_string( $cached ) && preg_match( '/^[A-Z]{2}$/D', $cached ) && ! in_array( $cached, [ 'XX', 'ZZ' ], true ) ) {
			return $cached;
		}
		$response = wp_remote_get(
			'https://ipapi.co/' . rawurlencode( $ip ) . '/country/',
			[ 'timeout' => 3, 'user-agent' => 'MK-Security-Shield/' . MKSS_VERSION ]
		);
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			set_transient( 'mkss_geo_' . md5( $ip ), 'XX', 5 * MINUTE_IN_SECONDS );
			return '';
		}
		$country = strtoupper( trim( wp_remote_retrieve_body( $response ) ) );
		if ( preg_match( '/^[A-Z]{2}$/D', $country ) && ! in_array( $country, [ 'XX', 'ZZ' ], true ) ) {
			set_transient( 'mkss_geo_' . md5( $ip ), $country, DAY_IN_SECONDS );
			return $country;
		}
		return '';
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
		if ( 'https' !== wp_parse_url( $webhook, PHP_URL_SCHEME ) || ! in_array( wp_parse_url( $webhook, PHP_URL_HOST ), [ 'hooks.slack.com', 'hooks.slack-gov.com' ], true ) ) {
			return;
		}
		wp_safe_remote_post( $webhook, [
			'body'    => wp_json_encode( [ 'text' => '🔒 *MK Security Shield* | ' . get_bloginfo( 'name' ) . "\n" . $message ] ),
			'headers' => [ 'Content-Type' => 'application/json' ],
			'timeout' => 5,
			'redirection' => 0,
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
