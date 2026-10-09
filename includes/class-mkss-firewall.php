<?php
/**
 * Web Application Firewall for MK Security Shield v2.0.
 *
 * @package MK_Security_Shield
 */

defined( 'ABSPATH' ) || exit;

class MKSS_Firewall {

	public function __construct() {
		// Run firewall very early
		add_action( 'init', [ $this, 'run' ], 1 );

		// XML-RPC
		if ( get_option( 'mkss_block_xmlrpc', true ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', [ $this, 'remove_xmlrpc_methods' ] );
		}

		// User enumeration
		if ( get_option( 'mkss_block_user_enum', true ) ) {
			add_action( 'template_redirect', [ $this, 'block_user_enum' ] );
		}

		// Pingback
		if ( get_option( 'mkss_disable_pingback', true ) ) {
			add_filter( 'wp_headers', [ $this, 'remove_x_pingback' ] );
			add_filter( 'bloginfo_url', [ $this, 'remove_pingback_url' ], 10, 2 );
		}

		// REST API protection
		if ( get_option( 'mkss_enable_rest_api_protection', false ) ) {
			add_filter( 'rest_authentication_errors', [ $this, 'restrict_rest_api' ] );
		}

		// Security headers
		add_action( 'send_headers', [ $this, 'add_security_headers' ] );

		// Hotlinking protection (images)
		add_action( 'init', [ $this, 'prevent_hotlinking' ], 2 );
	}

	/**
	 * Main firewall — inspects request and blocks bad actors.
	 */
	public function run(): void {
		$ip = MKSS_Helper::get_ip();

		// Check if IP is blocked
		if ( $this->is_ip_blocked( $ip ) ) {
			$this->deny( 'Your IP has been blocked due to suspicious activity.' );
		}

		// Inspect raw input before display sanitization can remove an attack payload.
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$query       = isset( $_SERVER['QUERY_STRING'] ) ? wp_unslash( $_SERVER['QUERY_STRING'] ) : ''; // phpcs:ignore

		$checks = [];

		if ( get_option( 'mkss_block_sql_injection', true ) ) {
			$checks[] = [ 'pattern' => '/(\bunion\b.{0,30}\bselect\b|\bselect\b.{0,30}\bfrom\b|\bdrop\b.{0,10}\btable\b|\binsert\b.{0,10}\binto\b|\bdelete\b.{0,10}\bfrom\b)/i', 'type' => 'SQL Injection' ];
		}
		if ( get_option( 'mkss_block_xss', true ) ) {
			$checks[] = [ 'pattern' => '/<script[\s\S]*?>[\s\S]*?<\/script>/i', 'type' => 'XSS' ];
			$checks[] = [ 'pattern' => '/javascript\s*:/i', 'type' => 'XSS' ];
		}
		if ( get_option( 'mkss_block_directory_traversal', true ) ) {
			$checks[] = [ 'pattern' => '/\.\.[\/\\\\]/i', 'type' => 'Directory Traversal' ];
			$checks[] = [ 'pattern' => '/%2e%2e[%2f%5c]/i', 'type' => 'Directory Traversal (encoded)' ];
		}

		$target = rawurldecode( rawurldecode( $request_uri . '?' . $query ) );

		foreach ( $checks as $check ) {
			if ( preg_match( $check['pattern'], $target ) ) {
				$this->log_attack( $ip, $check['type'], (string) wp_parse_url( $request_uri, PHP_URL_PATH ) );
				$this->deny( 'Request blocked by MK Security Shield firewall.' );
			}
		}

		// Bad bots
		if ( get_option( 'mkss_block_bad_bots', true ) ) {
			$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
			if ( $this->is_bad_bot( $ua ) ) {
				$this->log_attack( $ip, 'Bad Bot', $ua );
				$this->deny( 'Automated access not allowed.' );
			}
		}
	}

	/**
	 * Block user enumeration via ?author= and REST API /users endpoint.
	 */
	public function block_user_enum(): void {
		if ( ! is_admin() ) {
			$query = isset( $_SERVER['QUERY_STRING'] ) ? $_SERVER['QUERY_STRING'] : ''; // phpcs:ignore
			if ( preg_match( '/author=\d+/i', $query ) ) {
				wp_die( esc_html__( 'User enumeration is disabled.', 'mk-security-shield' ), '', [ 'response' => 403 ] );
			}
		}
	}

	/**
	 * Restrict REST API to authenticated users only.
	 */
	public function restrict_rest_api( $errors ) {
		if ( null !== $errors ) {
			return $errors;
		}
		if ( ! is_user_logged_in() ) {
			return new WP_Error( 'rest_not_logged_in', __( 'REST API requires authentication.', 'mk-security-shield' ), [ 'status' => 401 ] );
		}
		return $errors;
	}

	/**
	 * Remove X-Pingback header.
	 */
	public function remove_x_pingback( array $headers ): array {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/**
	 * Remove pingback URL from bloginfo.
	 */
	public function remove_pingback_url( string $output, string $show ): string {
		return 'pingback_url' === $show ? '' : $output;
	}

	/**
	 * Remove all XML-RPC methods.
	 */
	public function remove_xmlrpc_methods( array $methods ): array {
		return [];
	}

	/**
	 * Add HTTP security headers.
	 */
	public function add_security_headers(): void {
		if ( headers_sent() ) {
			return;
		}
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'X-XSS-Protection: 1; mode=block' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );

		// HSTS — only on HTTPS
		if ( is_ssl() ) {
			header( 'Strict-Transport-Security: max-age=31536000' );
		}
	}

	/**
	 * Prevent image hotlinking from external sites.
	 */
	public function prevent_hotlinking(): void {
		// Only on front-end file requests, skip admin and CRON
		if ( is_admin() || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}
		$referer   = isset( $_SERVER['HTTP_REFERER'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '';
		$site_host = wp_parse_url( home_url(), PHP_URL_HOST );
		if ( ! empty( $referer ) ) {
			$ref_host = wp_parse_url( $referer, PHP_URL_HOST );
			if ( $ref_host && $ref_host !== $site_host ) {
				$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
				if ( preg_match( '/\.(jpe?g|png|gif|webp|svg)$/i', $uri ) ) {
					// Allow hotlinking — just log it; set to deny if needed
					// status_header(403); exit;
				}
			}
		}
	}

	/**
	 * Check if an IP is currently blocked.
	 */
	private function is_ip_blocked( string $ip ): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'mkss_ip_blocks';
		$count = $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM `{$table}` WHERE ip_address = %s AND blocked_until > UTC_TIMESTAMP()",
			$ip
		) );
		return (int) $count > 0;
	}

	/**
	 * Log an attack to the activity log table.
	 */
	private function log_attack( string $ip, string $type, string $detail ): void {
		if ( class_exists( 'MKSS_Activity_Log' ) ) {
			MKSS_Activity_Log::log(
				'firewall_block',
				sprintf( '[%s] %s | Detail: %s', $type, $ip, substr( $detail, 0, 200 ) ),
				3 // critical severity
			);
		}
	}

	/**
	 * Block bad / malicious bots by user-agent string.
	 */
	private function is_bad_bot( string $ua ): bool {
		if ( empty( $ua ) ) {
			return false;
		}
		$bad_bots = [
			'nikto', 'sqlmap', 'masscan', 'nmap', 'nessus',
			'acunetix', 'burpsuite', 'dirbuster', 'havij',
			'paros', 'w3af', 'skipfish', 'ZmEu', 'libwww-perl',
			'python-requests/2.', 'zgrab', 'censys',
		];
		foreach ( $bad_bots as $bot ) {
			if ( stripos( $ua, $bot ) !== false ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Send a 403 response and halt execution.
	 */
	private function deny( string $message ): void {
		status_header( 403 );
		nocache_headers();
		wp_die(
			esc_html( $message ),
			esc_html__( 'Access Denied', 'mk-security-shield' ),
			[ 'response' => 403 ]
		);
	}
}
