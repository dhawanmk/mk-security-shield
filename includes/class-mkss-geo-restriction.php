<?php
/**
 * Geo Restriction for MK Security Shield v2.0.
 *
 * @package MK_Security_Shield
 */

defined( 'ABSPATH' ) || exit;

class MKSS_Geo_Restriction {

	public function __construct() {
		if ( ! get_option( 'mkss_geo_enabled', false ) ) {
			return;
		}
		add_action( 'init', [ $this, 'check_visitor_country' ], 5 );
	}

	/**
	 * Check if the visitor's country is blocked or not allowed.
	 */
	public function check_visitor_country(): void {
		// Skip for admin, cron, REST API internal, login page
		if ( is_admin() || ( defined( 'DOING_CRON' ) && DOING_CRON ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return;
		}

		$ip      = MKSS_Helper::get_ip();
		$country = MKSS_Helper::get_country( $ip );

		if ( empty( $country ) ) {
			return; // Can't determine country — allow
		}

		$mode    = get_option( 'mkss_geo_mode', 'blocklist' );
		$blocked = $this->get_country_list( 'mkss_geo_blocked_countries' );
		$allowed = $this->get_country_list( 'mkss_geo_allowed_countries' );

		$should_block = false;

		if ( 'blocklist' === $mode && ! empty( $blocked ) ) {
			$should_block = in_array( strtoupper( $country ), $blocked, true );
		} elseif ( 'allowlist' === $mode && ! empty( $allowed ) ) {
			$should_block = ! in_array( strtoupper( $country ), $allowed, true );
		}

		if ( $should_block ) {
			MKSS_Activity_Log::log(
				'geo_block',
				"Access blocked for country '{$country}' from IP {$ip}",
				2
			);
			status_header( 403 );
			nocache_headers();
			wp_die(
				esc_html__( 'Access to this website is not available in your region.', 'mk-security-shield' ),
				esc_html__( 'Access Restricted', 'mk-security-shield' ),
				[ 'response' => 403 ]
			);
		}
	}

	/**
	 * Parse a newline/comma separated list of country codes from a DB option.
	 *
	 * @param string $option_name
	 * @return string[] Uppercase 2-letter country codes.
	 */
	private function get_country_list( string $option_name ): array {
		$raw = (string) get_option( $option_name, '' );
		if ( empty( $raw ) ) {
			return [];
		}
		// Split on newlines or commas
		$parts = preg_split( '/[\r\n,]+/', $raw );
		$codes = [];
		foreach ( $parts as $part ) {
			$code = strtoupper( trim( $part ) );
			if ( preg_match( '/^[A-Z]{2}$/', $code ) ) {
				$codes[] = $code;
			}
		}
		return array_unique( $codes );
	}
}
