<?php
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

	public static function get_client_ip() { return self::get_ip(); }

	public static function send_alert( string $subject, string $body ): void {
		$to = MKSS_Settings::instance()->get( 'notify_email', get_option( 'admin_email' ) );
		wp_mail( $to, '[' . wp_parse_url( home_url(), PHP_URL_HOST ) . '] ' . $subject, $body, [ 'Content-Type: text/html; charset=UTF-8' ] );
	}
}
