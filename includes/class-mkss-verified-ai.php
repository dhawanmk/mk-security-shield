<?php
/** Verified public AI browsing. This module grants no WordPress permissions. */
defined( 'ABSPATH' ) || exit;

class MKSS_Verified_AI {
	/** Official provider feeds; never accept a request-supplied feed URL. */
	private const FEEDS = [
		'ChatGPT-User'    => 'https://openai.com/chatgpt-user.json',
		'OAI-SearchBot'   => 'https://openai.com/searchbot.json',
		'Claude-User'     => 'https://claude.com/crawling/bots.json',
		'Claude-SearchBot'=> 'https://claude.com/crawling/bots.json',
	];

	public static function can_bypass_geo(): bool {
		if ( ! MKSS_Settings::instance()->get( 'geo_allow_verified_ai', true ) || ! self::is_public_read() ) {
			return false;
		}
		$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
		if ( ! is_string( $ua ) || strlen( $ua ) > 2048 ) {
			return false;
		}
		foreach ( self::FEEDS as $bot => $url ) {
			if ( ! preg_match( '/(?:^|[\s;(])' . preg_quote( $bot, '/' ) . '(?:\/|[\s;)]|$)/i', $ua ) ) {
				continue;
			}
			foreach ( self::get_prefixes( $url ) as $prefix ) {
				if ( MKSS_Helper::ip_in_cidr( MKSS_Helper::get_ip(), $prefix ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/** Exclude login, admin, API, scripts, encoded routes and authenticated actions. */
	private static function is_public_read(): bool {
		if ( ! in_array( $_SERVER['REQUEST_METHOD'] ?? '', [ 'GET', 'HEAD' ], true ) || is_admin() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return false;
		}
		if ( ! empty( $_SERVER['HTTP_AUTHORIZATION'] ) || ! empty( $_SERVER['PHP_AUTH_USER'] ) || ! empty( $_POST ) ) {
			return false;
		}
		$uri = $_SERVER['REQUEST_URI'] ?? '';
		$path = wp_parse_url( $uri, PHP_URL_PATH );
		$path = is_string( $path ) ? rawurldecode( rawurldecode( $path ) ) : null;
		if ( ! is_string( $path ) || preg_match( '/[%\\\\\x00-\x1f\x7f]|\.\./', $path ) ) {
			return false;
		}
		if ( preg_match( '~(?:^|/)(?:wp-admin|wp-json|wp-login\.php|xmlrpc\.php)(?:/|$)|\.php(?:/|$)~i', $path ) ) {
			return false;
		}
		// Query-based REST/MCP/OAuth routes and actions must follow normal geo/auth rules.
		foreach ( [ 'rest_route', 'action', '_wpnonce', 'oauth', 'code', 'mcp' ] as $key ) {
			if ( isset( $_GET[$key] ) ) {
				return false;
			}
		}
		return ! preg_match( '~(?:^|/)(?:mcp|oauth|oauth2)(?:/|$)~i', $path );
	}

	/** Six-hour positive cache and short failure cache, bounded HTTPS fetch, fail closed. */
	private static function get_prefixes( string $url ): array {
		$key = 'mkss_ai_ranges_' . md5( $url );
		$cached = get_transient( $key );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		$response = wp_safe_remote_get( $url, [ 'timeout' => 3, 'redirection' => 0, 'limit_response_size' => 262144 ] );
		$prefixes = [];
		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
			$data = json_decode( wp_remote_retrieve_body( $response ), true );
			foreach ( (array) ( $data['prefixes'] ?? [] ) as $entry ) {
				if ( ! is_array( $entry ) ) {
					continue;
				}
				foreach ( [ 'ipv4Prefix', 'ipv6Prefix' ] as $field ) {
					$prefix = $entry[$field] ?? '';
					if ( is_string( $prefix ) && strpos( $prefix, '/' ) !== false && MKSS_Helper::ip_in_cidr( explode( '/', $prefix )[0], $prefix ) ) {
						$prefixes[] = $prefix;
					}
				}
			}
		}
		set_transient( $key, $prefixes, empty( $prefixes ) ? 5 * MINUTE_IN_SECONDS : 6 * HOUR_IN_SECONDS );
		return $prefixes;
	}
}
