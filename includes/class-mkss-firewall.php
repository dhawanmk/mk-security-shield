<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Lightweight request pattern filter. This is NOT a substitute for a real
 * WAF — it only catches obvious, common attack strings. It deliberately
 * skips requests from logged-in administrators to avoid blocking legitimate
 * site management (e.g. editing content that legitimately contains a
 * <script> tag or SQL-like text).
 */
class MKSS_Firewall {

	private static $instance = null;

	private $patterns = array(
		'/union[\s\/\*]+select/i',
		'/select.+from.+information_schema/i',
		'/base64_decode\s*\(/i',
		'/eval\s*\(/i',
		'/<script[^>]*>/i',
		'/javascript\s*:/i',
		'/\.\.\/\.\.\/\.\./',
		'/etc\/passwd/i',
		'/wp-config\.php/i',
		'/phpinfo\s*\(/i',
		'/\$GLOBALS\s*\[/i',
		'/(union|select).{1,80}(concat|group_concat)/i',
	);

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		if ( ! MKSS_Settings::instance()->get( 'firewall_enabled' ) ) {
			return;
		}
		add_action( 'init', array( $this, 'inspect_request' ), 1 );
	}

	public function inspect_request() {
		if ( is_admin() && current_user_can( 'manage_options' ) ) {
			return;
		}

		$inputs = array(
			'REQUEST_URI' => isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '',
		);
		$inputs = array_merge( $inputs, $this->flatten( $_GET ), $this->flatten( $_POST ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		foreach ( $inputs as $key => $value ) {
			if ( ! is_string( $value ) ) {
				continue;
			}
			$value = rawurldecode( rawurldecode( $value ) );
			foreach ( $this->patterns as $pattern ) {
				if ( preg_match( $pattern, $value ) ) {
					$this->handle_match( $key, $pattern );
					return;
				}
			}
		}
	}

	private function flatten( $array, $prefix = '' ) {
		$result = array();
		foreach ( (array) $array as $key => $value ) {
			$full_key = $prefix ? $prefix . '.' . $key : $key;
			if ( is_array( $value ) ) {
				$result += $this->flatten( $value, $full_key );
			} else {
				$result[ $full_key ] = wp_unslash( $value );
			}
		}
		return $result;
	}

	private function handle_match( $key, $pattern ) {
		$settings = MKSS_Settings::instance();
		$message  = sprintf( 'Field "%s" matched pattern %s', $key, $pattern );

		MKSS_Activity_Log::log( 'firewall_match', $message );

		if ( 'block' === $settings->get( 'firewall_mode' ) ) {
			wp_die( esc_html__( 'Request blocked by Security Shield firewall.', 'mk-security-shield' ), '', array( 'response' => 403 ) );
		}
	}
}
