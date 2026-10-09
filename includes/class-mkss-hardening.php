<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MKSS_Hardening {

	const MARKER = 'MK Security Shield';

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$settings = MKSS_Settings::instance();

		if ( $settings->get( 'disable_file_edit' ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}

		if ( $settings->get( 'disable_xmlrpc' ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', array( $this, 'strip_pingback_methods' ) );
			remove_action( 'wp_head', 'rsd_link' );
			add_action( 'init', array( $this, 'block_xmlrpc_requests' ), 1 );
		}

		if ( $settings->get( 'hide_wp_version' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
			add_filter( 'style_loader_src', array( $this, 'strip_version_query' ), 9999 );
			add_filter( 'script_loader_src', array( $this, 'strip_version_query' ), 9999 );
		}

		if ( $settings->get( 'disable_user_enumeration' ) ) {
			add_action( 'template_redirect', array( $this, 'block_author_scan' ), 0 );
		}

		if ( $settings->get( 'restrict_rest_users' ) ) {
			add_filter( 'rest_pre_dispatch', array( $this, 'restrict_rest_user_routes' ), 10, 3 );
		}

		if ( $settings->get( 'security_headers' ) ) {
			add_action( 'send_headers', array( $this, 'send_security_headers' ) );
			add_action( 'admin_init', array( $this, 'send_security_headers' ) );
			add_action( 'login_init', array( $this, 'send_security_headers' ) );
			add_filter( 'wp_headers', array( $this, 'filter_wp_headers' ) );
		}
	}

	public function filter_wp_headers( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	public function strip_pingback_methods( $methods ) {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		return $methods;
	}

	public function block_xmlrpc_requests() {
		$script = isset( $_SERVER['SCRIPT_NAME'] ) ? $_SERVER['SCRIPT_NAME'] : '';
		if ( false !== strpos( $script, 'xmlrpc.php' ) ) {
			MKSS_Activity_Log::log( 'xmlrpc_blocked', 'Blocked direct xmlrpc.php request' );
			wp_die( esc_html__( 'XML-RPC is disabled on this site.', 'mk-security-shield' ), '', array( 'response' => 403 ) );
		}
	}

	public function strip_version_query( $src ) {
		if ( is_string( $src ) && false !== strpos( $src, 'ver=' . get_bloginfo( 'version' ) ) ) {
			$src = remove_query_arg( 'ver', $src );
		}
		return $src;
	}

	public function block_author_scan() {
		if ( is_user_logged_in() ) {
			return;
		}
		if ( isset( $_GET['author'] ) && preg_match( '/^\d+$/', wp_unslash( $_GET['author'] ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	}

	public function restrict_rest_user_routes( $result, $server, $request ) {
		$route = $request->get_route();
		if ( ! is_user_logged_in() && 0 === strpos( $route, '/wp/v2/users' ) ) {
			return new WP_Error( 'mkss_rest_forbidden', __( 'Restricted.', 'mk-security-shield' ), array( 'status' => 401 ) );
		}
		return $result;
	}

	public function send_security_headers() {
		if ( headers_sent() ) {
			return;
		}

		$settings = MKSS_Settings::instance();

		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );
		header( 'X-XSS-Protection: 0' );

		if ( is_ssl() ) {
			header( 'Strict-Transport-Security: max-age=31536000' );
		}

		if ( $settings->get( 'csp_enabled' ) && $settings->get( 'csp_value' ) ) {
			header( 'Content-Security-Policy: ' . $settings->get( 'csp_value' ) );
		}
	}

	/**
	 * Writes a marked, safely-removable block into the site's root
	 * .htaccess using WordPress core's insert_with_markers(). Rules are
	 * written in a form compatible with both Apache 2.2 and 2.4+.
	 */
	public static function write_htaccess_rules() {
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}

		$htaccess = self::locate_root_htaccess();
		if ( ! $htaccess ) {
			return false;
		}

		$deny_block = array(
			'<IfModule mod_authz_core.c>',
			'Require all denied',
			'</IfModule>',
			'<IfModule !mod_authz_core.c>',
			'Order allow,deny',
			'Deny from all',
			'</IfModule>',
		);

		$rules = array_merge(
			array( '<Files wp-config.php>' ),
			$deny_block,
			array( '</Files>' ),
			array( '<FilesMatch "\.(log|sql|bak|env)$">' ),
			$deny_block,
			array( '</FilesMatch>' ),
			array( 'Options -Indexes' )
		);

		$result = insert_with_markers( $htaccess, self::MARKER, $rules );

		self::write_uploads_htaccess();

		return $result;
	}

	public static function remove_htaccess_rules() {
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}
		$htaccess = self::locate_root_htaccess();
		if ( $htaccess ) {
			insert_with_markers( $htaccess, self::MARKER, array() );
		}
	}

	private static function locate_root_htaccess() {
		$path = ABSPATH . '.htaccess';
		if ( file_exists( $path ) && ! is_writable( $path ) ) {
			return false;
		}
		if ( ! file_exists( $path ) && ! is_writable( ABSPATH ) ) {
			return false;
		}
		return $path;
	}

	private static function write_uploads_htaccess() {
		$upload_dir = wp_get_upload_dir();
		$path       = trailingslashit( $upload_dir['basedir'] ) . '.htaccess';

		if ( file_exists( $path ) || ! is_writable( $upload_dir['basedir'] ) ) {
			return;
		}

		$lines = array(
			'<FilesMatch "\.(php|php\d?|phtml|phar)$">',
			'<IfModule mod_authz_core.c>',
			'Require all denied',
			'</IfModule>',
			'<IfModule !mod_authz_core.c>',
			'Order allow,deny',
			'Deny from all',
			'</IfModule>',
			'</FilesMatch>',
		);

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		@file_put_contents( $path, implode( "\n", $lines ) . "\n" );
	}
}
