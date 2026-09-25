<?php
/**
 * WordPress Hardening for MK Security Shield v2.0.
 *
 * @package MK_Security_Shield
 */

defined( 'ABSPATH' ) || exit;

class MKSS_Hardening {

	public function __construct() {
		// Remove WP version
		if ( get_option( 'mkss_remove_wp_version', true ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
			add_filter( 'update_footer', '__return_empty_string' );
		}

		// Disable file editor
		if ( get_option( 'mkss_disable_file_editor', true ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}

		// Disable directory listing via .htaccess (done on activation; not via PHP)

		// Remove unnecessary head tags
		add_action( 'init', [ $this, 'clean_wp_head' ] );

		// Force strong passwords hint
		add_action( 'user_profile_update_errors', [ $this, 'enforce_password_strength' ], 10, 3 );

		// Protect wp-config.php and .htaccess via headers
		add_action( 'template_redirect', [ $this, 'block_sensitive_file_access' ] );

		// Disable application passwords if not needed
		add_filter( 'wp_is_application_passwords_available', '__return_false' );

		// Add noindex to login and register pages
		add_action( 'login_head', [ $this, 'noindex_login' ] );
	}

	/**
	 * Remove clutter from <head>.
	 */
	public function clean_wp_head(): void {
		remove_action( 'wp_head', 'rsd_link' );
		remove_action( 'wp_head', 'wlwmanifest_link' );
		remove_action( 'wp_head', 'wp_shortlink_wp_head' );
		remove_action( 'wp_head', 'adjacent_posts_rel_link_wp_head' );
	}

	/**
	 * Enforce password length minimum for admin-level users.
	 */
	public function enforce_password_strength( WP_Error $errors, bool $update, WP_User $user ): void {
		if ( ! in_array( 'administrator', (array) $user->roles, true ) ) {
			return;
		}
		$pass = isset( $_POST['pass1'] ) ? $_POST['pass1'] : ''; // phpcs:ignore
		if ( ! empty( $pass ) && strlen( $pass ) < 12 ) {
			$errors->add(
				'mkss_weak_password',
				__( '<strong>Security:</strong> Administrator passwords must be at least 12 characters long.', 'mk-security-shield' )
			);
		}
	}

	/**
	 * Block direct access to sensitive files if they somehow still exist.
	 */
	public function block_sensitive_file_access(): void {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$blocked_patterns = [
			'wp-config.php',
			'wp-config-sample.php',
			'php.ini',
			'.htpasswd',
			'xmlrpc.php',
		];
		foreach ( $blocked_patterns as $pattern ) {
			if ( strpos( $uri, $pattern ) !== false ) {
				status_header( 403 );
				wp_die( esc_html__( 'Access Denied', 'mk-security-shield' ), 403 );
			}
		}
	}

	/**
	 * Add noindex meta to login page.
	 */
	public function noindex_login(): void {
		echo '<meta name="robots" content="noindex,nofollow" />' . "\n";
	}
}
