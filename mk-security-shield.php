<?php
/**
 * Plugin Name: MK Security Shield
 * Plugin URI: https://mkdhawan.in
 * Description: Hardens WordPress against common attack vectors: brute-force logins, XML-RPC abuse, user enumeration, malicious requests, and core file tampering. Includes an optional Cloudflare-based country restriction. No single plugin can guarantee protection from "all" hacking threats — pair this with regular updates, strong unique passwords, and off-site backups.
 * Version: 2.1.1
 * Requires at least: 5.8
 * Requires PHP: 8.0
 * Author: MK Dhawan
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: mk-security-shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'MKSS_VERSION', '2.1.1' );
define( 'MKSS_PLUGIN_FILE', __FILE__ );
define( 'MKSS_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'MKSS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

require_once MKSS_PLUGIN_DIR . 'includes/class-mkss-helper.php';
require_once MKSS_PLUGIN_DIR . 'includes/class-mkss-verified-ai.php';
require_once MKSS_PLUGIN_DIR . 'includes/class-mkss-integrity-engine.php';
require_once MKSS_PLUGIN_DIR . 'includes/class-mkss-activity-log.php';
require_once MKSS_PLUGIN_DIR . 'includes/class-mkss-settings.php';
require_once MKSS_PLUGIN_DIR . 'includes/class-mkss-login-protection.php';
require_once MKSS_PLUGIN_DIR . 'includes/class-mkss-firewall.php';
require_once MKSS_PLUGIN_DIR . 'includes/class-mkss-hardening.php';
require_once MKSS_PLUGIN_DIR . 'includes/class-mkss-two-factor.php';
require_once MKSS_PLUGIN_DIR . 'includes/class-mkss-malware-scanner.php';
require_once MKSS_PLUGIN_DIR . 'includes/class-mkss-file-monitor.php';
require_once MKSS_PLUGIN_DIR . 'includes/class-mkss-geo-restriction.php';
require_once MKSS_PLUGIN_DIR . 'includes/class-mkss-ai-connect.php';

/**
 * Plugin bootstrap. Every module is instantiated on plugins_loaded; each
 * module decides internally (from MKSS_Settings) whether to actually attach
 * its hooks, so toggling a setting takes effect without reactivating.
 */
final class MKSS_Plugin {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		register_activation_hook( MKSS_PLUGIN_FILE, array( __CLASS__, 'activate' ) );
		register_deactivation_hook( MKSS_PLUGIN_FILE, array( __CLASS__, 'deactivate' ) );

		add_action( 'plugins_loaded', array( $this, 'init' ) );
	}

	public function init() {
		MKSS_Activity_Log::instance();
		MKSS_Settings::instance();
		MKSS_Login_Protection::instance();
		MKSS_Firewall::instance();
		MKSS_Hardening::instance();
		MKSS_Two_Factor::instance();
		MKSS_Malware_Scanner::instance();
		MKSS_File_Monitor::instance();
		MKSS_Geo_Restriction::instance();
		MKSS_AI_Connect::instance();
	}

	public static function activate() {
		MKSS_Activity_Log::create_table();
		MKSS_File_Monitor::schedule_events();
		MKSS_Malware_Scanner::schedule_events();

		if ( false === get_option( 'mkss_settings' ) ) {
			add_option( 'mkss_settings', MKSS_Settings::default_settings() );
		}
	}

	public static function deactivate() {
		MKSS_File_Monitor::clear_scheduled_events();
		MKSS_Malware_Scanner::clear_scheduled_events();
	}
}

MKSS_Plugin::instance();
