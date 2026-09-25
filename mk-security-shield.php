<?php
/**
 * Plugin Name:       MK Security Shield
 * Plugin URI:        https://mkdhawan.com/mk-security-shield
 * Description:       Advanced WordPress security plugin. Login protection, firewall, file integrity monitoring, malware scanning, geo-restriction, and 2FA.
 * Version:           2.0.0
 * Author:            MK Dhawan
 * Author URI:        https://mkdhawan.com
 * License:           GPL-2.0+
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       mk-security-shield
 * Domain Path:       /languages
 * Requires at least: 5.8
 * Requires PHP:      7.4
 *
 * @package MK_Security_Shield
 */

defined( 'ABSPATH' ) || exit;

// Plugin constants
define( 'MKSS_VERSION', '2.0.0' );
define( 'MKSS_PLUGIN_FILE', __FILE__ );
define( 'MKSS_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'MKSS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'MKSS_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
define( 'MKSS_DB_VERSION', '2.0' );

// Include core files
require_once MKSS_PLUGIN_DIR . 'includes/class-mkss-helper.php';
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
require_once MKSS_PLUGIN_DIR . 'includes/class-mkss-notifications.php';
require_once MKSS_PLUGIN_DIR . 'includes/class-mkss-dashboard.php';

/**
 * Main plugin bootstrap class.
 */
final class MK_Security_Shield {

	/** @var MK_Security_Shield|null Singleton instance */
	private static ?MK_Security_Shield $instance = null;

	/** @var array Loaded module instances */
	private array $modules = [];

	/**
	 * Get singleton instance.
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor — private to enforce singleton.
	 */
	private function __construct() {
		$this->load_textdomain();
		$this->init_modules();
		$this->register_hooks();
	}

	/**
	 * Load plugin translations.
	 */
	private function load_textdomain(): void {
		load_plugin_textdomain( 'mk-security-shield', false, dirname( MKSS_PLUGIN_BASENAME ) . '/languages' );
	}

	/**
	 * Instantiate all security modules.
	 */
	private function init_modules(): void {
		$this->modules['helper']           = new MKSS_Helper();
		$this->modules['activity_log']     = new MKSS_Activity_Log();
		$this->modules['settings']         = new MKSS_Settings();
		$this->modules['login_protection'] = new MKSS_Login_Protection();
		$this->modules['firewall']         = new MKSS_Firewall();
		$this->modules['hardening']        = new MKSS_Hardening();
		$this->modules['two_factor']       = new MKSS_Two_Factor();
		$this->modules['malware_scanner']  = new MKSS_Malware_Scanner();
		$this->modules['file_monitor']     = new MKSS_File_Monitor();
		$this->modules['geo_restriction']  = new MKSS_Geo_Restriction();
		$this->modules['notifications']    = new MKSS_Notifications();
		$this->modules['dashboard']        = new MKSS_Dashboard();
	}

	/**
	 * Register plugin-level hooks.
	 */
	private function register_hooks(): void {
		register_activation_hook( MKSS_PLUGIN_FILE, [ $this, 'on_activate' ] );
		register_deactivation_hook( MKSS_PLUGIN_FILE, [ $this, 'on_deactivate' ] );
		add_filter( 'plugin_action_links_' . MKSS_PLUGIN_BASENAME, [ $this, 'add_action_links' ] );
		add_action( 'admin_notices', [ $this, 'maybe_show_upgrade_notice' ] );
	}

	/**
	 * Plugin activation.
	 */
	public function on_activate(): void {
		MKSS_Helper::create_db_tables();
		MKSS_Helper::set_default_options();
		// Schedule cron jobs
		if ( ! wp_next_scheduled( 'mkss_daily_scan' ) ) {
			wp_schedule_event( time(), 'daily', 'mkss_daily_scan' );
		}
		if ( ! wp_next_scheduled( 'mkss_file_integrity_check' ) ) {
			wp_schedule_event( time(), 'twicedaily', 'mkss_file_integrity_check' );
		}
		update_option( 'mkss_activated_at', current_time( 'mysql' ) );
		update_option( 'mkss_version', MKSS_VERSION );
	}

	/**
	 * Plugin deactivation.
	 */
	public function on_deactivate(): void {
		wp_clear_scheduled_hook( 'mkss_daily_scan' );
		wp_clear_scheduled_hook( 'mkss_file_integrity_check' );
	}

	/**
	 * Add Settings link on plugins page.
	 */
	public function add_action_links( array $links ): array {
		$settings_link = sprintf(
			'<a href="%s">%s</a>',
			admin_url( 'admin.php?page=mk-security-shield' ),
			__( 'Settings', 'mk-security-shield' )
		);
		array_unshift( $links, $settings_link );
		return $links;
	}

	/**
	 * Show upgrade notice when major version changes.
	 */
	public function maybe_show_upgrade_notice(): void {
		$stored = get_option( 'mkss_version', '1.0.0' );
		if ( version_compare( $stored, MKSS_VERSION, '<' ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>';
			printf(
				/* translators: %s: version number */
				esc_html__( 'MK Security Shield upgraded to v%s — enjoy the new features!', 'mk-security-shield' ),
				esc_html( MKSS_VERSION )
			);
			echo '</p></div>';
			update_option( 'mkss_version', MKSS_VERSION );
		}
	}

	/**
	 * Get a module instance.
	 */
	public function get_module( string $name ): ?object {
		return $this->modules[ $name ] ?? null;
	}
}

// Boot
add_action( 'plugins_loaded', static function () {
	MK_Security_Shield::get_instance();
} );
