<?php
/**
 * WordPress Dashboard Widget for MK Security Shield v2.0.
 *
 * @package MK_Security_Shield
 */

defined( 'ABSPATH' ) || exit;

class MKSS_Dashboard {

	public function __construct() {
		add_action( 'wp_dashboard_setup', [ $this, 'register_widget' ] );
	}

	/**
	 * Register the dashboard widget.
	 */
	public function register_widget(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		wp_add_dashboard_widget(
			'mkss_security_widget',
			'🛡️ MK Security Shield — Overview',
			[ $this, 'render_widget' ]
		);
	}

	/**
	 * Render the dashboard widget content.
	 */
	public function render_widget(): void {
		global $wpdb;
		$table = $wpdb->prefix . 'mkss_activity_log';

		$failed = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$table}` WHERE event_type='login_failed' AND created_at >= NOW() - INTERVAL 24 HOUR" ); // phpcs:ignore
		$blocked = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$table}` WHERE event_type='ip_blocked' AND created_at >= NOW() - INTERVAL 24 HOUR" ); // phpcs:ignore
		$firewall = (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$table}` WHERE event_type='firewall_block' AND created_at >= NOW() - INTERVAL 24 HOUR" ); // phpcs:ignore

		$last_check = get_option( 'mkss_last_file_check_result', [] );
		$file_status = ! empty( $last_check['ok'] ) ? '<span style="color:#27ae60">✓ OK</span>' : '<span style="color:#c0392b">⚠ Issues found</span>';

		?>
		<style>
		.mkss-widget-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px}
		.mkss-widget-stat{background:#f8f9fa;border:1px solid #e2e8f0;border-radius:6px;padding:10px;text-align:center}
		.mkss-widget-stat .num{font-size:22px;font-weight:700;color:#c0392b}
		.mkss-widget-stat .lbl{font-size:11px;color:#666;margin-top:2px}
		</style>
		<div class="mkss-widget-grid">
			<div class="mkss-widget-stat"><div class="num"><?php echo esc_html( $failed ); ?></div><div class="lbl">Failed Logins (24h)</div></div>
			<div class="mkss-widget-stat"><div class="num"><?php echo esc_html( $blocked ); ?></div><div class="lbl">IPs Blocked (24h)</div></div>
			<div class="mkss-widget-stat"><div class="num"><?php echo esc_html( $firewall ); ?></div><div class="lbl">Firewall Blocks (24h)</div></div>
			<div class="mkss-widget-stat"><div class="num" style="font-size:14px"><?php echo wp_kses_post( $file_status ); ?></div><div class="lbl">File Integrity</div></div>
		</div>
		<p style="text-align:right;margin:0">
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=mk-security-shield' ) ); ?>" class="button button-small">Full Report →</a>
		</p>
		<?php
	}
}
