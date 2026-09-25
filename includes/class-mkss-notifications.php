<?php
/**
 * Notifications Manager for MK Security Shield v2.0.
 *
 * @package MK_Security_Shield
 */

defined( 'ABSPATH' ) || exit;

class MKSS_Notifications {

	/** In-memory queue to batch similar alerts within a request */
	private static array $queued = [];

	public function __construct() {
		// Send daily summary if configured
		add_action( 'mkss_daily_scan', [ $this, 'send_daily_summary' ] );
	}

	/**
	 * Dispatch an alert (email + optional Slack).
	 * Thin wrapper around MKSS_Helper so callers import one class.
	 */
	public static function alert( string $subject, string $html_body ): void {
		MKSS_Helper::send_alert( $subject, $html_body );
		MKSS_Helper::send_slack( wp_strip_all_tags( $subject ) . ' — ' . wp_strip_all_tags( $html_body ) );
	}

	/**
	 * Queue a low-priority notification to be batched into the daily summary.
	 */
	public static function queue( string $event, string $detail ): void {
		self::$queued[] = [ 'event' => $event, 'detail' => $detail, 'time' => current_time( 'mysql' ) ];
	}

	/**
	 * Send a daily security summary email.
	 */
	public function send_daily_summary(): void {
		$to = get_option( 'mkss_alert_email', get_option( 'admin_email' ) );
		if ( empty( $to ) ) {
			return;
		}

		$counts = $this->get_daily_counts();
		if ( array_sum( $counts ) === 0 ) {
			return; // Nothing to report
		}

		$rows = '';
		foreach ( $counts as $label => $count ) {
			$rows .= '<tr><td style="padding:6px 10px;">' . esc_html( $label ) . '</td>'
				. '<td style="padding:6px 10px;font-weight:bold;">' . (int) $count . '</td></tr>';
		}

		$body = '
		<h3>Daily Security Summary — ' . esc_html( get_bloginfo( 'name' ) ) . '</h3>
		<table border="0" cellspacing="0" cellpadding="0" style="border-collapse:collapse;width:100%;max-width:480px;">
		<thead><tr style="background:#c0392b;color:#fff;">
			<th style="padding:8px 10px;text-align:left;">Event</th>
			<th style="padding:8px 10px;text-align:left;">Count (24 h)</th>
		</tr></thead>
		<tbody>' . $rows . '</tbody>
		</table>
		<p style="margin-top:16px;font-size:12px;color:#666;">
			<a href="' . esc_url( admin_url( 'admin.php?page=mk-security-shield&tab=activity' ) ) . '">View full activity log →</a>
		</p>';

		MKSS_Helper::send_alert( 'Daily Security Summary', $body );
	}

	/**
	 * Get 24-hour event counts for the summary.
	 */
	private function get_daily_counts(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'mkss_activity_log';
		$rows  = $wpdb->get_results(
			"SELECT event_type, COUNT(*) as cnt FROM `{$table}` WHERE created_at >= NOW() - INTERVAL 1 DAY GROUP BY event_type", // phpcs:ignore
			ARRAY_A
		);
		$map = [];
		$labels = [
			'login_failed'   => 'Failed Login Attempts',
			'ip_blocked'     => 'IPs Blocked',
			'firewall_block' => 'Firewall Blocks',
			'geo_block'      => 'Geo Blocks',
			'file_issue'     => 'File Integrity Issues',
			'login_success'  => 'Successful Logins',
		];
		foreach ( (array) $rows as $row ) {
			$key = $row['event_type'];
			$label = $labels[ $key ] ?? ucwords( str_replace( '_', ' ', $key ) );
			$map[ $label ] = (int) $row['cnt'];
		}
		return $map;
	}
}
