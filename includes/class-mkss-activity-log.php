<?php
/**
 * Activity Log for MK Security Shield v2.0.
 *
 * @package MK_Security_Shield
 */

defined( 'ABSPATH' ) || exit;

class MKSS_Activity_Log {

	/** Severity levels */
	const SEV_INFO     = 0;
	const SEV_LOW      = 1;
	const SEV_HIGH     = 2;
	const SEV_CRITICAL = 3;

	public function __construct() {
		// Schedule log cleanup — keep 90 days
		add_action( 'mkss_daily_scan', [ $this, 'prune_old_logs' ] );
	}

	/**
	 * Write an entry to the activity log.
	 *
	 * @param string $event_type  Machine-readable event slug.
	 * @param string $description Human-readable description.
	 * @param int    $severity    0=info, 1=low, 2=high, 3=critical.
	 */
	public static function log( string $event_type, string $description, int $severity = 0 ): void {
		global $wpdb;

		$wpdb->insert(
			$wpdb->prefix . 'mkss_activity_log',
			[
				'event_type'  => sanitize_key( $event_type ),
				'user_id'     => get_current_user_id(),
				'ip_address'  => MKSS_Helper::get_ip(),
				'user_agent'  => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
				'description' => sanitize_text_field( $description ),
				'severity'    => min( 3, max( 0, (int) $severity ) ),
				'created_at'  => current_time( 'mysql' ),
			],
			[ '%s', '%d', '%s', '%s', '%s', '%d', '%s' ]
		);
	}

	/**
	 * Get recent log entries.
	 *
	 * @param int    $limit
	 * @param string $event_type  Optional filter.
	 * @param int    $min_severity Optional filter.
	 * @return array
	 */
	public static function get_logs( int $limit = 50, string $event_type = '', int $min_severity = -1 ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'mkss_activity_log';
		$where = 'WHERE 1=1';
		$args  = [];

		if ( ! empty( $event_type ) ) {
			$where .= ' AND event_type = %s';
			$args[] = $event_type;
		}
		if ( $min_severity >= 0 ) {
			$where .= ' AND severity >= %d';
			$args[] = $min_severity;
		}

		$args[] = absint( $limit );

		if ( ! empty( $args ) ) {
			// Remove the limit arg for prepare — add it separately
			$limit_val = array_pop( $args );
			if ( ! empty( $args ) ) {
				$sql = $wpdb->prepare( "SELECT * FROM `{$table}` {$where} ORDER BY id DESC LIMIT %d", array_merge( $args, [ $limit_val ] ) ); // phpcs:ignore
			} else {
				$sql = $wpdb->prepare( "SELECT * FROM `{$table}` ORDER BY id DESC LIMIT %d", $limit_val ); // phpcs:ignore
			}
		} else {
			$sql = $wpdb->prepare( "SELECT * FROM `{$table}` ORDER BY id DESC LIMIT %d", $limit ); // phpcs:ignore
		}

		return $wpdb->get_results( $sql, ARRAY_A ) ?: []; // phpcs:ignore
	}

	/**
	 * Delete log entries older than $days days.
	 */
	public function prune_old_logs( int $days = 90 ): int {
		global $wpdb;
		$deleted = $wpdb->query( $wpdb->prepare(
			"DELETE FROM `{$wpdb->prefix}mkss_activity_log` WHERE created_at < NOW() - INTERVAL %d DAY",
			$days
		) );
		return (int) $deleted;
	}
}
