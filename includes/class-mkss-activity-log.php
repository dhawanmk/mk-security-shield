<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MKSS_Activity_Log {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'admin_menu', array( $this, 'add_menu' ), 20 );
	}

	public static function table_name() {
		global $wpdb;
		return $wpdb->prefix . 'mkss_activity_log';
	}

	public static function create_table() {
		global $wpdb;

		$table           = self::table_name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			event_time DATETIME NOT NULL,
			event_type VARCHAR(50) NOT NULL,
			ip_address VARCHAR(100) NOT NULL,
			username VARCHAR(191) NULL,
			message TEXT NULL,
			PRIMARY KEY  (id),
			KEY event_type (event_type),
			KEY event_time (event_time)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	public static function log( $event_type, $message = '', $username = '' ) {
		global $wpdb;

		$wpdb->insert(
			self::table_name(),
			array(
				'event_time' => current_time( 'mysql' ),
				'event_type' => sanitize_key( $event_type ),
				'ip_address' => MKSS_Helper::get_client_ip(),
				'username'   => sanitize_text_field( (string) $username ),
				'message'    => sanitize_textarea_field( (string) $message ),
			),
			array( '%s', '%s', '%s', '%s', '%s' )
		);
	}

	public static function get_entries( $limit = 50, $offset = 0, $event_type = '' ) {
		global $wpdb;
		$table = self::table_name();

		if ( $event_type ) {
			return $wpdb->get_results(
				$wpdb->prepare(
					"SELECT * FROM {$table} WHERE event_type = %s ORDER BY id DESC LIMIT %d OFFSET %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$event_type,
					$limit,
					$offset
				)
			);
		}

		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} ORDER BY id DESC LIMIT %d OFFSET %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$limit,
				$offset
			)
		);
	}

	public static function count_entries() {
		global $wpdb;
		$table = self::table_name();
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
	}

	public function add_menu() {
		add_submenu_page(
			'mkss-settings',
			__( 'Activity Log', 'mk-security-shield' ),
			__( 'Activity Log', 'mk-security-shield' ),
			'manage_options',
			'mkss-activity-log',
			array( $this, 'render_page' )
		);
	}

	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$paged    = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$per_page = 30;
		$offset   = ( $paged - 1 ) * $per_page;

		$entries     = self::get_entries( $per_page, $offset );
		$total       = self::count_entries();
		$total_pages = max( 1, (int) ceil( $total / $per_page ) );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Security Shield — Activity Log', 'mk-security-shield' ); ?></h1>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Time', 'mk-security-shield' ); ?></th>
						<th><?php esc_html_e( 'Event', 'mk-security-shield' ); ?></th>
						<th><?php esc_html_e( 'IP', 'mk-security-shield' ); ?></th>
						<th><?php esc_html_e( 'User', 'mk-security-shield' ); ?></th>
						<th><?php esc_html_e( 'Details', 'mk-security-shield' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php if ( empty( $entries ) ) : ?>
						<tr><td colspan="5"><?php esc_html_e( 'No events recorded yet.', 'mk-security-shield' ); ?></td></tr>
					<?php else : ?>
						<?php foreach ( $entries as $entry ) : ?>
							<tr>
								<td><?php echo esc_html( $entry->event_time ); ?></td>
								<td><?php echo esc_html( $entry->event_type ); ?></td>
								<td><?php echo esc_html( $entry->ip_address ); ?></td>
								<td><?php echo esc_html( $entry->username ); ?></td>
								<td><?php echo esc_html( $entry->message ); ?></td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>

			<?php if ( $total_pages > 1 ) : ?>
				<div class="tablenav"><div class="tablenav-pages">
					<?php
					echo wp_kses_post(
						paginate_links(
							array(
								'base'    => add_query_arg( 'paged', '%#%' ),
								'format'  => '',
								'current' => $paged,
								'total'   => $total_pages,
							)
						)
					);
					?>
				</div></div>
			<?php endif; ?>
		</div>
		<?php
	}
}
