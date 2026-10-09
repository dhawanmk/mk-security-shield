<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Checks WordPress core files (wp-admin, wp-includes, root PHP files)
 * against the official checksums published by WordPress.org. wp-content
 * (themes/plugins/uploads) is intentionally excluded — those files are
 * expected to differ from a bare core install and are instead covered by
 * MKSS_Malware_Scanner.
 */
class MKSS_File_Monitor {

	const CRON_HOOK       = 'mkss_file_monitor_scan';
	const OPTION_RESULTS  = 'mkss_file_monitor_results';

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( self::CRON_HOOK, array( $this, 'run_scan' ) );

		if ( MKSS_Settings::instance()->get( 'file_monitor_enabled' ) && ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}

		add_action( 'admin_menu', array( $this, 'add_menu' ), 30 );
		add_action( 'admin_post_mkss_run_scan_now', array( $this, 'handle_manual_scan' ) );
	}

	public static function schedule_events() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	public static function clear_scheduled_events() {
		$timestamp = wp_next_scheduled( self::CRON_HOOK );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, self::CRON_HOOK );
		}
	}

	public function run_scan() {
        if ( ! MKSS_Settings::instance()->get( 'file_monitor_enabled' ) ) { return; }
        $result = ( new MKSS_Integrity_Engine() )->run_integrity_check();
        $modified = array(); $missing = array();
        foreach ( $result['issues'] as $issue ) {
            if ( 'missing' === $issue['type'] ) { $missing[] = $issue['file']; }
            else { $modified[] = $issue['file']; }
        }
        $result['time'] = time(); $result['modified'] = $modified; $result['missing'] = $missing;
        update_option( self::OPTION_RESULTS, $result, false );
        return $result;
    }

	public function handle_manual_scan() {
		if ( ! current_user_can( 'manage_options' ) || ! check_admin_referer( 'mkss_run_scan_now' ) ) {
			wp_die( esc_html__( 'Not allowed.', 'mk-security-shield' ) );
		}
		$this->run_scan();
		MKSS_Malware_Scanner::instance()->run_scan();
		wp_safe_redirect( admin_url( 'admin.php?page=mkss-scan-results&scanned=1' ) );
		exit;
	}

	public function add_menu() {
		add_submenu_page(
			'mkss-settings',
			__( 'Scan Results', 'mk-security-shield' ),
			__( 'Scan Results', 'mk-security-shield' ),
			'manage_options',
			'mkss-scan-results',
			array( $this, 'render_page' )
		);
	}

	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$file_results    = get_option( self::OPTION_RESULTS, array() );
		$malware_results = get_option( MKSS_Malware_Scanner::OPTION_RESULTS, array() );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Security Shield — Scan Results', 'mk-security-shield' ); ?></h1>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="mkss_run_scan_now" />
				<?php wp_nonce_field( 'mkss_run_scan_now' ); ?>
				<?php submit_button( __( 'Run Scan Now', 'mk-security-shield' ), 'secondary' ); ?>
			</form>

			<h2><?php esc_html_e( 'Core File Integrity', 'mk-security-shield' ); ?></h2>
			<?php if ( empty( $file_results ) ) : ?>
				<p><?php esc_html_e( 'No scan has run yet.', 'mk-security-shield' ); ?></p>
			<?php else : ?>
				<p>
					<?php
					printf(
						/* translators: %s: date/time of last scan */
						esc_html__( 'Last checked: %s', 'mk-security-shield' ),
						esc_html( wp_date( 'Y-m-d H:i', $file_results['time'] ) )
					);
					?>
				</p>
				<?php if ( ! empty( $file_results['errors'] ) ) : ?>
                    <p style="color:#b32d2e;"><?php echo esc_html( implode( ' ', $file_results['errors'] ) ); ?></p>
                <?php elseif ( empty( $file_results['modified'] ) && empty( $file_results['missing'] ) ) : ?>
					<p style="color:#1a7f37;"><?php esc_html_e( 'No changes detected in checked WordPress core files. Missing optional documentation is ignored; present documentation and executable files remain checked.', 'mk-security-shield' ); ?></p>
				<?php else : ?>
					<ul>
						<?php foreach ( $file_results['modified'] as $f ) : ?>
							<li><?php echo esc_html( 'Modified: ' . $f ); ?></li>
						<?php endforeach; ?>
						<?php foreach ( $file_results['missing'] as $f ) : ?>
							<li><?php echo esc_html( 'Missing: ' . $f ); ?></li>
						<?php endforeach; ?>
					</ul>
				<?php endif; ?>
			<?php endif; ?>

			<h2><?php esc_html_e( 'Malware Pattern Scan', 'mk-security-shield' ); ?></h2>
			<?php if ( empty( $malware_results ) ) : ?>
				<p><?php esc_html_e( 'No scan has run yet.', 'mk-security-shield' ); ?></p>
			<?php else : ?>
				<p>
					<?php
					printf(
						/* translators: 1: date/time of last scan, 2: number of files scanned */
						esc_html__( 'Last checked: %1$s — %2$d file(s) scanned.', 'mk-security-shield' ),
						esc_html( wp_date( 'Y-m-d H:i', $malware_results['time'] ) ),
						(int) $malware_results['scanned']
					);
					?>
					<?php if ( ! empty( $malware_results['truncated'] ) ) : ?>
						<em><?php esc_html_e( '(scan stopped early at the file limit — not every file was checked)', 'mk-security-shield' ); ?></em>
					<?php endif; ?>
				</p>
				<?php if ( empty( $malware_results['flagged'] ) ) : ?>
					<p style="color:#1a7f37;"><?php esc_html_e( 'No suspicious patterns found.', 'mk-security-shield' ); ?></p>
				<?php else : ?>
					<table class="widefat striped">
						<thead>
							<tr>
								<th><?php esc_html_e( 'File', 'mk-security-shield' ); ?></th>
								<th><?php esc_html_e( 'Line', 'mk-security-shield' ); ?></th>
								<th><?php esc_html_e( 'Pattern', 'mk-security-shield' ); ?></th>
							</tr>
						</thead>
						<tbody>
						<?php foreach ( $malware_results['flagged'] as $item ) : ?>
							<tr>
								<td><?php echo esc_html( $item['file'] ); ?></td>
								<td><?php echo esc_html( $item['line'] ); ?></td>
								<td><?php echo esc_html( $item['label'] ); ?></td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
					<p><em><?php esc_html_e( 'These are pattern matches for manual review, not confirmed malware. Verify each file before taking action.', 'mk-security-shield' ); ?></em></p>
				<?php endif; ?>
			<?php endif; ?>
		</div>
		<?php
	}
}
