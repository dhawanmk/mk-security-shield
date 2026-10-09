<?php
/**
 * File Integrity Monitor for MK Security Shield v2.0.
 *
 * Compares WordPress core files against official checksums.
 * Intentionally-removed security-hardening files are excluded from alerts.
 *
 * @package MK_Security_Shield
 */

defined( 'ABSPATH' ) || exit;

class MKSS_File_Monitor {

	/**
	 * Files that are intentionally removed for security hardening.
	 * Only their absence is ignored. Present files are always verified.
	 *
	 * Admins can extend this list via the 'mkss_security_exclusions' option
	 * or the 'mkss_file_monitor_exclusions' filter.
	 *
	 * @var string[]
	 */
	private array $builtin_exclusions = [
		'readme.html',
		'license.txt',
		'wp-config-sample.php',
	];

	public function __construct() {
		add_action( 'mkss_file_integrity_check', [ $this, 'run_integrity_check' ] );
		add_action( 'admin_init', [ $this, 'handle_manual_scan' ] );
		add_action( 'wp_ajax_mkss_file_integrity', [ $this, 'ajax_run_check' ] );
	}

	/**
	 * Get the full exclusion list (built-in + user-defined + filtered).
	 *
	 * @return string[]
	 */
	private function get_exclusions(): array {
		// User-configured exclusions stored in DB
		$raw = get_option( 'mkss_security_exclusions', [] );
		$db_exclusions = is_array( $raw ) ? $raw : preg_split( '/[\r\n,]+/', (string) $raw );

		$all = array_unique( array_merge( $this->builtin_exclusions, $db_exclusions ) );

		/**
		 * Filters the list of file paths excluded from integrity alerts.
		 *
		 * @param string[] $exclusions Relative paths (e.g. 'readme.html').
		 */
		return (array) apply_filters( 'mkss_file_monitor_exclusions', $all );
	}

	/**
	 * Run the core file integrity check against WordPress.org checksums.
	 *
	 * @return array{ok: bool, issues: array, skipped: int, checked: int}
	 */
	public function run_integrity_check(): array {
		global $wp_version, $wp_local_package;

		// Installed core package locale can differ from the visitor/admin UI language.
		$locale = $wp_local_package ?? 'en_US';

		$result = [
			'ok'      => true,
			'issues'  => [],
			'skipped' => 0,
			'checked' => 0,
			'errors'  => [],
			'status'  => 'complete',
		];
		$lock = (int) get_option( 'core_updater.lock', 0 );
		if ( ( file_exists( ABSPATH . '.maintenance' ) && filemtime( ABSPATH . '.maintenance' ) > time() - 10 * MINUTE_IN_SECONDS ) || ( $lock > time() - 15 * MINUTE_IN_SECONDS ) ) {
			$result['ok'] = false;
			$result['status'] = 'deferred';
			$result['errors'][] = 'Core update in progress. Run the integrity check again after it finishes.';
			return $this->store_result( $result );
		}
		$api_url = add_query_arg( [ 'version' => $wp_version, 'locale' => $locale ], 'https://api.wordpress.org/core/checksums/1.0/' );
		$response = wp_safe_remote_get( $api_url, [ 'timeout' => 15, 'redirection' => 0, 'limit_response_size' => 2097152 ] );

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			$result['ok']     = false;
			$result['status'] = 'error';
			$result['errors'] = [ 'Could not reach WordPress checksums API. Integrity has not been verified.' ];
			return $this->store_result( $result );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['checksums'] ) || ! is_array( $body['checksums'] ) ) {
			$result['ok']     = false;
			$result['status'] = 'error';
			$result['errors'] = [ 'Invalid checksums response from API. Integrity has not been verified.' ];
			return $this->store_result( $result );
		}
		// Validate the entire manifest before using any supplied path on the filesystem.
		foreach ( $body['checksums'] as $path => $hash ) {
			if ( ! is_string( $path ) || ! preg_match( '~^[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*$~D', $path ) || in_array( '..', explode( '/', $path ), true ) || ! is_string( $hash ) || ! preg_match( '/^[a-f0-9]{32}$/iD', $hash ) ) {
				$result['ok'] = false;
				$result['status'] = 'error';
				$result['errors'][] = 'Unsafe or invalid checksum manifest. Integrity has not been verified.';
				return $this->store_result( $result );
			}
		}

		$exclusions = $this->get_exclusions();
		$issues     = [];

		foreach ( $body['checksums'] as $relative_path => $expected_md5 ) {

			// Skip intentionally-removed / security-hardened files
			if ( ! file_exists( ABSPATH . $relative_path ) && ! is_link( ABSPATH . $relative_path ) && in_array( $relative_path, $exclusions, true ) ) {
				$result['skipped']++;
				continue;
			}

			$result['checked']++;
			$full_path = ABSPATH . $relative_path;

			if ( is_link( $full_path ) || ! is_file( $full_path ) || ! is_readable( $full_path ) ) {
				$issues[] = [
					'type' => file_exists( $full_path ) || is_link( $full_path ) ? 'unreadable' : 'missing',
					'file' => $relative_path,
					'msg'  => "Missing, unreadable or linked core file: {$relative_path}",
				];
				continue;
			}

			$actual_md5 = @md5_file( $full_path );
			if ( $actual_md5 !== strtolower( $expected_md5 ) ) {
				$issues[] = [
					'type'     => 'modified',
					'file'     => $relative_path,
					'msg'      => "Modified core file: {$relative_path}",
					'expected' => $expected_md5,
					'actual'   => $actual_md5,
				];
			}
		}

		$result['issues'] = $issues;
		$result['ok']     = empty( $issues );

		// Log and notify if issues found
		if ( ! empty( $issues ) ) {
			$this->handle_issues( $issues );
		} else {
			delete_option( 'mkss_integrity_alert_state' );
		}

		return $this->store_result( $result );
	}

	/** Persist scan failures as unknown/error, never as a clean or infected result. */
	private function store_result( array $result ): array {
		update_option( 'mkss_last_file_check', current_time( 'mysql' ) );
		update_option( 'mkss_last_file_check_result', $result, false );

		return $result;
	}

	/**
	 * Send alert and log when integrity issues are found.
	 *
	 * @param array $issues
	 */
	private function handle_issues( array $issues ): void {
		// Log to activity log
		if ( class_exists( 'MKSS_Activity_Log' ) ) {
			MKSS_Activity_Log::log(
				'file_integrity',
				sprintf( 'File integrity issues found: %d file(s) affected.', count( $issues ) ),
				2 // high severity
			);
		}

		if ( ! get_option( 'mkss_notify_on_file_change', true ) ) {
			return;
		}
		$fingerprints = array_map( static function ( $issue ) {
			return $issue['file'] . ':' . $issue['type'] . ':' . ( $issue['actual'] ?? '' );
		}, $issues );
		sort( $fingerprints );
		$fingerprint = hash( 'sha256', implode( '|', $fingerprints ) );
		$previous = get_option( 'mkss_integrity_alert_state', [] );
		if ( ( $previous['fingerprint'] ?? '' ) === $fingerprint && ( $previous['time'] ?? 0 ) > time() - DAY_IN_SECONDS ) {
			return;
		}

		$rows = '';
		foreach ( $issues as $issue ) {
			$rows .= "<tr><td style='padding:6px 12px;border-bottom:1px solid #eee;'>" . esc_html( strtoupper( $issue['type'] ) ) . '</td>'
				. "<td style='padding:6px 12px;border-bottom:1px solid #eee;font-family:monospace;'>" . esc_html( $issue['file'] ) . '</td></tr>';
		}

		$body = "
			<p>The file integrity check detected <strong>" . count( $issues ) . " issue(s)</strong> with WordPress core files.</p>
			<table style='width:100%;border-collapse:collapse;font-size:13px;'>
				<thead><tr>
					<th style='text-align:left;padding:8px 12px;background:#f5f5f5;'>Status</th>
					<th style='text-align:left;padding:8px 12px;background:#f5f5f5;'>File</th>
				</tr></thead>
				<tbody>{$rows}</tbody>
			</table>
			<p style='margin-top:16px;'>These checksum differences require review; they are not proof of a compromise.
			Missing optional documentation is ignored, but present excluded files are still checked.</p>
		";

		MKSS_Helper::send_alert( 'Core File Integrity Alert', $body );
		MKSS_Helper::send_slack( '⚠️ Core file integrity issues found: ' . count( $issues ) . ' file(s). Check your admin email.' );
		update_option( 'mkss_integrity_alert_state', [ 'fingerprint' => $fingerprint, 'time' => time() ], false );
	}

	/**
	 * Handle manual scan triggered from admin settings page.
	 */
	public function handle_manual_scan(): void {
		if ( ! isset( $_POST['mkss_run_file_check'] ) || ! check_admin_referer( 'mkss_run_file_check' ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$result = $this->run_integrity_check();
		$status = 'complete' !== $result['status'] ? $result['status'] : ( $result['ok'] ? 'ok' : 'issues' );
		wp_safe_redirect( add_query_arg( [ 'mkss_scan' => $status, 'mkss_count' => count( $result['issues'] ) ], wp_get_referer() ) );
		exit;
	}

	/**
	 * AJAX handler for quick scan from dashboard.
	 */
	public function ajax_run_check(): void {
		check_ajax_referer( 'mkss_ajax_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}
		$result = $this->run_integrity_check();
		wp_send_json_success( $result );
	}
}
