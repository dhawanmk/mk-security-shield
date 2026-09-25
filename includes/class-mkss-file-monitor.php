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
	 * These will NEVER trigger a missing-file alert.
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
		'wp-trackback.php',
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
		$db_exclusions = (array) get_option( 'mkss_security_exclusions', [] );

		$all = array_unique( array_merge( $this->builtin_exclusions, $db_exclusions ) );

		/**
		 * Filters the list of file paths excluded from integrity alerts.
		 *
		 * @param string[] $exclusions Relative paths (e.g. 'readme.html').
		 */
		return apply_filters( 'mkss_file_monitor_exclusions', $all );
	}

	/**
	 * Run the core file integrity check against WordPress.org checksums.
	 *
	 * @return array{ok: bool, issues: array, skipped: int, checked: int}
	 */
	public function run_integrity_check(): array {
		global $wp_version;

		$locale   = get_locale();
		$api_url  = "https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale={$locale}";
		$response = wp_remote_get( $api_url, [ 'timeout' => 15 ] );

		$result = [
			'ok'      => true,
			'issues'  => [],
			'skipped' => 0,
			'checked' => 0,
		];

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			$result['ok']     = false;
			$result['issues'] = [ 'Could not reach WordPress checksums API.' ];
			return $result;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['checksums'] ) ) {
			$result['ok']     = false;
			$result['issues'] = [ 'Invalid checksums response from API.' ];
			return $result;
		}

		$exclusions = $this->get_exclusions();
		$issues     = [];

		foreach ( $body['checksums'] as $relative_path => $expected_md5 ) {

			// Skip intentionally-removed / security-hardened files
			if ( in_array( $relative_path, $exclusions, true ) ) {
				$result['skipped']++;
				continue;
			}

			$result['checked']++;
			$full_path = ABSPATH . $relative_path;

			if ( ! file_exists( $full_path ) ) {
				$issues[] = [
					'type' => 'missing',
					'file' => $relative_path,
					'msg'  => "Missing core file: {$relative_path}",
				];
				continue;
			}

			$actual_md5 = md5_file( $full_path );
			if ( $actual_md5 !== $expected_md5 ) {
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
		}

		// Store last-check timestamp
		update_option( 'mkss_last_file_check', current_time( 'mysql' ) );
		update_option( 'mkss_last_file_check_result', $result );

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

		$rows = '';
		foreach ( $issues as $issue ) {
			$badge = 'modified' === $issue['type']
				? '<span style="background:#e67e22;color:#fff;padding:2px 6px;border-radius:3px;font-size:11px;">MODIFIED</span>'
				: '<span style="background:#c0392b;color:#fff;padding:2px 6px;border-radius:3px;font-size:11px;">MISSING</span>';
			$rows .= "<tr><td style='padding:6px 12px;border-bottom:1px solid #eee;'>{$badge}</td>"
				. "<td style='padding:6px 12px;border-bottom:1px solid #eee;font-family:monospace;'>{$issue['file']}</td></tr>";
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
			<p style='margin-top:16px;'>Please review your site immediately. If you intentionally removed a file for security,
			add it to the <strong>Security Exclusions</strong> list in MK Security Shield settings.</p>
		";

		MKSS_Helper::send_alert( 'Core File Integrity Alert', $body );
		MKSS_Helper::send_slack( '⚠️ Core file integrity issues found: ' . count( $issues ) . ' file(s). Check your admin email.' );
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
		$status = $result['ok'] ? 'ok' : 'issues';
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
