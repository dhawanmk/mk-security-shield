<?php
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

if ( ! function_exists( 'insert_with_markers' ) ) {
	require_once ABSPATH . 'wp-admin/includes/misc.php';
}

global $wpdb;

delete_option( 'mkss_settings' );
delete_option( 'mkss_file_monitor_results' );
delete_option( 'mkss_malware_scan_results' );

// Revoke (but do not delete) the AI Assistant service account's credential
// and role. The user account itself is left in place — it may be the
// author of real content — but it loses both its role and its Application
// Password, so it has no access of any kind once the plugin is gone.
$ai_connection = get_option( 'mkss_ai_connect', array() );
if ( ! empty( $ai_connection['user_id'] ) ) {
	if ( class_exists( 'WP_Application_Passwords' ) ) {
		WP_Application_Passwords::delete_all_application_passwords( $ai_connection['user_id'] );
	}
	$ai_user = get_user_by( 'id', $ai_connection['user_id'] );
	if ( $ai_user ) {
		$ai_user->set_role( '' );
	}
}
remove_role( 'mkss_ai_assistant' );
delete_option( 'mkss_ai_connect' );

$table = $wpdb->prefix . 'mkss_activity_log';
$wpdb->query( "DROP TABLE IF EXISTS {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

$users = get_users( array( 'fields' => 'ID' ) );
foreach ( $users as $user_id ) {
	delete_user_meta( $user_id, 'mkss_2fa_secret' );
	delete_user_meta( $user_id, 'mkss_2fa_enabled' );
	delete_user_meta( $user_id, 'mkss_2fa_pending_secret' );
}

// Best-effort .htaccess cleanup (Apache only); silently skip on read-only filesystems.
$htaccess = ABSPATH . '.htaccess';
if ( file_exists( $htaccess ) && is_writable( $htaccess ) ) {
	insert_with_markers( $htaccess, 'MK Security Shield', array() );
}

$timestamp = wp_next_scheduled( 'mkss_file_monitor_scan' );
if ( $timestamp ) {
	wp_unschedule_event( $timestamp, 'mkss_file_monitor_scan' );
}
$timestamp = wp_next_scheduled( 'mkss_malware_scan' );
if ( $timestamp ) {
	wp_unschedule_event( $timestamp, 'mkss_malware_scan' );
}
