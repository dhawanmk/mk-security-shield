<?php
/** Offline behavioral regressions. No network, email, Slack, or live WordPress writes. */
error_reporting( E_ALL );
set_error_handler( static function ( $severity, $message, $file, $line ) {
	if ( error_reporting() & $severity ) {
		throw new ErrorException( $message, 0, $severity, $file, $line );
	}
	return false;
} );
define( 'ABSPATH', __DIR__ . '/tmp/' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'DAY_IN_SECONDS', 86400 );
@mkdir( ABSPATH, 0777, true );
$options = $transients = $hooks = $http = $requests = $mail = $logs = [];
$admin = false;
$capable = true;
$logged_in = false;
$wp_version = '6.7';
$wp_local_package = 'en_US';
$checks = 0;
class WP_Error {}
class WP_User {}
class Test_Response extends RuntimeException {
	public $data;
	public function __construct( $data ) { $this->data = $data; parent::__construct(); }
}
class Test_DB {
	public $prefix = 'wp_';
	public $blocked = false;
	public function prepare( $sql, ...$args ) { return $sql; }
	public function get_var( $sql ) { return $this->blocked ? 1 : 0; }
	public function insert( $table, $data, $formats ) { $GLOBALS['logs'][] = $data; }
}
$wpdb = new Test_DB();
function get_option( $key, $default = false ) { return array_key_exists( $key, $GLOBALS['options'] ) ? $GLOBALS['options'][$key] : $default; }
function update_option( $key, $value, $autoload = null ) { $GLOBALS['options'][$key] = $value; }
function add_option( $key, $value ) { if ( ! array_key_exists( $key, $GLOBALS['options'] ) ) update_option( $key, $value ); }
function delete_option( $key ) { unset( $GLOBALS['options'][$key] ); }
function get_transient( $key ) { return $GLOBALS['transients'][$key][0] ?? false; }
function set_transient( $key, $value, $ttl ) { $GLOBALS['transients'][$key] = [ $value, $ttl ]; }
function add_action( $name, $callback, $priority = 10, $args = 1 ) { $GLOBALS['hooks'][$name][] = [ $callback, $priority ]; }
function add_filter( ...$args ) { add_action( ...$args ); }
function apply_filters( $name, $value ) { return $value; }
function remove_action( ...$args ) {}
function register_activation_hook( ...$args ) {}
function register_deactivation_hook( ...$args ) {}
function load_plugin_textdomain( ...$args ) {}
function plugin_dir_path( $file ) { return dirname( $file ) . '/'; }
function plugin_dir_url( $file ) { return 'https://example.org/wp-content/plugins/mk-security-shield/'; }
function plugin_basename( $file ) { return basename( $file ); }
function wp_unslash( $value ) { return $value; }
function sanitize_text_field( $value ) { return strip_tags( (string) $value ); }
function sanitize_key( $value ) { return $value; }
function sanitize_email( $value ) { return $value; }
function esc_url_raw( $value ) { return $value; }
function esc_html( $value ) { return htmlspecialchars( (string) $value, ENT_QUOTES ); }
function esc_html__( $value, $domain = '' ) { return $value; }
function __( $value, $domain = '' ) { return $value; }
function wp_kses_post( $value ) { return $value; }
function current_time( $type ) { return '2026-10-09 12:00:00'; }
function get_bloginfo( $key ) { return 'Test Site'; }
function get_current_user_id() { return 1; }
function current_user_can( $cap ) { return $GLOBALS['capable']; }
function is_admin() { return $GLOBALS['admin']; }
function is_user_logged_in() { return $GLOBALS['logged_in']; }
function get_locale() { return 'hi_IN'; }
function wp_parse_url( $url, $component = -1 ) { return parse_url( $url, $component ); }
function add_query_arg( $args, $url ) { return $url . '?' . http_build_query( $args ); }
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function wp_safe_remote_get( $url, $args = [] ) {
	$GLOBALS['requests'][] = [ $url, $args ];
	return $GLOBALS['http'][$url] ?? new WP_Error();
}
function wp_remote_get( ...$args ) { return wp_safe_remote_get( ...$args ); }
function wp_remote_retrieve_response_code( $response ) { return $response['code'] ?? 0; }
function wp_remote_retrieve_body( $response ) { return $response['body'] ?? ''; }
function wp_mail( ...$args ) { $GLOBALS['mail'][] = $args; return true; }
function wp_remote_post( ...$args ) { throw new RuntimeException( 'Unexpected Slack call' ); }
function wp_safe_remote_post( ...$args ) { return wp_remote_post( ...$args ); }
function status_header( $code ) {}
function nocache_headers() {}
function wp_die( $message, $title = '', $args = [] ) { throw new Test_Response( $args['response'] ?? 500 ); }
function check_ajax_referer( ...$args ) {}
function wp_send_json_error( $data ) { throw new Test_Response( [ 'success' => false, 'data' => $data ] ); }
function wp_send_json_success( $data ) { throw new Test_Response( [ 'success' => true, 'data' => $data ] ); }
function expect( $condition, $message ) {
	$GLOBALS['checks']++;
	if ( ! $condition ) throw new RuntimeException( 'FAIL: ' . $message );
}
function response( $body, $code = 200 ) { return [ 'code' => $code, 'body' => is_string( $body ) ? $body : json_encode( $body ) ]; }
function request( $ip = '198.51.100.5', $ua = 'Claude-User/1.0', $path = '/products/', $method = 'GET' ) {
	$_SERVER = [ 'REMOTE_ADDR' => $ip, 'HTTP_USER_AGENT' => $ua, 'REQUEST_URI' => $path, 'REQUEST_METHOD' => $method ];
	$_GET = $_POST = [];
}
function denied( callable $fn ) {
	try { $fn(); return false; } catch ( Test_Response $e ) { return 403 === $e->data; }
}

// Exercise the actual plugin entrypoint: previously fatal because two required files were absent.
require dirname( __DIR__ ) . '/mk-security-shield.php';
foreach ( $hooks['plugins_loaded'] as $hook ) { $hook[0](); }
expect( null !== MK_Security_Shield::get_instance()->get_module( 'file_monitor' ), 'plugin boots all shipped modules' );
expect( class_exists( 'MKSS_AI_Connect' ), 'AI module is packaged' );
expect( null === MK_Security_Shield::get_instance()->get_module( 'two_factor' ), 'missing 2FA is not represented as protection' );

$options = [ 'mkss_enable_geo' => true, 'mkss_geo_mode' => 'whitelist', 'mkss_geo_allowed_countries' => "in,US\nIN" ];
MKSS_Helper::migrate_options();
expect( true === get_option( 'mkss_geo_restriction_enabled' ), 'legacy enable migrates' );
expect( 'allowlist' === get_option( 'mkss_geo_mode' ), 'legacy mode migrates' );
expect( [ 'IN', 'US' ] === get_option( 'mkss_geo_allowed_countries' ), 'legacy country text normalized' );
$options = [ 'mkss_geo_restriction_enabled' => false, 'mkss_geo_enabled' => true ];
MKSS_Helper::migrate_options();
expect( false === get_option( 'mkss_geo_restriction_enabled' ), 'explicit current disabled setting wins' );
expect( [ 'IN', 'US' ] === MKSS_Helper::country_codes( [ 'in', 'US', 'XX', [], 'INVALID' ] ), 'array country validation' );

foreach ( [ [ '198.51.100.255', '198.51.100.0/24', true ], [ '198.51.101.0', '198.51.100.0/24', false ], [ '2001:db8:abcd::1', '2001:db8::/32', true ], [ '2001:db9::', '2001:db8::/32', false ], [ '2001:db8::1', '198.51.100.0/24', false ], [ '1.2.3.4', '0.0.0.0/0', false ], [ '1.2.3.4', '1.2.3.4/33', false ], [ '1.2.3.4', '1.2.3.4/-1', false ], [ '1.2.3.4', '1.2.3.4/32/1', false ], [ '198.51.100.127', '198.51.100.0/25', true ], [ '198.51.100.128', '198.51.100.0/25', false ] ] as $case ) {
	expect( $case[2] === MKSS_Helper::ip_in_cidr( $case[0], $case[1] ), 'CIDR boundary ' . $case[1] );
}
request();
$_SERVER['HTTP_CF_CONNECTING_IP'] = '1.1.1.1';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '1.0.0.1';
expect( '198.51.100.5' === MKSS_Helper::get_ip(), 'direct forged forwarded headers ignored' );
$_SERVER['REMOTE_ADDR'] = '173.245.48.10';
expect( '1.1.1.1' === MKSS_Helper::get_ip(), 'Cloudflare IPv4 peer accepts CF client IP' );
$_SERVER['REMOTE_ADDR'] = '2606:4700::1234';
expect( '1.1.1.1' === MKSS_Helper::get_ip(), 'Cloudflare IPv6 peer accepts CF client IP' );
$_SERVER['HTTP_CF_CONNECTING_IP'] = '1.1.1.1,2.2.2.2';
expect( '2606:4700::1234' === MKSS_Helper::get_ip(), 'invalid single-IP header rejected' );

$http['https://ipapi.co/1.1.1.1/country/'] = response( 'US' );
expect( 'US' === MKSS_Helper::get_country( '1.1.1.1' ), 'valid country lookup' );
$before = count( $requests );
expect( 'US' === MKSS_Helper::get_country( '1.1.1.1' ) && $before === count( $requests ), 'country success cache' );
expect( '' === MKSS_Helper::get_country( '127.0.0.1' ), 'local address does not use geo API' );
expect( '' === MKSS_Helper::get_country( '8.8.8.8' ), 'geo outage returns unknown' );
$before = count( $requests );
expect( '' === MKSS_Helper::get_country( '8.8.8.8' ) && $before === count( $requests ), 'geo outage negative cache' );
$http['https://ipapi.co/9.9.9.9/country/'] = response( '<html>Error</html>' );
expect( '' === MKSS_Helper::get_country( '9.9.9.9' ), 'invalid country response remains unknown' );

$feeds = [ 'ChatGPT-User' => 'https://openai.com/chatgpt-user.json', 'OAI-SearchBot' => 'https://openai.com/searchbot.json', 'Claude-User' => 'https://claude.com/crawling/bots.json', 'Claude-SearchBot' => 'https://claude.com/crawling/bots.json' ];
foreach ( $feeds as $bot => $url ) {
	$http[$url] = response( [ 'prefixes' => [ [ 'ipv4Prefix' => '198.51.100.0/24' ], [ 'ipv6Prefix' => '2001:db8::/32' ] ] ] );
	request( '198.51.100.5', 'Mozilla/5.0 (compatible; ' . $bot . '/1.0)' );
	expect( MKSS_AI_Connect::can_bypass_geo(), 'verified bot ' . $bot );
}
request( '2001:db8::1' );
expect( MKSS_AI_Connect::can_bypass_geo(), 'verified IPv6 bot' );
request( '198.51.101.5' );
$_SERVER['HTTP_CF_CONNECTING_IP'] = '198.51.100.5';
expect( ! MKSS_AI_Connect::can_bypass_geo(), 'forged bot IP/header has no exception' );
request( '198.51.100.5', 'PretendClaude-User/1.0' );
expect( ! MKSS_AI_Connect::can_bypass_geo(), 'bot token must match fully' );
foreach ( [ 'GPTBot/1.0', 'ClaudeBot/1.0', 'python-requests/2.0' ] as $ua ) {
	request( '198.51.100.5', $ua );
	expect( ! MKSS_AI_Connect::can_bypass_geo(), 'training/generic bot excluded ' . $ua );
}
foreach ( [ '/wp-login.php', '/wp-admin/', '/wp-json/wp/v2/posts', '/?rest_route=/wp/v2/posts', '/wp%2dadmin/', '/xmlrpc.php', '/mcp/', '/oauth/', '/foo.php', '/../wp-admin' ] as $path ) {
	request( '198.51.100.5', 'Claude-User/1.0', $path );
	if ( strpos( $path, 'rest_route' ) !== false ) $_GET['rest_route'] = '/wp/v2/posts';
	expect( ! MKSS_AI_Connect::can_bypass_geo(), 'protected path excluded ' . $path );
}
request( '198.51.100.5', 'Claude-User/1.0', '/', 'POST' );
expect( ! MKSS_AI_Connect::can_bypass_geo(), 'POST has no AI exception' );
request( '198.51.100.5', 'Claude-User/1.0', '/', 'HEAD' );
expect( MKSS_AI_Connect::can_bypass_geo(), 'HEAD public read allowed' );
request( '198.51.100.5', 'Claude-User/1.0', '/caf%C3%A9/' );
expect( MKSS_AI_Connect::can_bypass_geo(), 'international public slug allowed' );
$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer test';
expect( ! MKSS_AI_Connect::can_bypass_geo(), 'authorization does not acquire crawler exemption' );
request();
$options['mkss_geo_allow_verified_ai'] = false;
expect( ! MKSS_AI_Connect::can_bypass_geo(), 'admin can disable exception' );
$options['mkss_geo_allow_verified_ai'] = true;
$transients = [];
$http['https://claude.com/crawling/bots.json'] = new WP_Error();
expect( ! MKSS_AI_Connect::can_bypass_geo(), 'provider outage fails verification closed' );
$before = count( $requests );
expect( ! MKSS_AI_Connect::can_bypass_geo() && count( $requests ) === $before, 'provider outage cached' );
$transients = [];
$http['https://claude.com/crawling/bots.json'] = response( [ 'prefixes' => [ [ 'ipv4Prefix' => '0.0.0.0/0' ], 'malformed' ] ] );
expect( ! MKSS_AI_Connect::can_bypass_geo(), 'unsafe/malformed feed grants no access' );
$transients = [];
$http['https://claude.com/crawling/bots.json'] = response( [ 'prefixes' => [ [ 'ipv4Prefix' => '198.51.100.0/24' ] ] ] );

// Geo behavior through its registered front-end hook.
$options['mkss_geo_restriction_enabled'] = true;
$options['mkss_geo_mode'] = 'allowlist';
$options['mkss_geo_allowed_countries'] = [ 'IN' ];
$geo = new MKSS_Geo_Restriction();
expect( isset( $hooks['template_redirect'] ), 'geo runs after routing' );
$transients['mkss_geo_' . md5( '198.51.100.5' )] = [ 'US', DAY_IN_SECONDS ];
request();
expect( ! denied( [ $geo, 'check_visitor_country' ] ), 'verified US AI reads India-only site' );
request( '198.51.100.5', 'Mozilla/5.0' );
expect( denied( [ $geo, 'check_visitor_country' ] ), 'ordinary US visitor remains geo-blocked' );
$transients['mkss_geo_' . md5( '198.51.100.5' )] = [ 'IN', DAY_IN_SECONDS ];
expect( ! denied( [ $geo, 'check_visitor_country' ] ), 'allowed-country visitor passes' );
$options['mkss_geo_mode'] = 'blocklist';
$options['mkss_geo_blocked_countries'] = 'in,US';
expect( denied( [ $geo, 'check_visitor_country' ] ), 'legacy text blocklist applies' );
request( '8.8.8.8', 'Mozilla/5.0' );
expect( ! denied( [ $geo, 'check_visitor_country' ] ), 'geo API outage does not lock out visitors' );

// A verified crawler still faces active IP blocks and encoded attack rules.
$firewall = new MKSS_Firewall();
request( '198.51.100.5', 'Claude-User/1.0', '/?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E' );
expect( denied( [ $firewall, 'run' ] ), 'double-encoded XSS blocked for AI' );
request( '198.51.100.5', 'Claude-User/1.0', '/%252e%252e%252fwp-config.php' );
expect( denied( [ $firewall, 'run' ] ), 'double-encoded traversal blocked' );
request();
$wpdb->blocked = true;
expect( denied( [ $firewall, 'run' ] ), 'blocked AI IP stays blocked' );
$wpdb->blocked = false;
$prior_error = new WP_Error();
expect( $prior_error === $firewall->restrict_rest_api( $prior_error ), 'REST authentication error preserved' );

// Missing-only exclusions and actual checksum changes.
$options['mkss_notify_on_file_change'] = true;
$options['mkss_security_exclusions'] = [ 'readme.html' ];
$manifest_url = 'https://api.wordpress.org/core/checksums/1.0/?version=6.7&locale=en_US';
$manifest = [ 'readme.html' => md5( 'official readme' ), 'wp-trackback.php' => md5( 'trackback' ), 'index.php' => md5( 'core' ) ];
file_put_contents( ABSPATH . 'wp-trackback.php', 'trackback' );
file_put_contents( ABSPATH . 'index.php', 'core' );
$http[$manifest_url] = response( [ 'checksums' => $manifest ] );
$monitor = new MKSS_File_Monitor();
$mail = [];
$result = $monitor->run_integrity_check();
expect( $result['ok'] && 1 === $result['skipped'] && 2 === $result['checked'], 'missing readme is excluded, executable files checked' );
expect( empty( $mail ), 'missing readme sends no alarm' );
expect( $manifest_url === end( $requests )[0], 'installed package locale used instead of UI language' );
file_put_contents( ABSPATH . 'readme.html', 'tampered' );
$result = $monitor->run_integrity_check();
expect( ! $result['ok'] && 'modified' === $result['issues'][0]['type'], 'present excluded file is checked' );
expect( 1 === count( $mail ), 'real change notifies' );
$monitor->run_integrity_check();
expect( 1 === count( $mail ), 'unchanged alert deduplicated' );
file_put_contents( ABSPATH . 'readme.html', 'changed again' );
$monitor->run_integrity_check();
expect( 2 === count( $mail ), 'new content notifies inside cooldown' );
unlink( ABSPATH . 'readme.html' );
unlink( ABSPATH . 'wp-trackback.php' );
$result = $monitor->run_integrity_check();
expect( 'wp-trackback.php' === $result['issues'][0]['file'], 'missing executable wp-trackback is not silently excluded' );
file_put_contents( ABSPATH . 'wp-trackback.php', 'trackback' );
$monitor->run_integrity_check();
expect( false === get_option( 'mkss_integrity_alert_state' ), 'clean result resets notification state' );
$before = count( $mail );
$http[$manifest_url] = new WP_Error();
$result = $monitor->run_integrity_check();
expect( ! $result['ok'] && 'error' === $result['status'] && empty( $result['issues'] ), 'API failure is unverified rather than infection' );
expect( $before === count( $mail ) && $result === get_option( 'mkss_last_file_check_result' ), 'failed scan stored without false email' );
$http[$manifest_url] = response( [ 'checksums' => [ '../outside.php' => md5( 'bad' ) ] ] );
expect( 'error' === $monitor->run_integrity_check()['status'], 'manifest path traversal rejected' );
$http[$manifest_url] = response( [ 'checksums' => [ 'index.php' => 'invalid' ] ] );
expect( 'error' === $monitor->run_integrity_check()['status'], 'invalid checksum rejected' );
$options['core_updater.lock'] = time();
$before = count( $requests );
expect( 'deferred' === $monitor->run_integrity_check()['status'] && count( $requests ) === $before, 'active core update defers scan' );
delete_option( 'core_updater.lock' );

// Save only the displayed tab; reject invalid arrays and unauthorized users.
$settings = new MKSS_Settings();
$options['mkss_block_sql_injection'] = true;
$options['mkss_max_login_attempts'] = 9;
$_POST = [ 'settings' => [ 'mkss_geo_restriction_enabled' => '1', 'mkss_geo_allow_verified_ai' => '0', 'mkss_geo_allowed_countries' => "in,US\nIN" ] ];
try { $settings->ajax_save(); } catch ( Test_Response $e ) { expect( $e->data['success'], 'geo settings saved' ); }
expect( true === get_option( 'mkss_block_sql_injection' ) && 9 === get_option( 'mkss_max_login_attempts' ), 'saving geo preserves firewall/login settings' );
expect( [ 'IN', 'US' ] === get_option( 'mkss_geo_allowed_countries' ) && false === get_option( 'mkss_geo_allow_verified_ai' ), 'geo settings normalize and unchecked toggles save' );
$_POST = [ 'settings' => [ 'mkss_geo_mode' => [] ] ];
try { $settings->ajax_save(); } catch ( Test_Response $e ) { expect( ! $e->data['success'], 'nested value rejected' ); }
$capable = false;
$_POST = [ 'settings' => [ 'mkss_geo_restriction_enabled' => '0' ] ];
try { $settings->ajax_save(); } catch ( Test_Response $e ) { expect( ! $e->data['success'], 'non-admin save rejected' ); }
expect( true === get_option( 'mkss_geo_restriction_enabled' ), 'non-admin cannot change geo' );
$capable = true;
$_POST = [ 'settings' => [ 'mkss_notify_slack_webhook' => 'https://127.0.0.1/internal' ] ];
try { $settings->ajax_save(); } catch ( Test_Response $e ) { expect( ! $e->data['success'], 'non-Slack webhook rejected' ); }
expect( false === get_option( 'mkss_notify_slack_webhook' ), 'invalid webhook not persisted' );

// Custom host proxy chains: walk from the trusted peer toward the client, never trust the leftmost value blindly.
define( 'MKSS_TRUSTED_PROXIES', [ '10.0.0.0/8' ] );
define( 'MKSS_CLIENT_IP_HEADER', 'HTTP_X_FORWARDED_FOR' );
request( '10.0.0.1' );
$_SERVER['HTTP_X_FORWARDED_FOR'] = '1.1.1.1, 198.51.100.5, 10.0.0.2';
expect( '198.51.100.5' === MKSS_Helper::get_ip(), 'rightmost untrusted proxy-chain client wins' );
$_SERVER['HTTP_X_FORWARDED_FOR'] = '1.1.1.1, malformed';
expect( '10.0.0.1' === MKSS_Helper::get_ip(), 'malformed proxy chain falls back to peer' );

foreach ( [ 'index.php', 'wp-trackback.php' ] as $file ) { unlink( ABSPATH . $file ); }
rmdir( ABSPATH );
echo "PASS: {$checks} behavioral assertions; no network or messages sent.\n";
