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
$capable = false;
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


function wp_parse_args( $a, $b ) { return array_merge( $b, (array) $a ); }
function wp_generate_password( ...$args ) { return str_repeat( 'x', 32 ); }
function wp_next_scheduled( $name ) { return false; }
function wp_schedule_event( $time, $recurrence, $hook ) { $GLOBALS['scheduled'][$hook] = $recurrence; }
function wp_doing_cron() { return false; }
function wpautop( $v ) { return $v; }
function home_url( $v = '' ) { return 'https://example.org' . $v; }
function sanitize_textarea_field( $v ) { return $v; }
function do_action( $name, ...$args ) { $GLOBALS['actions'][] = $name; }
function is_email( $v ) { return filter_var( $v, FILTER_VALIDATE_EMAIL ); }
function insert_with_markers( ...$args ) { return true; }
function wp_get_upload_dir() { return [ 'basedir' => ABSPATH ]; }
function trailingslashit( $v ) { return rtrim( $v, '/' ) . '/'; }
function set_setting( $key, $value ) {
    $p = new ReflectionProperty( MKSS_Settings::class, 'options' ); if ( PHP_VERSION_ID < 80100 ) { $p->setAccessible( true ); }
    $settings = MKSS_Settings::instance(); $values = $p->getValue( $settings ); $values[$key] = $value; $p->setValue( $settings, $values );
}
$options['mkss_settings'] = [ 'login_lockout_minutes' => 20, 'login_math_captcha' => 1, 'disable_file_edit' => 0, 'geo_restriction_enabled' => 1, 'geo_confirmed_cloudflare' => 1, 'geo_allowed_countries' => 'IN,NP,LK,AE', 'firewall_mode' => 'log' ];
require dirname( __DIR__ ) . '/mk-security-shield.php';
foreach ( $hooks['plugins_loaded'] as $hook ) { $hook[0](); }
expect( class_exists( 'MKSS_Two_Factor' ) && class_exists( 'MKSS_AI_Connect' ) && class_exists( 'MKSS_Verified_AI' ), 'legacy 2FA and AI account modules plus public verification boot' );
expect( 20 === MKSS_Settings::instance()->get( 'login_lockout_minutes' ), 'existing settings retained' );
expect( 1 === MKSS_Settings::instance()->get( 'login_math_captcha' ) && isset( $hooks['login_form'] ), 'existing login challenge retained' );
expect( 'daily' === $scheduled['mkss_file_monitor_scan'] && 'daily' === $scheduled['mkss_malware_scan'], 'legacy daily integrity and malware schedules retained' );
expect( ! isset( $hooks['wp_is_application_passwords_available'] ), 'existing application password availability preserved' );
expect( isset( $hooks['rest_dispatch_request'] ) && ! isset( $hooks['rest_authentication_errors'] ) && isset( $hooks['template_redirect'] ), 'geo waits until routing, REST authentication and route permissions' );
expect( DONOTCACHEPAGE, 'geo responses cannot share full-page cache' );
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

$feeds = [ 'ChatGPT-User' => 'https://openai.com/chatgpt-user.json', 'OAI-SearchBot' => 'https://openai.com/searchbot.json', 'Claude-User' => 'https://claude.com/crawling/bots.json', 'Claude-SearchBot' => 'https://claude.com/crawling/bots.json' ];
foreach ( $feeds as $bot => $url ) {
	$http[$url] = response( [ 'prefixes' => [ [ 'ipv4Prefix' => '198.51.100.0/24' ], [ 'ipv6Prefix' => '2001:db8::/32' ] ] ] );
	request( '198.51.100.5', 'Mozilla/5.0 (compatible; ' . $bot . '/1.0)' );
	expect( MKSS_Verified_AI::can_bypass_geo(), 'verified bot ' . $bot );
}
request( '2001:db8::1' );
expect( MKSS_Verified_AI::can_bypass_geo(), 'verified IPv6 bot' );
request( '198.51.101.5' );
$_SERVER['HTTP_CF_CONNECTING_IP'] = '198.51.100.5';
expect( ! MKSS_Verified_AI::can_bypass_geo(), 'forged bot IP/header has no exception' );
request( '198.51.100.5', 'PretendClaude-User/1.0' );
expect( ! MKSS_Verified_AI::can_bypass_geo(), 'bot token must match fully' );
foreach ( [ 'GPTBot/1.0', 'ClaudeBot/1.0', 'python-requests/2.0' ] as $ua ) {
	request( '198.51.100.5', $ua );
	expect( ! MKSS_Verified_AI::can_bypass_geo(), 'training/generic bot excluded ' . $ua );
}
foreach ( [ '/wp-login.php', '/wp-admin/', '/wp-json/wp/v2/posts', '/?rest_route=/wp/v2/posts', '/wp%2dadmin/', '/xmlrpc.php', '/mcp/', '/oauth/', '/foo.php', '/../wp-admin' ] as $path ) {
	request( '198.51.100.5', 'Claude-User/1.0', $path );
	if ( strpos( $path, 'rest_route' ) !== false ) $_GET['rest_route'] = '/wp/v2/posts';
	expect( ! MKSS_Verified_AI::can_bypass_geo(), 'protected path excluded ' . $path );
}
request( '198.51.100.5', 'Claude-User/1.0', '/', 'POST' );
expect( ! MKSS_Verified_AI::can_bypass_geo(), 'POST has no AI exception' );
request( '198.51.100.5', 'Claude-User/1.0', '/', 'HEAD' );
expect( MKSS_Verified_AI::can_bypass_geo(), 'HEAD public read allowed' );
request( '198.51.100.5', 'Claude-User/1.0', '/caf%C3%A9/' );
expect( MKSS_Verified_AI::can_bypass_geo(), 'international public slug allowed' );
$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer test';
expect( ! MKSS_Verified_AI::can_bypass_geo(), 'authorization does not acquire crawler exemption' );
request();
set_setting( 'geo_allow_verified_ai', false );
expect( ! MKSS_Verified_AI::can_bypass_geo(), 'admin can disable exception' );
set_setting( 'geo_allow_verified_ai', true );
$transients = [];
$http['https://claude.com/crawling/bots.json'] = new WP_Error();
expect( ! MKSS_Verified_AI::can_bypass_geo(), 'provider outage fails verification closed' );
$before = count( $requests );
expect( ! MKSS_Verified_AI::can_bypass_geo() && count( $requests ) === $before, 'provider outage cached' );
$transients = [];
$http['https://claude.com/crawling/bots.json'] = response( [ 'prefixes' => [ [ 'ipv4Prefix' => '0.0.0.0/0' ], 'malformed' ] ] );
expect( ! MKSS_Verified_AI::can_bypass_geo(), 'unsafe/malformed feed grants no access' );
$transients = [];
$http['https://claude.com/crawling/bots.json'] = response( [ 'prefixes' => [ [ 'ipv4Prefix' => '198.51.100.0/24' ] ] ] );


$geo = MKSS_Geo_Restriction::instance();
request(); expect( ! denied( [ $geo, 'enforce' ] ), 'verified overseas AI reads restricted public page' );
request( '198.51.100.5', 'Mozilla/5.0' ); expect( denied( [ $geo, 'enforce' ] ), 'unverified direct-origin request is denied' );
request( '173.245.48.10', 'Mozilla/5.0' ); $_SERVER['HTTP_CF_CONNECTING_IP'] = '198.51.101.5'; $_SERVER['HTTP_CF_IPCOUNTRY'] = 'US';
expect( denied( [ $geo, 'enforce' ] ), 'ordinary overseas visitor remains blocked' );
$_SERVER['HTTP_USER_AGENT'] = 'Claude-User/1.0'; expect( denied( [ $geo, 'enforce' ] ), 'spoofed AI user agent stays blocked' );
$_SERVER['HTTP_CF_CONNECTING_IP'] = '198.51.100.5'; expect( ! denied( [ $geo, 'enforce' ] ), 'trusted proxy verified AI passes' );
$_SERVER['REQUEST_URI'] = '/wp-login.php'; expect( denied( [ $geo, 'enforce' ] ), 'verified AI has no login exemption' );
$_SERVER['REQUEST_URI'] = '/products/'; $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0'; $_SERVER['HTTP_CF_IPCOUNTRY'] = 'IN';
expect( ! denied( [ $geo, 'enforce' ] ), 'allowed visitor country passes' );
unset( $_SERVER['HTTP_CF_IPCOUNTRY'] ); expect( denied( [ $geo, 'enforce' ] ), 'unknown country remains denied under existing policy' );
$capable = true; request( '198.51.101.5', 'Mozilla/5.0' ); expect( ! denied( [ $geo, 'enforce' ] ), 'authenticated administrator retains recovery access' ); $capable = false;
$prior = new WP_Error(); expect( $geo->enforce_rest( $prior ) === $prior, 'REST auth error is preserved' );
$logged_in = true; expect( null === $geo->enforce_rest( null ), 'late authenticated connector dispatch proceeds without adding capabilities' ); $logged_in = false;
expect( denied( static function () use ( $geo ) { $geo->enforce_rest( null ); } ), 'anonymous protected REST dispatch still faces country rules' );
expect( [ 'prior' => 'response' ] === $geo->enforce_rest( [ 'prior' => 'response' ] ), 'existing REST dispatch response is preserved' );
$geo->disable_geo_cache(); expect( in_array( 'litespeed_control_set_nocache', $actions, true ), 'LiteSpeed receives no-cache directive' );
$firewall = MKSS_Firewall::instance(); request( '198.51.100.5', 'Claude-User/1.0', '/?q=%253Cscript%253Etest%253C%252Fscript%253E' );
expect( ! denied( [ $firewall, 'inspect_request' ] ) && 'firewall_match' === end( $logs )['event_type'], 'encoded threat is logged in existing log-only mode' );
set_setting( 'firewall_mode', 'block' ); expect( denied( [ $firewall, 'inspect_request' ] ), 'encoded threat blocked with actual HTTP 403 in block mode' );
request(); $_POST = [ 'nested' => [ 'value' => 'etc/passwd' ] ]; expect( denied( [ $firewall, 'inspect_request' ] ), 'POST body threat remains checked' );
set_setting( 'firewall_mode', 'log' );
// Missing-only exclusions and actual checksum changes.
$options['mkss_notify_on_file_change'] = true;
$options['mkss_security_exclusions'] = [ 'readme.html' ];
$manifest_url = 'https://api.wordpress.org/core/checksums/1.0/?version=6.7&locale=en_US';
$manifest = [ 'readme.html' => md5( 'official readme' ), 'wp-trackback.php' => md5( 'trackback' ), 'index.php' => md5( 'core' ) ];
file_put_contents( ABSPATH . 'wp-trackback.php', 'trackback' );
file_put_contents( ABSPATH . 'index.php', 'core' );
$http[$manifest_url] = response( [ 'checksums' => $manifest ] );
$monitor = new MKSS_Integrity_Engine();
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


$manifest = [ 'index.php' => md5( 'core' ), 'wp-content/themes/custom.php' => md5( 'default' ) ];
$http[$manifest_url] = response( [ 'checksums' => $manifest ] );
expect( $monitor->run_integrity_check()['ok'], 'custom wp-content is excluded from core verification' );
$manifest['wp-content/themes/theme/assets/VariableFont_slnt,wght.ttf'] = md5( 'font' );
$manifest['wp-content/plugins/plugin/logo@2x.png'] = md5( 'image' );
$http[$manifest_url] = response( [ 'checksums' => $manifest ] );
expect( $monitor->run_integrity_check()['ok'], 'legitimate comma and at-sign paths in official manifests are accepted safely' );
$scanner = MKSS_Malware_Scanner::instance();
$scan_method = new ReflectionMethod( MKSS_Malware_Scanner::class, 'scan_contents' );
if ( PHP_VERSION_ID < 80100 ) { $scan_method->setAccessible( true ); }
$matches = [];
$own_source = file_get_contents( dirname( __DIR__ ) . '/includes/class-mkss-malware-scanner.php' );
$args = [ $own_source, 'scanner.php', &$matches ]; $scan_method->invokeArgs( $scanner, $args );
expect( empty( $matches ), 'scanner does not flag its own literal signature database' );
foreach ( [ 'FilesMan', 'c99shell', 'r57shell', 'b374k' ] as $marker ) {
    $matches = []; $args = [ $marker, 'fixture.php', &$matches ]; $scan_method->invokeArgs( $scanner, $args );
    expect( 1 === count( $matches ), 'marker detection retained for ' . $marker );
}
$result = MKSS_File_Monitor::instance()->run_scan();
expect( 'complete' === $result['status'] && isset( get_option( 'mkss_file_monitor_results' )['time'] ), 'legacy results UI receives new verified status' );
$values = $options['mkss_settings']; $values['harden_htaccess'] = 0; $values['firewall_mode'] = 'log'; $values['notify_email'] = 'owner@example.org';
$values['geo_allow_verified_ai'] = 1; $values['geo_bypass_key'] = str_repeat( 'b', 32 );
$clean = MKSS_Settings::instance()->sanitize( $values );
expect( 20 === $clean['login_lockout_minutes'] && 1 === $clean['login_math_captcha'] && 0 === $clean['disable_file_edit'], 'settings save preserves prior selected controls' );
expect( 'IN,NP,LK,AE' === $clean['geo_allowed_countries'] && 1 === $clean['geo_allow_verified_ai'], 'legacy countries and new AI control save together' );
expect( in_array( 'litespeed_purge_all', $actions, true ), 'settings changes purge previous page cache decisions' );
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
