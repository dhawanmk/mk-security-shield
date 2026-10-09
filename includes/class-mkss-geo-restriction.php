<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Restricts site access to visitors from an allowed list of countries,
 * determined from Cloudflare's CF-IPCountry header.
 *
 * This is a real defense against opportunistic bot/attack traffic from
 * outside a site's target markets, but it has hard limits worth being clear
 * about:
 *
 * - It ONLY works if the site's DNS is actually proxied through Cloudflare
 *   (orange-clouded). If it isn't, this module refuses to activate at all
 *   (see the admin notice) rather than silently trusting a header nobody is
 *   actually setting.
 * - Even with Cloudflare in front, if an attacker discovers the origin
 *   server's real IP address, they can connect to it directly and bypass
 *   Cloudflare (and this restriction) entirely. This module mitigates that
 *   by verifying the direct TCP peer is actually a Cloudflare edge IP before
 *   trusting anything it says — but the durable fix is a server/firewall
 *   rule that only accepts connections from Cloudflare's published IP
 *   ranges (https://www.cloudflare.com/ips/). That's outside what a
 *   WordPress plugin can configure.
 * - Country IP geolocation is inherently approximate, and anyone using a
 *   VPN/proxy in an allowed country bypasses it trivially. Treat this as
 *   noise reduction, not a hard perimeter.
 */
class MKSS_Geo_Restriction {

	const COOKIE_NAME           = 'mkss_geo_bypass';
	const CRAWLER_CACHE_PREFIX  = 'mkss_crawler_';

	/**
	 * Cloudflare's published IP ranges. Verify periodically against
	 * https://www.cloudflare.com/ips/ — these change rarely, but do change.
	 */
	const CLOUDFLARE_CIDRS = array(
		'173.245.48.0/20',
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'141.101.64.0/18',
		'108.162.192.0/18',
		'190.93.240.0/20',
		'188.114.96.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'162.158.0.0/15',
		'104.16.0.0/13',
		'104.24.0.0/14',
		'172.64.0.0/13',
		'131.0.72.0/22',
		'2400:cb00::/32',
		'2606:4700::/32',
		'2803:f800::/32',
		'2405:b500::/32',
		'2405:8100::/32',
		'2a06:98c0::/29',
		'2c0f:f248::/32',
	);

	private static $instance = null;

	private $known_crawlers = array(
		'Googlebot'   => array( '.googlebot.com', '.google.com' ),
		'bingbot'     => array( '.search.msn.com' ),
		'DuckDuckBot' => array( '.duckduckgo.com' ),
	);

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'admin_notices', array( $this, 'maybe_render_warning' ) );

		if ( ! MKSS_Settings::instance()->get( 'geo_restriction_enabled' ) ) {
			return;
		}

		// Wait until routes/authentication are established. Never share geo decisions in a page cache.
        if ( ! defined( 'DONOTCACHEPAGE' ) ) { define( 'DONOTCACHEPAGE', true ); }
        add_action( 'template_redirect', array( $this, 'enforce' ), 0 );
        add_action( 'login_init', array( $this, 'enforce' ), 0 );
        add_action( 'admin_init', array( $this, 'enforce' ), 0 );
        // Runs after authentication and the route's permission callback, including connector auth.
        add_filter( 'rest_dispatch_request', array( $this, 'enforce_rest' ), 99 );
        add_action( 'init', array( $this, 'disable_geo_cache' ), 0 );
	}

	public function maybe_render_warning() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$settings = MKSS_Settings::instance();
		if ( $settings->get( 'geo_restriction_enabled' ) && ! $settings->get( 'geo_confirmed_cloudflare' ) ) {
			echo '<div class="notice notice-warning"><p>' .
				esc_html__( 'MK Security Shield: Geo-restriction is turned on but NOT active yet — confirm your site is proxied through Cloudflare under Security Shield → Settings before it takes effect. This prevents trusting a country header on a site that isn\'t actually behind Cloudflare.', 'mk-security-shield' ) .
				'</p></div>';
		}
	}

    public function disable_geo_cache() {
        do_action( 'litespeed_control_set_nocache', 'MKSS country access decisions' );
        nocache_headers();
    }

    public function enforce_rest( $result ) {
        if ( null !== $result || is_user_logged_in() ) { return $result; }
        $this->enforce();
        return $result;
    }

	public function enforce() {
		if ( current_user_can( 'manage_options' ) || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}

		$settings = MKSS_Settings::instance();

		if ( ! $settings->get( 'geo_confirmed_cloudflare' ) ) {
			return;
		}

		if ( $this->handle_bypass_key() ) {
			return; // Redirected.
		}

		if ( $this->has_valid_bypass_cookie() ) {
			return;
		}

        // IP verification uses trusted proxy peers, never a request-supplied AI identity.
        if ( MKSS_Verified_AI::can_bypass_geo() ) {
            MKSS_Activity_Log::log( 'geo_verified_ai', 'Allowed verified AI public page retrieval' );
            return;
        }

		// Some hosts (Hostinger, Kinsta, WP Engine, SiteGround, and many
		// others) automatically rewrite REMOTE_ADDR from Cloudflare's edge
		// IP back to the real visitor IP at the web-server level, before
		// PHP ever runs — a normal, often-desirable feature for logging and
		// analytics. When that happens, this check can never see a genuine
		// Cloudflare IP no matter how correctly Cloudflare itself is
		// configured, because the evidence has already been overwritten by
		// the time it reaches WordPress. The site owner has to explicitly
		// confirm their host does this (mirroring the Cloudflare
		// confirmation above) rather than this silently and permanently
		// failing closed.
		if ( ! $settings->get( 'geo_host_restores_real_ip' ) && ! $this->is_request_from_cloudflare() ) {
			MKSS_Activity_Log::log( 'geo_blocked_origin_direct', 'Blocked request that did not arrive via a Cloudflare edge IP — cannot trust country header' );
			$this->deny();
			return;
		}

		if ( $settings->get( 'geo_allow_verified_crawlers' ) && $this->is_verified_crawler() ) {
			return;
		}

		$country = $this->get_visitor_country();
		$allowed = $this->get_allowed_countries();

		if ( in_array( $country, $allowed, true ) ) {
			return;
		}

		MKSS_Activity_Log::log( 'geo_blocked', "Blocked visitor from country '{$country}'" );
		$this->deny();
	}

	/**
	 * wp_die() reliably halts execution in every real WordPress request, but
	 * every caller still follows this with an explicit `return;` rather than
	 * relying on that alone.
	 */
	private function deny() {
		nocache_headers();
		do_action( 'litespeed_control_set_nocache', 'MKSS geo denied' );
		$message = MKSS_Settings::instance()->get(
			'geo_block_message',
			__( 'This website is only available to visitors from India, Nepal, Sri Lanka, and the United Arab Emirates.', 'mk-security-shield' )
		);
		wp_die( wp_kses_post( wpautop( $message ) ), esc_html__( 'Access Restricted', 'mk-security-shield' ), array( 'response' => 403 ) );
	}

	private function get_visitor_country() {
		$country = isset( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) ) : '';
		return $country ? $country : 'XX';
	}

	private function get_allowed_countries() {
		$raw  = MKSS_Settings::instance()->get( 'geo_allowed_countries', 'IN,NP,LK,AE' );
		$list = array_filter( array_map( 'trim', explode( ',', strtoupper( (string) $raw ) ) ) );
		return $list ? array_values( $list ) : array( 'IN', 'NP', 'LK', 'AE' );
	}

	// ---- Bypass key / cookie ----

	private function handle_bypass_key() {
		if ( empty( $_GET['mkss_bypass'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return false;
		}

		$provided = sanitize_text_field( wp_unslash( $_GET['mkss_bypass'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$expected = MKSS_Settings::instance()->get( 'geo_bypass_key' );

		if ( ! $expected || ! hash_equals( (string) $expected, $provided ) ) {
			return false;
		}

		$this->set_bypass_cookie();
		MKSS_Activity_Log::log( 'geo_bypass_used', 'Geo-restriction bypass key used' );

		wp_safe_redirect( remove_query_arg( 'mkss_bypass' ) );
		exit;
	}

	private function bypass_cookie_value() {
		return wp_hash( 'mkss_geo_bypass|' . MKSS_Settings::instance()->get( 'geo_bypass_key' ) );
	}

	private function set_bypass_cookie() {
		setcookie(
			self::COOKIE_NAME,
			$this->bypass_cookie_value(),
			array(
				'expires'  => time() + YEAR_IN_SECONDS,
				'path'     => defined( 'COOKIEPATH' ) && COOKIEPATH ? COOKIEPATH : '/',
				'domain'   => defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '',
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
	}

	private function has_valid_bypass_cookie() {
		if ( empty( $_COOKIE[ self::COOKIE_NAME ] ) ) {
			return false;
		}
		return hash_equals( $this->bypass_cookie_value(), (string) wp_unslash( $_COOKIE[ self::COOKIE_NAME ] ) );
	}

	// ---- Cloudflare-origin verification ----

	private function is_request_from_cloudflare() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';
		if ( ! $ip ) {
			return false;
		}

		foreach ( self::CLOUDFLARE_CIDRS as $cidr ) {
			if ( $this->ip_in_cidr( $ip, $cidr ) ) {
				return true;
			}
		}
		return false;
	}

	private function ip_in_cidr( $ip, $cidr ) {
		$parts = explode( '/', $cidr );
		if ( 2 !== count( $parts ) ) {
			return false;
		}
		list( $subnet, $bits ) = $parts;
		$bits = (int) $bits;

		$ip_bin     = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$subnet_bin = @inet_pton( $subnet ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$bytes           = intdiv( $bits, 8 );
		$remainder_bits  = $bits % 8;

		if ( $bytes > 0 && substr( $ip_bin, 0, $bytes ) !== substr( $subnet_bin, 0, $bytes ) ) {
			return false;
		}

		if ( 0 === $remainder_bits ) {
			return true;
		}

		$mask = ( 0xFF << ( 8 - $remainder_bits ) ) & 0xFF;
		return ( ord( $ip_bin[ $bytes ] ) & $mask ) === ( ord( $subnet_bin[ $bytes ] ) & $mask );
	}

	private function get_true_client_ip() { return MKSS_Helper::get_client_ip(); }

	// ---- Verified crawler allowlist ----
	// Follows Google's documented method for verifying Googlebot: a reverse
	// DNS lookup must resolve to a trusted crawler domain, then a forward
	// lookup on that hostname must resolve back to the original IP. A raw
	// User-Agent match alone is trivially spoofable and would defeat the
	// point of geo-restriction entirely.

	private function is_verified_crawler() {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : '';
		if ( ! $ua ) {
			return false;
		}

		$matched_domains = array();
		foreach ( $this->known_crawlers as $needle => $domains ) {
			if ( false !== stripos( $ua, $needle ) ) {
				$matched_domains = $domains;
				break;
			}
		}

		if ( empty( $matched_domains ) ) {
			return false;
		}

		// Verification runs on the true client IP (as forwarded by
		// Cloudflare), not the edge IP that actually connected to us — by
		// this point is_request_from_cloudflare() has already confirmed the
		// CF-Connecting-IP header can be trusted.
		$ip = $this->get_true_client_ip();
		if ( ! $ip ) {
			return false;
		}

		$cache_key = self::CRAWLER_CACHE_PREFIX . md5( $ip . '|' . implode( ',', $matched_domains ) );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached ) {
			return (bool) $cached;
		}

		$verified = $this->verify_crawler_dns( $ip, $matched_domains );
		set_transient( $cache_key, $verified, DAY_IN_SECONDS );

		return $verified;
	}

	private function verify_crawler_dns( $ip, $trusted_domains ) {
		$hostname = @gethostbyaddr( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! $hostname || $hostname === $ip ) {
			return false;
		}

		$hostname       = strtolower( rtrim( $hostname, '.' ) );
		$matches_domain = false;
		foreach ( $trusted_domains as $domain ) {
			if ( substr( $hostname, -strlen( $domain ) ) === $domain ) {
				$matches_domain = true;
				break;
			}
		}
		if ( ! $matches_domain ) {
			return false;
		}

		$records = @dns_get_record( $hostname, DNS_A | DNS_AAAA );
        foreach ( (array) $records as $record ) {
            $forward = $record['ip'] ?? $record['ipv6'] ?? '';
            if ( @inet_pton( $forward ) === @inet_pton( $ip ) ) { return true; }
        }
        return false;
	}
}
