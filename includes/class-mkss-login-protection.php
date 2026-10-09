<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MKSS_Login_Protection {

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'login_init', array( $this, 'block_if_locked_out' ) );
		add_action( 'wp_login_failed', array( $this, 'record_failed_attempt' ), 10, 2 );
		add_action( 'wp_login', array( $this, 'clear_failed_attempts' ), 10, 2 );
		add_filter( 'authenticate', array( $this, 'verify_captcha' ), 21, 3 );

		if ( MKSS_Settings::instance()->get( 'login_generic_errors' ) ) {
			add_filter( 'login_errors', array( $this, 'generic_error_message' ) );
		}

		if ( MKSS_Settings::instance()->get( 'login_math_captcha' ) ) {
			add_action( 'login_form', array( $this, 'render_captcha' ) );
		}
	}

	private function attempts_key( $ip ) {
		return 'mkss_attempts_' . md5( $ip );
	}

	private function lockout_key( $ip ) {
		return 'mkss_lockout_' . md5( $ip );
	}

	public function block_if_locked_out() {
		$ip           = MKSS_Helper::get_client_ip();
		$locked_until = get_transient( $this->lockout_key( $ip ) );

		if ( $locked_until && $locked_until > time() ) {
			MKSS_Activity_Log::log( 'login_blocked', 'Login attempt while IP is locked out' );
			wp_die(
				esc_html__( 'Too many failed login attempts. Please try again later.', 'mk-security-shield' ),
				esc_html__( 'Access temporarily blocked', 'mk-security-shield' ),
				array( 'response' => 429 )
			);
		}
	}

	public function record_failed_attempt( $username, $error = null ) {
		$ip       = MKSS_Helper::get_client_ip();
		$settings = MKSS_Settings::instance();
		$key      = $this->attempts_key( $ip );
		$count    = (int) get_transient( $key ) + 1;

		set_transient( $key, $count, HOUR_IN_SECONDS );

		MKSS_Activity_Log::log( 'login_failed', "Failed login attempt ({$count})", $username );

		if ( $count >= (int) $settings->get( 'login_max_attempts' ) ) {
			$minutes = (int) $settings->get( 'login_lockout_minutes' );
			set_transient( $this->lockout_key( $ip ), time() + ( $minutes * MINUTE_IN_SECONDS ), $minutes * MINUTE_IN_SECONDS );
			MKSS_Activity_Log::log( 'ip_locked', "IP locked out for {$minutes} minutes", $username );
		}
	}

	public function clear_failed_attempts( $user_login, $user = null ) {
		$ip = MKSS_Helper::get_client_ip();
		delete_transient( $this->attempts_key( $ip ) );
		delete_transient( $this->lockout_key( $ip ) );
		MKSS_Activity_Log::log( 'login_success', 'Successful login', $user_login );
	}

	public function generic_error_message( $error ) {
		return esc_html__( 'Invalid credentials.', 'mk-security-shield' );
	}

	public function render_captcha() {
		$a       = wp_rand( 1, 10 );
		$b       = wp_rand( 1, 10 );
		$expires = time() + ( 15 * MINUTE_IN_SECONDS );
		$token   = wp_hash( $a . '|' . $b . '|' . $expires . '|mkss_captcha' );
		?>
		<p class="mkss-captcha-field">
			<label for="mkss_captcha_answer"><?php printf( esc_html__( 'Security check: what is %1$d + %2$d?', 'mk-security-shield' ), (int) $a, (int) $b ); ?></label>
			<input type="text" name="mkss_captcha_answer" id="mkss_captcha_answer" class="input" autocomplete="off" />
			<input type="hidden" name="mkss_captcha_a" value="<?php echo esc_attr( $a ); ?>" />
			<input type="hidden" name="mkss_captcha_b" value="<?php echo esc_attr( $b ); ?>" />
			<input type="hidden" name="mkss_captcha_expires" value="<?php echo esc_attr( $expires ); ?>" />
			<input type="hidden" name="mkss_captcha_token" value="<?php echo esc_attr( $token ); ?>" />
		</p>
		<?php
	}

	public function verify_captcha( $user, $username, $password ) {
		// Only enforce on an actual wp-login.php form submission (login_init
		// already fired earlier in this same request). This avoids blocking
		// programmatic authenticate() calls such as REST API Application
		// Passwords, which have no captcha fields to check.
		if ( ! did_action( 'login_init' ) ) {
			return $user;
		}

		if ( ! MKSS_Settings::instance()->get( 'login_math_captcha' ) ) {
			return $user;
		}

		if ( empty( $username ) && empty( $password ) ) {
			return $user;
		}

		$a       = isset( $_POST['mkss_captcha_a'] ) ? (int) $_POST['mkss_captcha_a'] : null;
		$b       = isset( $_POST['mkss_captcha_b'] ) ? (int) $_POST['mkss_captcha_b'] : null;
		$expires = isset( $_POST['mkss_captcha_expires'] ) ? (int) $_POST['mkss_captcha_expires'] : 0;
		$token   = isset( $_POST['mkss_captcha_token'] ) ? sanitize_text_field( wp_unslash( $_POST['mkss_captcha_token'] ) ) : '';
		$answer  = isset( $_POST['mkss_captcha_answer'] ) ? (int) $_POST['mkss_captcha_answer'] : null;

		if ( null === $a || null === $b || ! $token || $expires < time() ) {
			return new WP_Error( 'mkss_captcha_expired', __( '<strong>Error:</strong> Security check expired, please try again.', 'mk-security-shield' ) );
		}

		$expected_token = wp_hash( $a . '|' . $b . '|' . $expires . '|mkss_captcha' );

		if ( ! hash_equals( $expected_token, $token ) || ( $a + $b ) !== $answer ) {
			return new WP_Error( 'mkss_captcha_failed', __( '<strong>Error:</strong> Incorrect answer to the security check.', 'mk-security-shield' ) );
		}

		return $user;
	}
}
