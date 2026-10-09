<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Optional per-user TOTP Two-Factor Authentication, compatible with Google
 * Authenticator / Authy / 1Password etc. Implemented with pure PHP (RFC
 * 6238) — no external service or QR image dependency, so the secret must be
 * entered manually into the authenticator app.
 */
class MKSS_Two_Factor {

	const META_SECRET      = 'mkss_2fa_secret';
	const META_ENABLED     = 'mkss_2fa_enabled';
	const META_PENDING     = 'mkss_2fa_pending_secret';
	const TRANSIENT_PREFIX = 'mkss_2fa_pending_';
	const NONCE_ACTION     = 'mkss_2fa_profile';

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_filter( 'authenticate', array( $this, 'maybe_require_2fa' ), 25, 3 );

		add_action( 'login_form_mkss_2fa_verify', array( $this, 'handle_2fa_verify' ) );

		add_action( 'show_user_profile', array( $this, 'render_own_profile_fields' ) );
		add_action( 'edit_user_profile', array( $this, 'render_other_profile_fields' ) );
		add_action( 'personal_options_update', array( $this, 'save_own_profile_fields' ) );
		add_action( 'edit_user_profile_update', array( $this, 'save_other_profile_fields' ) );
	}

	public function maybe_require_2fa( $user, $username, $password ) {
		// Only intervene on an actual wp-login.php submission — never on
		// programmatic authenticate() calls (REST Application Passwords,
		// XML-RPC, etc.) where a browser redirect would corrupt the response.
		if ( ! did_action( 'login_init' ) ) {
			return $user;
		}

		if ( ! ( $user instanceof WP_User ) ) {
			return $user;
		}

		if ( ! get_user_meta( $user->ID, self::META_ENABLED, true ) ) {
			return $user;
		}

		$token = wp_generate_password( 32, false, false );
		set_transient(
			self::TRANSIENT_PREFIX . $token,
			array(
				'user_id'  => $user->ID,
				'remember' => ! empty( $_POST['rememberme'] ),
				'attempts' => 0,
			),
			5 * MINUTE_IN_SECONDS
		);

		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : admin_url();

		wp_safe_redirect(
			add_query_arg(
				array(
					'action'      => 'mkss_2fa_verify',
					'token'       => $token,
					'redirect_to' => rawurlencode( $redirect_to ),
				),
				wp_login_url()
			)
		);
		exit;
	}

	public function handle_2fa_verify() {
		$token = isset( $_REQUEST['token'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['token'] ) ) : '';
		$data  = $token ? get_transient( self::TRANSIENT_PREFIX . $token ) : false;

		if ( ! $data ) {
			wp_die( esc_html__( 'This two-factor verification link has expired. Please log in again.', 'mk-security-shield' ) );
		}

		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : admin_url();

		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			$code   = isset( $_POST['mkss_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['mkss_2fa_code'] ) ) : '';
			$secret = get_user_meta( $data['user_id'], self::META_SECRET, true );

			if ( $secret && $this->verify_code( $secret, $code ) ) {
				delete_transient( self::TRANSIENT_PREFIX . $token );

				$user = get_user_by( 'id', $data['user_id'] );
				if ( $user ) {
					wp_set_current_user( $user->ID );
					wp_set_auth_cookie( $user->ID, ! empty( $data['remember'] ) );
					do_action( 'wp_login', $user->user_login, $user );
				}

				wp_safe_redirect( $redirect_to );
				exit;
			}

			$user_obj  = get_userdata( $data['user_id'] );
			$user_name = $user_obj ? $user_obj->user_login : '';

			MKSS_Activity_Log::log( 'two_factor_failed', 'Invalid 2FA code', $user_name );

			$data['attempts'] = (int) $data['attempts'] + 1;

			if ( $data['attempts'] >= 5 ) {
				delete_transient( self::TRANSIENT_PREFIX . $token );
				wp_die( esc_html__( 'Too many invalid codes. Please log in again.', 'mk-security-shield' ) );
			}

			set_transient( self::TRANSIENT_PREFIX . $token, $data, 5 * MINUTE_IN_SECONDS );
			$this->render_verify_form( $token, $redirect_to, esc_html__( 'Incorrect code, please try again.', 'mk-security-shield' ) );
			exit;
		}

		$this->render_verify_form( $token, $redirect_to );
		exit;
	}

	private function render_verify_form( $token, $redirect_to, $error = '' ) {
		login_header( __( 'Two-Factor Authentication', 'mk-security-shield' ), '', $error ? new WP_Error( 'mkss_2fa', $error ) : null );
		?>
		<form name="mkss_2fa_form" id="mkss_2fa_form" action="<?php echo esc_url( add_query_arg( array( 'action' => 'mkss_2fa_verify' ), wp_login_url() ) ); ?>" method="post">
			<p>
				<label for="mkss_2fa_code"><?php esc_html_e( 'Authentication code', 'mk-security-shield' ); ?></label>
				<input type="text" name="mkss_2fa_code" id="mkss_2fa_code" class="input" inputmode="numeric" autocomplete="one-time-code" autofocus />
			</p>
			<input type="hidden" name="token" value="<?php echo esc_attr( $token ); ?>" />
			<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'mk-security-shield' ); ?>" />
			</p>
		</form>
		<p id="backtoblog"><a href="<?php echo esc_url( home_url( '/' ) ); ?>"><?php esc_html_e( '← Back to site', 'mk-security-shield' ); ?></a></p>
		<?php
		login_footer( 'mkss_2fa_code' );
	}

	// ---- TOTP (RFC 6238) ----

	public static function generate_secret( $length = 20 ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$secret   = '';
		for ( $i = 0; $i < $length; $i++ ) {
			$secret .= $alphabet[ random_int( 0, strlen( $alphabet ) - 1 ) ];
		}
		return $secret;
	}

	private function base32_decode( $b32 ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$b32      = strtoupper( $b32 );
		$buffer   = 0;
		$bits     = 0;
		$output   = '';

		for ( $i = 0, $len = strlen( $b32 ); $i < $len; $i++ ) {
			$char = $b32[ $i ];
			if ( '=' === $char ) {
				continue;
			}
			$val = strpos( $alphabet, $char );
			if ( false === $val ) {
				continue;
			}
			$buffer = ( $buffer << 5 ) | $val;
			$bits  += 5;
			if ( $bits >= 8 ) {
				$bits   -= 8;
				$output .= chr( ( $buffer >> $bits ) & 0xFF );
			}
		}
		return $output;
	}

	private function totp_at( $secret, $timeslice ) {
		$key      = $this->base32_decode( $secret );
		$time_bin = str_pad( pack( 'N', $timeslice & 0xFFFFFFFF ), 8, "\x00", STR_PAD_LEFT );
		$hash     = hash_hmac( 'sha1', $time_bin, $key, true );
		$offset   = ord( substr( $hash, -1 ) ) & 0x0F;
		$part     = substr( $hash, $offset, 4 );
		$unpacked = unpack( 'N', $part );
		$value    = $unpacked[1] & 0x7FFFFFFF;
		return str_pad( (string) ( $value % 1000000 ), 6, '0', STR_PAD_LEFT );
	}

	public function verify_code( $secret, $code ) {
		$code = preg_replace( '/\D/', '', (string) $code );
		if ( 6 !== strlen( $code ) ) {
			return false;
		}
		$current = (int) floor( time() / 30 );
		for ( $i = -1; $i <= 1; $i++ ) {
			if ( hash_equals( $this->totp_at( $secret, $current + $i ), $code ) ) {
				return true;
			}
		}
		return false;
	}

	// ---- Profile UI ----

	public function render_own_profile_fields( $user ) {
		$enabled        = get_user_meta( $user->ID, self::META_ENABLED, true );
		$pending_secret = get_user_meta( $user->ID, self::META_PENDING, true );

		if ( ! $pending_secret && ! $enabled ) {
			$pending_secret = self::generate_secret();
			update_user_meta( $user->ID, self::META_PENDING, $pending_secret );
		}

		$secret_to_show = $enabled ? get_user_meta( $user->ID, self::META_SECRET, true ) : $pending_secret;
		$label          = rawurlencode( get_bloginfo( 'name' ) . ':' . $user->user_login );
		$issuer         = rawurlencode( get_bloginfo( 'name' ) );
		$otpauth        = "otpauth://totp/{$label}?secret={$secret_to_show}&issuer={$issuer}";
		?>
		<h2><?php esc_html_e( 'Two-Factor Authentication', 'mk-security-shield' ); ?></h2>
		<table class="form-table">
			<tr>
				<th><?php esc_html_e( 'Status', 'mk-security-shield' ); ?></th>
				<td>
					<?php if ( $enabled ) : ?>
						<p><strong style="color:#1a7f37;"><?php esc_html_e( 'Enabled', 'mk-security-shield' ); ?></strong></p>
						<label>
							<input type="checkbox" name="mkss_2fa_disable" value="1" />
							<?php esc_html_e( 'Disable two-factor authentication', 'mk-security-shield' ); ?>
						</label>
					<?php else : ?>
						<p><?php esc_html_e( 'Manually enter this key into an authenticator app (Google Authenticator, Authy, 1Password, etc.), then enter a generated code below to enable.', 'mk-security-shield' ); ?></p>
						<p><code><?php echo esc_html( $secret_to_show ); ?></code></p>
						<p><small><?php echo esc_html( $otpauth ); ?></small></p>
						<p>
							<label for="mkss_2fa_confirm_code"><?php esc_html_e( 'Enter code to enable', 'mk-security-shield' ); ?></label><br/>
							<input type="text" name="mkss_2fa_confirm_code" id="mkss_2fa_confirm_code" class="regular-text" autocomplete="one-time-code" />
						</p>
					<?php endif; ?>
					<?php wp_nonce_field( self::NONCE_ACTION, 'mkss_2fa_nonce' ); ?>
				</td>
			</tr>
		</table>
		<?php
	}

	public function render_other_profile_fields( $user ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$enabled = get_user_meta( $user->ID, self::META_ENABLED, true );
		?>
		<h2><?php esc_html_e( 'Two-Factor Authentication', 'mk-security-shield' ); ?></h2>
		<table class="form-table">
			<tr>
				<th><?php esc_html_e( 'Status', 'mk-security-shield' ); ?></th>
				<td>
					<p><?php echo $enabled ? esc_html__( 'Enabled', 'mk-security-shield' ) : esc_html__( 'Disabled', 'mk-security-shield' ); ?></p>
					<?php if ( $enabled ) : ?>
						<label>
							<input type="checkbox" name="mkss_2fa_force_disable" value="1" />
							<?php esc_html_e( 'Disable two-factor authentication for this user (use for account recovery)', 'mk-security-shield' ); ?>
						</label>
					<?php endif; ?>
					<?php wp_nonce_field( self::NONCE_ACTION, 'mkss_2fa_nonce' ); ?>
				</td>
			</tr>
		</table>
		<?php
	}

	public function save_own_profile_fields( $user_id ) {
		if ( ! isset( $_POST['mkss_2fa_nonce'] ) || ! wp_verify_nonce( $_POST['mkss_2fa_nonce'], self::NONCE_ACTION ) ) {
			return;
		}
		if ( (int) $user_id !== get_current_user_id() ) {
			return;
		}

		if ( ! empty( $_POST['mkss_2fa_disable'] ) ) {
			delete_user_meta( $user_id, self::META_ENABLED );
			delete_user_meta( $user_id, self::META_SECRET );
			$user_obj = get_userdata( $user_id );
			MKSS_Activity_Log::log( 'two_factor_disabled', 'User disabled 2FA', $user_obj ? $user_obj->user_login : '' );
			return;
		}

		$pending = get_user_meta( $user_id, self::META_PENDING, true );
		$code    = isset( $_POST['mkss_2fa_confirm_code'] ) ? sanitize_text_field( wp_unslash( $_POST['mkss_2fa_confirm_code'] ) ) : '';

		if ( $pending && $code && $this->verify_code( $pending, $code ) ) {
			update_user_meta( $user_id, self::META_SECRET, $pending );
			update_user_meta( $user_id, self::META_ENABLED, 1 );
			delete_user_meta( $user_id, self::META_PENDING );
			$user_obj = get_userdata( $user_id );
			MKSS_Activity_Log::log( 'two_factor_enabled', 'User enabled 2FA', $user_obj ? $user_obj->user_login : '' );
		}
	}

	public function save_other_profile_fields( $user_id ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( ! isset( $_POST['mkss_2fa_nonce'] ) || ! wp_verify_nonce( $_POST['mkss_2fa_nonce'], self::NONCE_ACTION ) ) {
			return;
		}
		if ( ! empty( $_POST['mkss_2fa_force_disable'] ) ) {
			delete_user_meta( $user_id, self::META_ENABLED );
			delete_user_meta( $user_id, self::META_SECRET );
			$user_obj = get_userdata( $user_id );
			MKSS_Activity_Log::log( 'two_factor_disabled', 'Administrator disabled 2FA for user', $user_obj ? $user_obj->user_login : '' );
		}
	}
}
