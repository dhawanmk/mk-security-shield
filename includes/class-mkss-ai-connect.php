<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * "Connect AI Assistant" — an explicit, revocable consent flow for letting
 * an external MCP client (Claude Desktop, Claude Code, etc.) manage this
 * WordPress site, modeled on Jetpack's connection screen rather than a
 * hidden or automatic mechanism.
 *
 * This module deliberately does NOT implement an MCP server itself. Bridging
 * the Model Context Protocol to WordPress is WordPress core's own job via
 * the official WordPress/mcp-adapter plugin
 * (https://github.com/WordPress/mcp-adapter), which already does this and
 * is maintained by WordPress core contributors. Reinventing that inside a
 * hardening plugin would mean maintaining a second, almost certainly worse,
 * copy of the same bridge — and, worse, would tempt a "no login required"
 * shortcut that is a straightforward backdoor. This module only owns the
 * parts a security plugin should own:
 *
 * - A dedicated, least-privilege service account (never the site owner's
 *   own admin account) so AI-driven changes are attributable in revision
 *   history and distinguishable from human edits.
 * - An explicit, plain-English consent screen before any credential exists.
 * - Application Password lifecycle (generate/revoke) using WordPress
 *   core's own built-in mechanism (5.6+) — no custom auth, no secrets
 *   embedded in plugin code.
 * - An audit trail of every authenticated use of that credential.
 */
class MKSS_AI_Connect {

	const OPTION_KEY   = 'mkss_ai_connect';
	const ROLE_SLUG    = 'mkss_ai_assistant';
	const NONCE_ACTION = 'mkss_ai_connect';

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'admin_menu', array( $this, 'add_menu' ), 40 );
		add_action( 'admin_post_mkss_ai_connect_generate', array( $this, 'handle_generate' ) );
		add_action( 'admin_post_mkss_ai_connect_revoke', array( $this, 'handle_revoke' ) );
		add_action( 'application_password_did_authenticate', array( $this, 'log_authenticated_use' ), 10, 2 );
		add_action( 'application_password_failed_authentication', array( $this, 'log_failed_use' ) );
		// Priority 30: run AFTER WordPress core's own username/password check
		// (priority 20) so this always wins regardless of whether the
		// submitted password happened to be correct — a WP_Error returned
		// at an earlier priority can still be overwritten by core's own
		// later callback, so blocking has to happen after it, not before.
		add_filter( 'authenticate', array( $this, 'block_interactive_login_for_service_account' ), 30, 2 );
		// Backstop, independent of the filter above: WordPress core also
		// accepts email-address logins (wp_authenticate_email_password),
		// and other modules in this plugin (e.g. Two-Factor) can complete a
		// login and fire 'wp_login' without ever re-running 'authenticate'.
		// Rather than track every such path, terminate on sight: any
		// session actually established for the service account, however it
		// got there, is destroyed immediately.
		add_action( 'wp_login', array( $this, 'destroy_session_if_service_account' ), 1, 2 );
	}

	// ---- Capability presets ----

	public static function presets() {
		$content_caps = array(
			'read'                   => true,
			'edit_posts'             => true,
			'edit_others_posts'      => true,
			'edit_published_posts'   => true,
			'edit_private_posts'     => true,
			'delete_posts'           => true,
			'delete_others_posts'    => true,
			'delete_published_posts' => true,
			'delete_private_posts'   => true,
			'publish_posts'          => true,
			'edit_pages'             => true,
			'edit_others_pages'      => true,
			'edit_published_pages'   => true,
			'edit_private_pages'     => true,
			'delete_pages'           => true,
			'delete_others_pages'    => true,
			'delete_published_pages' => true,
			'delete_private_pages'   => true,
			'publish_pages'          => true,
			'upload_files'           => true,
			'moderate_comments'      => true,
			'manage_categories'      => true,
			'manage_links'           => true,
		);

		return array(
			'content' => array(
				'label'       => __( 'Content Editor (Recommended)', 'mk-security-shield' ),
				'description' => __( 'Create, edit, and delete posts, pages, media, and comments. Cannot install plugins/themes, change site-wide settings, or manage users. Deliberately excludes unfiltered_html, so raw/unsafe HTML in content is still stripped just like any normal Editor-level account.', 'mk-security-shield' ),
				'caps'        => $content_caps,
			),
			'design'  => array(
				'label'       => __( 'Content + Design', 'mk-security-shield' ),
				'description' => __( 'Everything in Content Editor, plus menus, widgets, and site-editor/customizer changes (edit_theme_options). Still no plugin/theme installation or user management.', 'mk-security-shield' ),
				'caps'        => array_merge( $content_caps, array( 'edit_theme_options' => true ) ),
			),
			'full'    => array(
				'label'       => __( 'Full Control (High Risk)', 'mk-security-shield' ),
				'description' => __( 'Everything an Administrator can do: install/activate/edit plugins and themes, manage users, change every site setting. A leaked or misused credential at this level can take over the entire site. Only choose this if you specifically need it.', 'mk-security-shield' ),
				'caps'        => self::administrator_caps(),
			),
		);
	}

	private static function administrator_caps() {
		$admin_role = get_role( 'administrator' );
		return $admin_role ? $admin_role->capabilities : array( 'manage_options' => true );
	}

	// ---- Admin UI ----

	public function add_menu() {
		add_submenu_page(
			'mkss-settings',
			__( 'Connect AI Assistant', 'mk-security-shield' ),
			__( 'Connect AI Assistant', 'mk-security-shield' ),
			'manage_options',
			'mkss-ai-connect',
			array( $this, 'render_page' )
		);
	}

	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$connection = get_option( self::OPTION_KEY, array() );
		$secret_key = 'mkss_ai_connect_new_secret_' . get_current_user_id();
		$new_secret = get_transient( $secret_key );
		delete_transient( $secret_key );

		$available = function_exists( 'wp_is_application_passwords_available' ) && wp_is_application_passwords_available();
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Connect AI Assistant', 'mk-security-shield' ); ?></h1>
			<p><?php esc_html_e( 'Grant an AI assistant (like Claude, via an MCP client) permission to manage this site through a dedicated, revocable connection — similar to how Jetpack connects to WordPress.com. Nothing here uses a shared or hardcoded secret: the credential below is generated by WordPress itself, tied to a dedicated account you control, and can be revoked instantly.', 'mk-security-shield' ); ?></p>

			<?php if ( ! $available ) : ?>
				<div class="notice notice-error"><p><?php esc_html_e( 'Application Passwords are not available on this site right now. They require HTTPS and WordPress 5.6+, but another active plugin can also disable them outright — see the diagnostics below for which one it is.', 'mk-security-shield' ); ?></p></div>
				<?php $this->render_ssl_diagnostics(); ?>
			<?php endif; ?>

			<?php if ( $new_secret ) : ?>
				<div class="notice notice-success">
					<p><strong><?php esc_html_e( 'Connection created. Copy this password now — WordPress will not show it again.', 'mk-security-shield' ); ?></strong></p>
					<p><code style="font-size:1.1em;"><?php echo esc_html( $new_secret ); ?></code></p>
				</div>
			<?php endif; ?>

			<?php if ( ! empty( $connection['user_id'] ) && ! empty( $connection['app_uuid'] ) ) : ?>
				<?php $this->render_connected_state( $connection ); ?>
			<?php elseif ( $available ) : ?>
				<?php $this->render_setup_form(); ?>
			<?php endif; ?>

			<h2><?php esc_html_e( 'One more step: install the MCP bridge', 'mk-security-shield' ); ?></h2>
			<p>
				<?php
				printf(
					/* translators: %s: link to WordPress core's official MCP Adapter plugin */
					wp_kses_post( __( 'This screen only issues the credential. To let an MCP client (Claude Desktop, Claude Code, etc.) actually talk to WordPress with it, also install WordPress core\'s official <a href="%s" target="_blank" rel="noopener noreferrer">MCP Adapter plugin</a> — it translates the Model Context Protocol into WordPress REST API calls. We deliberately don\'t bundle a custom MCP server here: that\'s exactly the kind of thing best left to WordPress core\'s own maintained tooling, not reinvented per-plugin.', 'mk-security-shield' ) ),
					'https://github.com/WordPress/mcp-adapter'
				);
				?>
			</p>
		</div>
		<?php
	}

	/**
	 * Shown only when Application Passwords are unavailable. Splits the
	 * diagnosis into two independent questions rather than assuming HTTPS
	 * is always the cause: (1) does is_ssl() actually return true, and (2)
	 * if it does, is something else — a filter registered by another
	 * plugin, most commonly a security/hardening plugin that deliberately
	 * disables Application Passwords — overriding the result anyway.
	 */
	private function render_ssl_diagnostics() {
		$forwarded_headers = array(
			'HTTP_X_FORWARDED_PROTO',
			'HTTP_X_FORWARDED_SSL',
			'HTTP_X_FORWARDED_PROTOCOL',
			'HTTP_X_FORWARDED_SCHEME',
			'HTTP_CF_VISITOR',
			'HTTP_CF_CONNECTING_IP',
			'HTTP_CF_RAY',
			'HTTP_FRONT_END_HTTPS',
		);

		$ssl_ok = is_ssl();
		$site_wide_available = function_exists( 'wp_is_application_passwords_available' ) ? wp_is_application_passwords_available() : null;
		$user_available       = function_exists( 'wp_is_application_passwords_available_for_user' ) ? wp_is_application_passwords_available_for_user( wp_get_current_user() ) : null;
		?>
		<div class="notice notice-info">
			<p><strong><?php esc_html_e( 'Diagnostics — share this with whoever is troubleshooting:', 'mk-security-shield' ); ?></strong></p>

			<table class="widefat" style="max-width:640px;margin-bottom:1em;">
				<tr>
					<th style="width:280px;"><?php esc_html_e( 'is_ssl() result', 'mk-security-shield' ); ?></th>
					<td><code><?php echo $ssl_ok ? 'true' : 'false'; ?></code></td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'wp_is_application_passwords_available()', 'mk-security-shield' ); ?></th>
					<td><code><?php echo null === $site_wide_available ? 'n/a' : ( $site_wide_available ? 'true' : 'false' ); ?></code></td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'wp_is_application_passwords_available_for_user( you )', 'mk-security-shield' ); ?></th>
					<td><code><?php echo null === $user_available ? 'n/a' : ( $user_available ? 'true' : 'false' ); ?></code></td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Something hooked into the site-wide filter?', 'mk-security-shield' ); ?></th>
					<td><code><?php echo has_filter( 'wp_is_application_passwords_available' ) ? 'yes' : 'no'; ?></code></td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Something hooked into the per-user filter?', 'mk-security-shield' ); ?></th>
					<td><code><?php echo has_filter( 'wp_is_application_passwords_available_for_user' ) ? 'yes' : 'no'; ?></code></td>
				</tr>
			</table>

			<?php if ( $ssl_ok && ! $site_wide_available ) : ?>
				<p><strong><?php esc_html_e( 'is_ssl() is already true, so HTTPS is not the blocker here.', 'mk-security-shield' ); ?></strong> <?php esc_html_e( 'Something else — most likely another active plugin (a security/hardening plugin explicitly disabling Application Passwords is common) or a host-provided must-use plugin — is forcing this off. Check your other security plugins\' settings for anything mentioning "Application Passwords" or "REST API authentication," and check Plugins → look for any plugin installed by your host that isn\'t one you added yourself.', 'mk-security-shield' ); ?></p>
				<?php $this->render_hooked_callbacks( 'wp_is_application_passwords_available' ); ?>
				<?php $this->render_hooked_callbacks( 'wp_is_application_passwords_available_for_user' ); ?>
			<?php elseif ( ! $ssl_ok ) : ?>
				<table class="widefat" style="max-width:640px;margin:1em 0;">
					<tr>
						<th style="width:280px;"><?php esc_html_e( '$_SERVER[HTTPS]', 'mk-security-shield' ); ?></th>
						<td><code><?php echo isset( $_SERVER['HTTPS'] ) ? esc_html( $_SERVER['HTTPS'] ) : esc_html__( '(not set)', 'mk-security-shield' ); ?></code></td>
					</tr>
					<tr>
						<th><?php esc_html_e( '$_SERVER[SERVER_PORT]', 'mk-security-shield' ); ?></th>
						<td><code><?php echo isset( $_SERVER['SERVER_PORT'] ) ? esc_html( $_SERVER['SERVER_PORT'] ) : esc_html__( '(not set)', 'mk-security-shield' ); ?></code></td>
					</tr>
					<?php foreach ( $forwarded_headers as $header ) : ?>
						<tr>
							<th><?php echo esc_html( '$_SERVER[' . $header . ']' ); ?></th>
							<td><code><?php echo isset( $_SERVER[ $header ] ) ? esc_html( (string) wp_unslash( $_SERVER[ $header ] ) ) : esc_html__( '(not set)', 'mk-security-shield' ); ?></code></td>
						</tr>
					<?php endforeach; ?>
				</table>
				<p class="description"><?php esc_html_e( 'is_ssl() is false, so this really is an HTTPS-detection problem — check whether Cloudflare\'s SSL/TLS mode for this domain is set to "Full" or "Full (strict)" rather than "Flexible", and confirm whichever forwarded-proto header shows a value above is the one being trusted.', 'mk-security-shield' ); ?></p>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Best-effort listing of what's actually hooked into a filter, for
	 * diagnosing "is_ssl() is fine but the feature is still disabled"
	 * cases. Reads WordPress's internal $wp_filter registry directly since
	 * there's no public API to enumerate registered callback names.
	 */
	private function render_hooked_callbacks( $hook_name ) {
		global $wp_filter;

		if ( empty( $wp_filter[ $hook_name ] ) || ! ( $wp_filter[ $hook_name ] instanceof WP_Hook ) ) {
			return;
		}

		$lines = array();
		foreach ( $wp_filter[ $hook_name ]->callbacks as $priority => $callbacks ) {
			foreach ( $callbacks as $cb ) {
				$function = $cb['function'];
				if ( is_string( $function ) ) {
					$label = $function;
				} elseif ( is_array( $function ) && isset( $function[0], $function[1] ) ) {
					$label = ( is_object( $function[0] ) ? get_class( $function[0] ) : $function[0] ) . '::' . $function[1];
				} else {
					$label = __( '(anonymous function)', 'mk-security-shield' );
				}
				$lines[] = sprintf( '%s (priority %d)', $label, $priority );
			}
		}

		if ( empty( $lines ) ) {
			return;
		}
		?>
		<p><code><?php echo esc_html( $hook_name ); ?>:</code></p>
		<ul style="list-style:disc;margin-left:2em;">
			<?php foreach ( $lines as $line ) : ?>
				<li><code><?php echo esc_html( $line ); ?></code></li>
			<?php endforeach; ?>
		</ul>
		<?php
	}

	private function render_setup_form() {
		$presets            = self::presets();
		$suggested_username = 'ai-assistant';
		$suggested_email    = $this->suggest_service_email();
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="mkss_ai_connect_generate" />
			<?php wp_nonce_field( self::NONCE_ACTION ); ?>

			<table class="form-table">
				<tr>
					<th><?php esc_html_e( 'Access level', 'mk-security-shield' ); ?></th>
					<td>
						<?php foreach ( $presets as $key => $preset ) : ?>
							<p>
								<label>
									<input type="radio" name="mkss_ai_preset" value="<?php echo esc_attr( $key ); ?>" <?php checked( 'content', $key ); ?> />
									<strong><?php echo esc_html( $preset['label'] ); ?></strong>
								</label><br/>
								<span class="description" style="margin-left:24px;"><?php echo esc_html( $preset['description'] ); ?></span>
							</p>
						<?php endforeach; ?>
						<p>
							<label>
								<input type="checkbox" name="mkss_ai_confirm_full" value="1" />
								<?php esc_html_e( 'I understand "Full Control" grants administrator-equivalent access, and I am choosing it deliberately.', 'mk-security-shield' ); ?>
							</label>
							<span class="description"><?php esc_html_e( '(only required if you selected Full Control above)', 'mk-security-shield' ); ?></span>
						</p>
					</td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Service account username', 'mk-security-shield' ); ?></th>
					<td><input type="text" class="regular-text" name="mkss_ai_username" value="<?php echo esc_attr( $suggested_username ); ?>" /></td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Service account email', 'mk-security-shield' ); ?></th>
					<td>
						<input type="email" class="regular-text" name="mkss_ai_email" value="<?php echo esc_attr( $suggested_email ); ?>" />
						<p class="description"><?php esc_html_e( 'Must be a unique, deliverable address (WordPress requires one per account) — it will never be used to log in interactively.', 'mk-security-shield' ); ?></p>
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Generate Connection', 'mk-security-shield' ) ); ?>
		</form>
		<?php
	}

	private function render_connected_state( $connection ) {
		$user    = get_user_by( 'id', $connection['user_id'] );
		$item    = $user ? WP_Application_Passwords::get_user_application_password( $user->ID, $connection['app_uuid'] ) : null;
		$presets = self::presets();
		$label   = isset( $presets[ $connection['preset'] ] ) ? $presets[ $connection['preset'] ]['label'] : $connection['preset'];
		?>
		<table class="widefat" style="max-width:640px;">
			<tr>
				<th style="width:200px;"><?php esc_html_e( 'Status', 'mk-security-shield' ); ?></th>
				<td><strong style="color:#1a7f37;"><?php esc_html_e( 'Connected', 'mk-security-shield' ); ?></strong></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Service account', 'mk-security-shield' ); ?></th>
				<td><?php echo $user ? esc_html( $user->user_login ) : esc_html__( '(user missing)', 'mk-security-shield' ); ?></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Access level', 'mk-security-shield' ); ?></th>
				<td><?php echo esc_html( $label ); ?></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Site URL for MCP config', 'mk-security-shield' ); ?></th>
				<td><code><?php echo esc_html( site_url() ); ?></code></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Created', 'mk-security-shield' ); ?></th>
				<td><?php echo $item ? esc_html( wp_date( 'Y-m-d H:i', $item['created'] ) ) : '—'; ?></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Last used', 'mk-security-shield' ); ?></th>
				<td>
					<?php
					if ( $item && $item['last_used'] ) {
						echo esc_html( wp_date( 'Y-m-d H:i', $item['last_used'] ) . ' — ' . $item['last_ip'] );
					} else {
						esc_html_e( 'Never', 'mk-security-shield' );
					}
					?>
				</td>
			</tr>
		</table>
		<p class="description"><?php esc_html_e( 'The password itself is never shown again after creation, in line with WordPress\'s own security model — revoke and regenerate below if it needs to change.', 'mk-security-shield' ); ?></p>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('<?php echo esc_js( __( 'This immediately cuts off AI access to the site. Continue?', 'mk-security-shield' ) ); ?>');">
			<input type="hidden" name="action" value="mkss_ai_connect_revoke" />
			<?php wp_nonce_field( self::NONCE_ACTION ); ?>
			<?php submit_button( __( 'Revoke Connection', 'mk-security-shield' ), 'delete' ); ?>
		</form>
		<?php
	}

	private function suggest_service_email() {
		$admin_email = get_option( 'admin_email' );
		$parts       = explode( '@', (string) $admin_email );
		if ( 2 !== count( $parts ) ) {
			return '';
		}
		return $parts[0] . '+ai-assistant@' . $parts[1];
	}

	// ---- Generate / Revoke ----

	public function handle_generate() {
		if ( ! current_user_can( 'manage_options' ) || ! check_admin_referer( self::NONCE_ACTION ) ) {
			wp_die( esc_html__( 'Not allowed.', 'mk-security-shield' ) );
		}

		if ( ! function_exists( 'wp_is_application_passwords_available' ) || ! wp_is_application_passwords_available() ) {
			wp_die( esc_html__( 'Application Passwords are not available on this site (they require HTTPS and WordPress 5.6+, and can be disabled by hosting or another plugin).', 'mk-security-shield' ) );
		}

		$preset_key = isset( $_POST['mkss_ai_preset'] ) ? sanitize_key( wp_unslash( $_POST['mkss_ai_preset'] ) ) : 'content';
		$presets    = self::presets();
		if ( ! isset( $presets[ $preset_key ] ) ) {
			$preset_key = 'content';
		}
		if ( 'full' === $preset_key && empty( $_POST['mkss_ai_confirm_full'] ) ) {
			wp_die( esc_html__( 'You must explicitly confirm Full Control access before it can be granted.', 'mk-security-shield' ) );
		}

		$username = isset( $_POST['mkss_ai_username'] ) ? sanitize_user( wp_unslash( $_POST['mkss_ai_username'] ) ) : 'ai-assistant';
		$email    = isset( $_POST['mkss_ai_email'] ) ? sanitize_email( wp_unslash( $_POST['mkss_ai_email'] ) ) : '';

		if ( ! $username || ! is_email( $email ) ) {
			wp_die( esc_html__( 'A valid username and email are required.', 'mk-security-shield' ) );
		}

		// Register/refresh the least-privilege role for the chosen preset.
		remove_role( self::ROLE_SLUG );
		add_role( self::ROLE_SLUG, __( 'AI Assistant', 'mk-security-shield' ), $presets[ $preset_key ]['caps'] );

		$existing = get_option( self::OPTION_KEY, array() );
		$user     = ! empty( $existing['user_id'] ) ? get_user_by( 'id', $existing['user_id'] ) : null;

		if ( $user ) {
			// Reconnecting/rotating: reuse the existing dedicated account and
			// refresh its role, but first revoke every existing Application
			// Password for it — otherwise a credential rotation (the normal
			// response to a suspected leak) would leave the old, possibly
			// compromised password still valid alongside the new one.
			if ( class_exists( 'WP_Application_Passwords' ) ) {
				WP_Application_Passwords::delete_all_application_passwords( $user->ID );
			}
			$user->set_role( self::ROLE_SLUG );
		} else {
			if ( username_exists( $username ) || email_exists( $email ) ) {
				wp_die( esc_html__( 'That username or email is already in use by another account on this site.', 'mk-security-shield' ) );
			}
			$user_id = wp_insert_user(
				array(
					'user_login'   => $username,
					'user_email'   => $email,
					'user_pass'    => wp_generate_password( 64, true, true ),
					'role'         => self::ROLE_SLUG,
					'display_name' => __( 'AI Assistant', 'mk-security-shield' ),
				)
			);
			if ( is_wp_error( $user_id ) ) {
				wp_die( esc_html( $user_id->get_error_message() ) );
			}
			$user = get_user_by( 'id', $user_id );
		}

		$result = WP_Application_Passwords::create_new_application_password(
			$user->ID,
			array( 'name' => 'MK Security Shield — ' . gmdate( 'Y-m-d H:i' ) )
		);

		if ( is_wp_error( $result ) ) {
			wp_die( esc_html( $result->get_error_message() ) );
		}

		list( $raw_password, $item ) = $result;

		update_option(
			self::OPTION_KEY,
			array(
				'user_id'  => $user->ID,
				'app_uuid' => $item['uuid'],
				'preset'   => $preset_key,
			),
			false
		);

		set_transient( 'mkss_ai_connect_new_secret_' . get_current_user_id(), $raw_password, 5 * MINUTE_IN_SECONDS );

		MKSS_Activity_Log::log( 'ai_connect_created', "AI assistant connection created (preset: {$preset_key})", $user->user_login );

		wp_safe_redirect( admin_url( 'admin.php?page=mkss-ai-connect' ) );
		exit;
	}

	public function handle_revoke() {
		if ( ! current_user_can( 'manage_options' ) || ! check_admin_referer( self::NONCE_ACTION ) ) {
			wp_die( esc_html__( 'Not allowed.', 'mk-security-shield' ) );
		}

		$connection = get_option( self::OPTION_KEY, array() );

		if ( ! empty( $connection['user_id'] ) ) {
			// Delete ALL Application Passwords for this account, not just the
			// one this connection happens to be tracking — "Revoke" must
			// actually cut off every credential, including any that could
			// have been created outside this screen (e.g. directly on the
			// user's own profile page by an administrator).
			WP_Application_Passwords::delete_all_application_passwords( $connection['user_id'] );
			$user = get_user_by( 'id', $connection['user_id'] );
			MKSS_Activity_Log::log( 'ai_connect_revoked', 'AI assistant connection revoked', $user ? $user->user_login : '' );
		}

		delete_option( self::OPTION_KEY );

		wp_safe_redirect( admin_url( 'admin.php?page=mkss-ai-connect' ) );
		exit;
	}

	// ---- Guardrails ----

	/**
	 * The dedicated service account should only ever authenticate via its
	 * Application Password (a separate code path used only for REST/API
	 * requests). Any interactive wp-login.php attempt against that account
	 * is presumptively an attack, since the legitimate integration never
	 * uses that path — so it's always blocked, regardless of whether the
	 * submitted password happens to be correct. WordPress core accepts
	 * EITHER the username or the email address on this form
	 * (wp_authenticate_username_password / wp_authenticate_email_password),
	 * so both must be checked here — this is a backstop only; the
	 * authoritative block is destroy_session_if_service_account() below,
	 * which fires on any completed login regardless of how it got there.
	 */
	public function block_interactive_login_for_service_account( $user, $username ) {
		if ( ! $username ) {
			return $user;
		}
		$connection = get_option( self::OPTION_KEY, array() );
		if ( empty( $connection['user_id'] ) ) {
			return $user;
		}
		$service_user = get_user_by( 'id', $connection['user_id'] );
		if ( $service_user && (
			strtolower( $service_user->user_login ) === strtolower( $username ) ||
			strtolower( $service_user->user_email ) === strtolower( $username )
		) ) {
			MKSS_Activity_Log::log( 'ai_connect_interactive_login_blocked', 'Blocked an interactive wp-login.php attempt against the AI service account — it should only ever authenticate via its Application Password' );
			return new WP_Error( 'mkss_service_account', __( 'This account cannot log in interactively.', 'mk-security-shield' ) );
		}
		return $user;
	}

	/**
	 * Authoritative version of the guardrail above: fires on ANY completed
	 * login for the service account, regardless of which code path
	 * established it (core password/email login, this plugin's own
	 * Two-Factor module completing its own separate login flow, or
	 * anything else that calls wp_set_auth_cookie() + do_action('wp_login',
	 * ...) without going back through the 'authenticate' filter). Rather
	 * than enumerate every such path, this just refuses to let the session
	 * stand: destroy it immediately and stop the request.
	 */
	public function destroy_session_if_service_account( $user_login, $user = null ) {
		$connection = get_option( self::OPTION_KEY, array() );
		if ( empty( $connection['user_id'] ) ) {
			return;
		}

		$user_id = ( $user instanceof WP_User ) ? $user->ID : 0;
		if ( ! $user_id ) {
			$maybe   = get_user_by( 'login', $user_login );
			$user_id = $maybe ? $maybe->ID : 0;
		}

		if ( (int) $user_id !== (int) $connection['user_id'] ) {
			return;
		}

		MKSS_Activity_Log::log( 'ai_connect_interactive_login_blocked', 'An interactive session was established for the AI service account via a non-Application-Password path and was terminated immediately' );
		wp_logout();
		wp_die( esc_html__( 'This account cannot log in interactively.', 'mk-security-shield' ) );
	}

	public function log_authenticated_use( $user, $item ) {
		$connection = get_option( self::OPTION_KEY, array() );
		if ( empty( $connection['user_id'] ) || (int) $connection['user_id'] !== (int) $user->ID ) {
			return;
		}
		$route  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		MKSS_Activity_Log::log( 'ai_connect_used', trim( "{$method} {$route}" ), $user->user_login );
	}

	public function log_failed_use( $error ) {
		MKSS_Activity_Log::log( 'ai_connect_auth_failed', 'A request presented an invalid Application Password' );
	}
}
