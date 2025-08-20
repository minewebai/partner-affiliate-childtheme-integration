<?php
/**
 * Child theme functions.php
 * User: MSI
 * Date: 21/08/2015
 */

/* =========================
   Load parent & child styles
   ========================= */
add_action('wp_enqueue_scripts', 'enqueue_parent_styles', 20);
function enqueue_parent_styles() {
    wp_enqueue_style('parent-style', get_template_directory_uri() . '/style.css');
    wp_enqueue_style('child-style', get_stylesheet_uri());
}
/* load partnerlisting css */
function enqueue_partner_preview_css() {
    if (is_page_template('page-partners.php')) { // make sure template name matches exactly
        wp_enqueue_style(
            'partner-preview',
            get_stylesheet_directory_uri() . '/partner-preview.css',
            array(),
            '1.0',
            'all'
        );
    }
}
add_action('wp_enqueue_scripts', 'enqueue_partner_preview_css');


/* =========================
   Affiliate dashboard pages
   ========================= */
function pbp_affiliate_dashboard_page($user_data) {
    $path = get_stylesheet_directory() . '/partner-affiliate/affiliate-dashboard.php';
    if (file_exists($path)) { include $path; }
    else { echo '<p style="color:red;">Error: affiliate-dashboard.php file not found.</p>'; }
}
function pbp_affiliate_book_page($user_data) {
    $path = get_stylesheet_directory() . '/partner-affiliate/book.php';
    if (file_exists($path)) { include $path; }
    else { echo '<p style="color:red;">Error: Book file not found.</p>'; }
}
function pbp_affiliate_bookings_page($user_data) {
    $path = get_stylesheet_directory() . '/partner-affiliate/bookings.php';
    if (file_exists($path)) { include $path; }
    else { echo '<p style="color:red;">Error: Bookings file not found.</p>'; }
}
function pbp_affiliate_commissions_page($user_data) {
    $path = get_stylesheet_directory() . '/partner-affiliate/commissions.php';
    if (file_exists($path)) { include $path; }
    else { echo '<p style="color:red;">Error: Commissions file not found.</p>'; }
}
function pbp_affiliate_account_page($user_data) {
    $path = get_stylesheet_directory() . '/partner-affiliate/account.php';
    if (file_exists($path)) { include $path; }
    else { echo '<p style="color:red;">Error: Account file not found.</p>'; }
}

/* =========================
   Expose ajaxurl for logged-in users (optional)
   ========================= */
add_action('wp_head', function () {
    if (is_user_logged_in()) {
        echo '<script>var ajaxurl = "' . esc_url(admin_url('admin-ajax.php')) . '";</script>';
    }
});

/* =========================
   reCAPTCHA keys (server-side only)
   ========================= */
if (!defined('MY_RECAPTCHA_SITE_KEY')) {
    define('MY_RECAPTCHA_SITE_KEY', '6Lf3YVArAAAAAA1QZ6cs2jsVVfzID9WIOeTfKX8x');
}
if (!defined('MY_RECAPTCHA_SECRET_KEY')) {
    define('MY_RECAPTCHA_SECRET_KEY', '6Lf3YVArAAAAAG8TbCmh_jduN6K2Ocr-GVe5AEnv');
}

/* =========================
   reCAPTCHA helpers
   ========================= */

/**
 * Get a single token even if POSTed as an array (Firefox/duplicate fields, etc.).
 */
if (!function_exists('pbp_recaptcha_get_token')) {
    function pbp_recaptcha_get_token($field = 'g-recaptcha-response') {
        if (!isset($_POST[$field])) return '';
        $raw = $_POST[$field];
        if (is_array($raw)) {
            foreach ($raw as $v) {
                if (is_string($v)) {
                    $v = trim($v);
                    if ($v !== '') return $v;
                }
            }
            return '';
        }
        return is_string($raw) ? trim($raw) : '';
    }
}

/**
 * Verify token with Google (send the raw token).
 */
if (!function_exists('pbp_recaptcha_siteverify')) {
    function pbp_recaptcha_siteverify($token) {
        $resp = wp_remote_post('https://www.google.com/recaptcha/api/siteverify', [
            'timeout' => 10,
            'body'    => [
                'secret'   => MY_RECAPTCHA_SECRET_KEY,
                'response' => $token, // exact token required
                'remoteip' => isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field($_SERVER['REMOTE_ADDR']) : '',
            ],
        ]);
        if (is_wp_error($resp)) {
            return ['ok' => false, 'codes' => ['unavailable'], 'raw' => []];
        }
        $data  = json_decode(wp_remote_retrieve_body($resp), true);
        $ok    = !empty($data['success']);
        $codes = !empty($data['error-codes']) ? (array) $data['error-codes'] : [];
        return ['ok' => $ok, 'codes' => $codes, 'raw' => $data];
    }
}

/* =========================
   LOGIN: Short-circuit Traveler's AJAX login (st_login_popup)
   - Verify captcha once with Google
   - Manual auth to avoid other filters
   - Return JSON and exit
   ========================= */

if (!function_exists('pbp_handle_login_override')) {
    function pbp_handle_login_override() {
        // Identify our handler (helps debugging in Network tab)
        @header('X-PBP-Handler: st_login_popup');

        // Already logged in
        if (is_user_logged_in()) {
            wp_send_json(['status' => 1, 'message' => __('Already logged in.', 'traveler'), 'reload' => 1]);
        }

        // 1) reCAPTCHA: flatten token, verify with Google
        $raw = isset($_POST['g-recaptcha-response']) ? $_POST['g-recaptcha-response'] : null;
        @header('X-PBP-Raw-Type: ' . gettype($raw));
        @header('X-PBP-Raw-IsArray: ' . (is_array($raw) ? '1' : '0'));
        if (is_string($raw)) {
            @header('X-PBP-Raw-Len: ' . strlen(trim($raw)));
        } elseif (is_array($raw)) {
            $first = '';
            foreach ($raw as $v) { if (is_string($v) && ($v = trim($v)) !== '') { $first = $v; break; } }
            @header('X-PBP-Raw-First-Len: ' . strlen($first));
        }

        $token = pbp_recaptcha_get_token();
        @header('X-PBP-Token-Len: ' . strlen($token));

        if ($token === '') {
            @header('X-Recaptcha-Codes: missing-input-response');
            wp_send_json([
                'status'  => 0,
                'message' => __('Please complete the captcha.', 'traveler'),
                'codes'   => ['missing-input-response'],
                'raw'     => null,
            ]);
        }

        $vr = pbp_recaptcha_siteverify($token);
        if (!$vr['ok']) {
            $codes = !empty($vr['codes']) ? implode(', ', $vr['codes']) : 'unknown';
            @header('X-Recaptcha-Codes: ' . $codes);
            wp_send_json([
                'status'  => 0,
                'message' => sprintf(__('Captcha failed (%s). Please try again.', 'traveler'), esc_html($codes)),
                'codes'   => $vr['codes'],
                'raw'     => isset($vr['raw']) ? $vr['raw'] : null,
            ]);
        }

        // 2) Credentials (read form)
        $login_input = isset($_POST['username']) ? sanitize_text_field(wp_unslash($_POST['username'])) : '';
        $password    = isset($_POST['password']) ? (string) $_POST['password'] : '';
        $remember    = !empty($_POST['remember']);

        if ($login_input === '' || $password === '') {
            wp_send_json(['status' => 0, 'message' => __('Username and password are required.', 'traveler')]);
        }

        // 3) MANUAL AUTHENTICATION (bypass all authenticate filters)
        $user = get_user_by('login', $login_input);
        if (!$user && is_email($login_input)) {
            $user = get_user_by('email', $login_input);
        }
        if (!$user) {
            @header('X-PBP-Auth: user-not-found');
            wp_send_json(['status' => 0, 'message' => __('Invalid username or email.', 'traveler')]);
        }

        if (!wp_check_password($password, $user->user_pass, $user->ID)) {
            @header('X-PBP-Auth: bad-password');
            wp_send_json(['status' => 0, 'message' => __('Incorrect password.', 'traveler')]);
        }

        // 4) Establish session (set logged-in cookies)
        @header('X-PBP-Auth: manual-ok');
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, $remember, is_ssl());
        do_action('wp_login', $user->user_login, $user);

        // 5) Compute redirect URL and return it
        $redirect = home_url('/'); // default fallback
        if (function_exists('st')) {
            $candidates = [
                'page_user_dashboard',
                'page_user_account',
                'page_my_account',
            ];
            foreach ($candidates as $opt) {
                $pid = (int) st()->get_option($opt);
                if ($pid) { $redirect = get_permalink($pid); break; }
            }
        }
        if (!empty($_POST['redirect_to'])) {
            $rt = esc_url_raw(wp_unslash($_POST['redirect_to']));
            if ($rt) $redirect = $rt;
        }
        @header('X-Redirect: ' . $redirect);

        wp_send_json([
            'status'   => 1,
            'message'  => __('Login successful. Redirecting...', 'traveler'),
            'redirect' => $redirect,
            'reload'   => 1, // in case some scripts look for this
        ]);
    }
}

/**
 * EARLY INTERCEPT in admin-ajax for st_login_popup so our handler runs first and exits.
 */
add_action('admin_init', function () {
    if (defined('DOING_AJAX') && DOING_AJAX && isset($_REQUEST['action']) && $_REQUEST['action'] === 'st_login_popup') {
        pbp_handle_login_override();
        wp_die();
    }
}, 0);

/**
 * Belt & suspenders: remove theme handlers for st_login_popup then add ours.
 */
add_action('init', function () {
    if (function_exists('remove_all_actions')) {
        remove_all_actions('wp_ajax_nopriv_st_login_popup');
        remove_all_actions('wp_ajax_st_login_popup');
    } else {
        // Fallback for older WP
        remove_all_filters('wp_ajax_nopriv_st_login_popup');
        remove_all_filters('wp_ajax_st_login_popup');
    }
    add_action('wp_ajax_nopriv_st_login_popup', 'pbp_handle_login_override', 1);
    add_action('wp_ajax_st_login_popup',        'pbp_handle_login_override', 1);
}, 9999);

/* =========================
   REGISTER: enforce captcha then let theme continue
   ========================= */
if (!function_exists('pbp_guard_registration_captcha')) {
    function pbp_guard_registration_captcha() {
        if (is_user_logged_in()) return;

        $token = pbp_recaptcha_get_token();
        if ($token === '') {
            wp_send_json(['status' => 0, 'message' => __('Please complete the captcha.', 'traveler')]);
        }
        $vr = pbp_recaptcha_siteverify($token);
        if (!$vr['ok']) {
            $codes = !empty($vr['codes']) ? implode(', ', $vr['codes']) : 'unknown';
            wp_send_json(['status' => 0, 'message' => sprintf(__('Captcha failed (%s). Please try again.', 'traveler'), esc_html($codes))]);
        }
        // success: let theme's registration handler continue
    }
}
add_action('wp_ajax_nopriv_st_registration_popup', 'pbp_guard_registration_captcha', 0);
add_action('wp_ajax_st_registration_popup',        'pbp_guard_registration_captcha', 0);

/* =========================
   RESET PASSWORD: enforce captcha then let theme continue
   ========================= */
if (!function_exists('pbp_guard_reset_password_captcha')) {
    function pbp_guard_reset_password_captcha() {
        if (is_user_logged_in()) return;

        $token = pbp_recaptcha_get_token();
        if ($token === '') {
            wp_send_json(['status' => 0, 'message' => __('Please complete the captcha.', 'traveler')]);
        }
        $vr = pbp_recaptcha_siteverify($token);
        if (!$vr['ok']) {
            $codes = !empty($vr['codes']) ? implode(', ', $vr['codes']) : 'unknown';
            wp_send_json(['status' => 0, 'message' => sprintf(__('Captcha failed (%s). Please try again.', 'traveler'), esc_html($codes))]);
        }
        // success: let theme's reset handler continue
    }
}
add_action('wp_ajax_nopriv_st_reset_password', 'pbp_guard_reset_password_captcha', 0);
add_action('wp_ajax_st_reset_password',        'pbp_guard_reset_password_captcha', 0);

/* =========================
   Front-end redirect helper (login + register)
   - Listens for admin-ajax success on st_login_popup and st_registration_popup
   - Redirects to server-provided or computed URL
   ========================= */
add_action('wp_footer', function () {
    if (is_user_logged_in()) return; // only needed while logged-out

    // Compute login page for post-registration redirect
    $login_page_id = function_exists('st') ? (int) st()->get_option('page_user_login') : 0;
    $login_url     = $login_page_id ? get_permalink($login_page_id) : home_url('/login/');

    ?>
    <script>
    (function($){
      function parseAction(settings){
        try{
          if (!settings) return '';
          if (typeof settings.data === 'string') {
            var m = settings.data.match(/(?:^|&)action=([^&]+)/);
            return m ? decodeURIComponent(m[1]) : '';
          }
          if (settings.data && settings.data.get) {
            return settings.data.get('action') || '';
          }
        }catch(e){}
        return '';
      }

      function onAjaxSuccess(e, xhr, settings){
        try{
          if (!settings || !settings.url || settings.url.indexOf('admin-ajax.php') === -1) return;

          var action = parseAction(settings);
          if (action !== 'st_login_popup' && action !== 'st_registration_popup') return;

          // Prefer header-based redirect if server sent it (login flow)
          var hdr = xhr.getResponseHeader ? xhr.getResponseHeader('X-Redirect') : '';
          if (action === 'st_login_popup' && hdr) { window.location.assign(hdr); return; }

          // Parse JSON body
          var txt = xhr && xhr.responseText ? xhr.responseText : '';
          if (!txt) return;
          var res = {};
          try { res = JSON.parse(txt); } catch(e){ return; }

          if (!(res && (res.status === 1 || res.status === true))) return;

          if (action === 'st_login_popup') {
            var url = (res.redirect && typeof res.redirect === 'string') ? res.redirect : window.location.href;
            window.location.assign(url);
            return;
          }

          if (action === 'st_registration_popup') {
            // Registration usually keeps user logged-out; send to the Login page unless redirect_to is present
            var url = <?php echo json_encode($login_url); ?>;
            try {
              if (typeof settings.data === 'string') {
                var m = settings.data.match(/(?:^|&)redirect_to=([^&]+)/);
                if (m) url = decodeURIComponent(m[1]);
              } else if (settings.data && settings.data.get) {
                var rt = settings.data.get('redirect_to'); if (rt) url = rt;
              }
            } catch(e){}
            window.location.assign(url);
          }
        }catch(err){}
      }

      var $jq = window.jQuery || window.$;
      if ($jq && $jq(document) && $jq(document).on) {
        $jq(document).on('ajaxSuccess', onAjaxSuccess);
      }
    })(window.jQuery || window.$);
    </script>
    <?php
}, 999);

// End of file