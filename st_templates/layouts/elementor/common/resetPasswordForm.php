<?php
if (!is_user_logged_in()) {
    // Get login page URL for "Back to Log In"
    $login_page = get_the_permalink(function_exists('st') ? st()->get_option('page_user_login') : 0);
    if (empty($login_page)) {
        $p = get_page_by_path('login');
        if ($p) $login_page = get_permalink($p->ID);
    }
    if (empty($login_page)) $login_page = home_url('/login/');

    // reCAPTCHA v2 site key
    $recaptcha_site_key = defined('MY_RECAPTCHA_SITE_KEY') ? MY_RECAPTCHA_SITE_KEY : '6LcB-6MrAAAAAAs2aQQwdpRxdZAXfKrt-UcF3n8M';
    ?>
    <div class="modal fade" id="st-forgot-form" tabindex="-1" role="dialog" aria-hidden="true">
        <div class="modal-dialog" role="document" style="max-width: 450px;">
            <div class="modal-content">
                <?php echo st()->load_template('layouts/modern/common/loader'); ?>
                <div class="modal-header d-sm-flex d-md-flex justify-content-between align-items-center">
                    <div class="modal-title"><?php echo __('Reset Password', 'traveler') ?></div>
                    <button type="button" class="close" data-bs-dismiss="modal" aria-label="Close">
                        <?php echo TravelHelper::getNewIcon('Ico_close') ?>
                    </button>
                </div>
                <div class="modal-body">
                    <form action="#" class="form" method="post">
                        <input type="hidden" name="st_theme_style" value="modern"/>
                        <input type="hidden" name="action" value="st_reset_password">
                        <p class="c-grey f14">
                            <?php echo __('Enter the e-mail address associated with the account.', 'traveler') ?><br/>
                            <?php echo __('We\'ll e-mail a link to reset your password.', 'traveler') ?>
                        </p>

                        <div class="form-group">
                            <input type="email" class="form-control" name="email"
                                   placeholder="<?php echo esc_html__('Email', 'traveler') ?>">
                            <?php echo TravelHelper::getNewIcon('ico_email_login_form'); ?>
                        </div>

                        <?php if (!empty($recaptcha_site_key)) : ?>
                            <div class="form-group recaptcha-wrap">
                                <div class="g-recaptcha" data-sitekey="<?php echo esc_attr($recaptcha_site_key); ?>"></div>
                            </div>
                        <?php endif; ?>

                        <div class="form-group">
                            <input type="submit" name="submit" class="form-submit"
                                   value="<?php echo esc_html__('Send Reset Link', 'traveler') ?>">
                        </div>

                        <div class="message-wrapper mt20"></div>

                        <div class="text-center mt20">
                            <a href="<?php echo esc_url($login_page); ?>" class="st-link font-medium back-login-link">
                                <?php echo esc_html__('Back to Log In', 'traveler') ?>
                            </a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <?php if (!empty($recaptcha_site_key)) : ?>
        <script>
        (function(){
            // Load the reCAPTCHA API only once
            if (!document.querySelector('script[src*="www.google.com/recaptcha/api.js"]')) {
                var s = document.createElement('script');
                s.src = 'https://www.google.com/recaptcha/api.js';
                s.async = true; s.defer = true;
                document.head.appendChild(s);
            }
        })();
        </script>
    <?php endif; ?>
    <?php
}
?>