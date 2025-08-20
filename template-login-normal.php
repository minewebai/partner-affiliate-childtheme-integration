<?php
/*
Template Name: Login Normal
*/
do_action('st_before_login_template');
get_header();
?>

<div class="container-fluid">
    <div class="row">
        <div class="container">
            <h1 class="page-title">
                <?php printf(__("Login/Register on %s", 'traveler'), get_bloginfo('name')); ?>
            </h1>
        </div>
        <div class="container">
            <div class="row" data-gutter="60">

                <!-- Info/Description -->
                <div class="col-md-4 mt30">
                    <h3><?php the_title(); ?></h3>
                    <?php
                    while ( have_posts() ) {
                        the_post();
                        the_content();
                    }
                    ?>
                </div>

                <!-- Login Form -->
                <div class="col-md-4 mt30">
                    <h3><?php esc_html_e('Login', 'traveler'); ?></h3>

                    <!-- Load reCAPTCHA script unconditionally for this template -->
                    <script src="https://www.google.com/recaptcha/api.js" async defer></script>

                    <form method="post" action="<?php echo esc_url( wp_login_url() ); ?>">
                        <?php wp_nonce_field( 'login_form', 'login_field' ); ?>

                        <div class="form-group">
                            <label for="user_login"><?php esc_html_e('Username', 'traveler'); ?></label>
                            <input type="text" name="log" id="user_login" class="form-control" required>
                        </div>

                        <div class="form-group">
                            <label for="user_password"><?php esc_html_e('Password', 'traveler'); ?></label>
                            <input type="password" name="pwd" id="user_password" class="form-control" required>
                        </div>

                        <!-- reCAPTCHA v2 Checkbox -->
                        <div class="g-recaptcha mb20" data-sitekey="6LcB-6MrAAAAAAs2aQQwdpRxdZAXfKrt-UcF3n8M"></div>

                        <button type="submit" class="btn btn-primary"><?php esc_html_e('Login', 'traveler'); ?></button>
                    </form>
                </div>

                <!-- Registration Column -->
                <div class="col-md-4 mt30">
                    <h3 class="pb30 mb0">
                        <?php printf(__("New To %s ?", 'traveler'), get_bloginfo('title')); ?>
                    </h3>
                    <?php $page_user_register = st()->get_option("page_user_register"); ?>
                    <div class="mt5">
                        <b><a class="btn-lg btn btn-primary" href="<?php echo get_permalink($page_user_register); ?>">
                            <?php _e("Register New", 'traveler'); ?>
                        </a></b>
                    </div>
                    <div class="mt15"><?php do_action('wordpress_social_login'); ?></div>
                </div>

            </div>
        </div>
        <div class="gap"></div>
    </div>
</div>

<?php
// Server-side verification of reCAPTCHA
if ( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
    if ( empty( $_POST['g-recaptcha-response'] ) ) {
        wp_die( __( 'Please complete the reCAPTCHA.', 'traveler' ) );
    }

    $secret_key = '6LcB-6MrAAAAABInszdzBKGJTxf7ObXX3Uag7lfs';

    $response = wp_remote_post(
        'https://www.google.com/recaptcha/api/siteverify',
        [
            'body' => [
                'secret'   => $secret_key,
                'response' => sanitize_text_field( $_POST['g-recaptcha-response'] ),
                'remoteip' => $_SERVER['REMOTE_ADDR']
            ]
        ]
    );

    $result = json_decode( wp_remote_retrieve_body( $response ), true );

    if ( empty( $result['success'] ) ) {
        wp_die( __( 'reCAPTCHA verification failed. Please try again.', 'traveler' ) );
    }
}
?>

<?php get_footer(); ?>