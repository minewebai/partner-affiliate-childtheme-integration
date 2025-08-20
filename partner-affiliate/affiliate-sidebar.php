<?php
// File: ffiliate-sidebar.php
if (!defined('ABSPATH')) exit;

$current_page = isset($_GET['page']) ? sanitize_text_field($_GET['page']) : 'pbp_dashboard';
$base_permalink = get_permalink(get_the_ID());
?>

<li class="sidebar-dropdown <?php echo ($current_page === 'pbp_dashboard') ? 'active' : ''; ?>">
    <a href="<?php echo esc_url(add_query_arg('page', 'pbp_dashboard', $base_permalink)); ?>" style="color:#fff; font-weight:bold;">
        <img src="<?php echo get_template_directory_uri(); ?>/v2/images/dashboard/ico_dashboard.svg" alt="" class="st-icon-menu">
        <span><?php _e('Dashboard', 'partner-portal'); ?></span>
    </a>
</li>

<li class="sidebar-dropdown <?php echo ($current_page === 'pbp_book') ? 'active' : ''; ?>">
    <a href="<?php echo esc_url(add_query_arg('page', 'pbp_book', $base_permalink)); ?>" style="color:#fff; font-weight:bold;">
        <img src="<?php echo get_template_directory_uri(); ?>/v2/images/dashboard/ico_tour.svg" alt="" class="st-icon-menu">
        <span><?php _e('Book', 'partner-portal'); ?></span>
    </a>
</li>

<li class="sidebar-dropdown <?php echo ($current_page === 'pbp_bookings') ? 'active' : ''; ?>">
    <a href="<?php echo esc_url(add_query_arg('page', 'pbp_bookings', $base_permalink)); ?>" style="color:#fff; font-weight:bold;">
        <img src="<?php echo get_template_directory_uri(); ?>/v2/images/dashboard/ico_booking_his.svg" alt="" class="st-icon-menu">
        <span><?php _e('Bookings', 'partner-portal'); ?></span>
    </a>
</li>

<li class="sidebar-dropdown <?php echo ($current_page === 'pbp_commissions') ? 'active' : ''; ?>">
    <a href="<?php echo esc_url(add_query_arg('page', 'pbp_commissions', $base_permalink)); ?>" style="color:#fff; font-weight:bold;">
        <img src="<?php echo get_template_directory_uri(); ?>/v2/images/dashboard/ico_wishlish.svg" alt="" class="st-icon-menu">
        <span><?php _e('Commissions', 'partner-portal'); ?></span>
    </a>
</li>

<li class="sidebar-dropdown <?php echo ($current_page === 'pbp_account') ? 'active' : ''; ?>">
    <a href="<?php echo esc_url(add_query_arg('page', 'pbp_account', $base_permalink)); ?>" style="color:#fff; font-weight:bold;">
        <img src="<?php echo get_template_directory_uri(); ?>/v2/images/dashboard/ico_seting.svg" alt="" class="st-icon-menu">
        <span><?php _e('Account', 'partner-portal'); ?></span>
    </a>
</li>
