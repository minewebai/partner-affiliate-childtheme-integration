<?php
// File: theme_root/partner-affiliate/assign.php

if (!defined('ABSPATH')) exit;

$user_id = get_current_user_id();
$is_admin = current_user_can('manage_options');
$is_partner = current_user_can('partner');
$is_affiliate = function_exists('get_field') && get_field('type', 'user_' . $user_id) === 'affiliate';

if (!($is_partner && $is_affiliate) && !$is_admin) {
    echo '<p class="st-alert" style="color:#fff;">' . esc_html__('You do not have permission to view this page.', 'partner-portal') . '</p>';
    return;
}
?>

<div class="affiliate-hub-overview">
    <h2 class="page-title"><?php esc_html_e('Affiliate Hub Overview', 'partner-portal'); ?></h2>
    <p><?php esc_html_e('Manage and assign commission roles, access settings, and partner visibility from here.', 'partner-portal'); ?></p>

    <ul class="affiliate-hub-links">
        <li><a href="?page=commission-tiers"><?php esc_html_e('Commission Tiers', 'partner-portal'); ?></a></li>
        <li><a href="?page=affiliate-edit"><?php esc_html_e('Edit Partner Settings', 'partner-portal'); ?></a></li>
    </ul>
</div>
