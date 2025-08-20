<?php
// File: /home/dbfa8e5/reimaginetours.com/wp-content/themes/traveler-childtheme/partner-affiliate/class-pbp-utils.php (created based on your backend repo)

if (!defined('ABSPATH')) exit;

class PBP_Utils {
    public static function get_partner_allowed_posts($user_id, $post_type) {
        $posts = get_posts([
            'post_type' => $post_type,
            'author' => $user_id,
            'posts_per_page' => -1,
            'post_status' => 'publish'
        ]);

        return wp_list_pluck($posts, 'ID');
    }
}
?>