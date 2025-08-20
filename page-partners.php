<?php
/**
 * Template Name: Our Guides and Partners  
 * File : page-partners.php
 * Fixed: Admin-first order without breaking reviews/stars
 */
get_header();

echo '<h1 style="text-align:center;">' . esc_html__('Our Guides and Partners', 'traveler') . '</h1>';

$roles = ['partner', 'administrator'];
$users = get_users([
    'role__in' => $roles,
    'orderby'  => 'display_name',
    'order'    => 'ASC',
    'number'   => 100,
]);

$valid_post_types = ['st_tours', 'st_hotel', 'st_activity', 'st_rental', 'st_cars'];
$post_types = array_filter($valid_post_types, 'post_type_exists');

if (!$users || empty($post_types)) {
    echo '<p>' . esc_html__('No partners or valid listings found.', 'traveler') . '</p>';
    get_footer();
    exit;
}

// Separate admins first
$admin_users = [];
$other_users = [];
$user_counts = []; // store listing counts

foreach ($users as $user) {
    $user_id = $user->ID;
    $counts = [];
    foreach ($post_types as $pt) {
        $counts[$pt] = count_user_posts($user_id, $pt);
    }
    if (array_sum($counts) === 0) continue; // skip users with no listings
    $user_counts[$user_id] = $counts;

    if (in_array('administrator', $user->roles)) {
        $admin_users[] = $user;
    } else {
        $other_users[] = $user;
    }
}

$users_ordered = array_merge($admin_users, $other_users);

echo '<div class="partner-listing-wrapper">';

foreach ($users_ordered as $user) {
    $user_id = $user->ID;
    $counts = $user_counts[$user_id];

    $avatar_url = get_avatar_url($user_id, ['size' => 70]) ?: get_template_directory_uri() . '/images/default-avatar.png';
    $avatar_img = '<img class="partner-avatar" src="' . esc_url($avatar_url) . '" alt="' . esc_attr($user->display_name) . '" style="border-radius:50%;">';

    $first_name = get_user_meta($user_id, 'first_name', true);
    $display_name = $first_name ?: $user->display_name;
    $profile_link = get_author_posts_url($user_id);
    $bio_trimmed = mb_strimwidth((string) get_user_meta($user_id, 'description', true), 0, 500, '...');
    $city = get_user_meta($user_id, 'st_city', true);

    // Services for reviews
    $map_pt_to_service = [
        'st_hotel' => 'hotel',
        'st_tours' => 'tours',
        'st_activity'=> 'activity',
        'st_rental' => 'rental',
        'st_cars' => 'cars',
        'st_flight' => 'flight',
    ];

    $arr_service_for_reviews = [];
    foreach ($counts as $pt => $count) {
        if ($count > 0 && isset($map_pt_to_service[$pt])) {
            $arr_service_for_reviews[] = $map_pt_to_service[$pt];
        }
    }
    if (empty($arr_service_for_reviews)) {
        $arr_service_for_reviews = ['hotel','tours','activity','rental','cars','flight'];
    }

    // REVIEW DATA – pass original $user
    $review_data = STUser_f::getReviewsDataAuthor($arr_service_for_reviews, $user);
    $total_reviews = is_array($review_data) ? count($review_data) : 0;
    $average_rating = $total_reviews > 0 ? (float) STUser_f::getAVGRatingAuthor($review_data) : 0.0;

    $admin_class = in_array('administrator', $user->roles) ? ' admin-partner' : '';

    echo '<div class="partner-card' . $admin_class . '">';
    echo '<a href="' . esc_url($profile_link) . '">' . $avatar_img . '</a>';
    echo '<a class="partner-name" href="' . esc_url($profile_link) . '">' . esc_html($display_name) . '</a>';
    if ($city) echo '<div class="partner-city">' . esc_html($city) . '</div>';
    if ($bio_trimmed) echo '<div class="partner-bio">' . esc_html($bio_trimmed) . '</div>';

    // REVIEWS stars + count
    echo '<div class="author-review-box" style="margin:6px 0 10px;">';
    echo '  <div class="author-star-rating">'; // fixed typo from "author-start-rating"
    echo '      <div class="stm-star-rating">';
    echo '          <div class="inner">';
    echo '              <div class="stm-star-rating-upper" style="width:' . esc_attr(($average_rating / 5) * 100) . '%;"></div>';
    echo '              <div class="stm-star-rating-lower"></div>';
    echo '          </div>';
    echo '      </div>';
    echo '  </div>';
    echo '  <p class="author-review-label" style="margin:6px 0 0;">' . sprintf(esc_html__('%d Reviews', 'traveler'), (int) $total_reviews) . '</p>';
    echo '</div>';

    // Listing counts
    echo '<div class="listing-counts">';
    foreach ($counts as $type => $count) {
        if ($count > 0) {
            $label = ucfirst(str_replace('st_', '', $type));
            echo '<span>' . esc_html($label) . ': ' . esc_html($count) . '</span> ';
        }
    }
    echo '</div>';

    echo '</div>'; // .partner-card
}

echo '</div>'; // .partner-listing-wrapper

get_footer();
?>
