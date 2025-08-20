<?php
get_header();
$current_user_upage = get_user_by('slug', get_query_var('author_name'));

$role = $current_user_upage->roles[0];
$user_meta = get_user_meta($current_user_upage->ID);
$user_meta = array_filter(array_map(function ($a) {
    return $a[0];
}, $user_meta));

$list_info = st()->get_option('display_list_partner_info', '');
$style_item_author_page = st()->get_option('option_style_item_author_page', '');

if ($list_info == 'all') {
    $list_info = array('all');
}
if (empty($list_info)) {
    $list_info = array('all');
}

$arr_service = STUser_f::getListServicesAuthor($current_user_upage);
if (!empty($arr_service)) {
    $active_tab = STInput::get('service', $arr_service[0]);
}

$inner_style = '';
$header_bg = st()->get_option('patner_page_header_bg', '');
if (!empty($header_bg)) {
    $inner_style = Assets::build_css("background-image: url(" . esc_url($header_bg) . ") !important;");
    $img = $header_bg;
} else {
    $thumb_id = get_post_thumbnail_id(get_the_ID());
    $img = wp_get_attachment_image_url($thumb_id, 'full');
    $inner_style = Assets::build_css("background-image: url(" . esc_url($img) . ") !important;");
}

/* Helper: reorder services to Tours → Activity → Cars → Hotel → Rental → Flight */
if (!function_exists('rt_reorder_services')) {
    function rt_reorder_services($arr_service) {
        $arr = is_array($arr_service) ? array_values($arr_service) : array();
        $norm = array();
        foreach ($arr as $s) {
            $n = strtolower(trim($s));
            $n = preg_replace('/^st_/', '', $n);
            if ($n !== '') $norm[] = $n;
        }
        $norm = array_values(array_unique($norm));
        $desired = array('tours', 'activity', 'cars', 'hotel', 'rental', 'flight');
        $ordered = array_values(array_intersect($desired, $norm));
        foreach ($norm as $svc) {
            if (!in_array($svc, $ordered, true)) $ordered[] = $svc;
        }
        return $ordered;
    }
}

/* Renderer: services with custom order */
if (!function_exists('rt_render_author_service_override')) {
    function rt_render_author_service_override($arr_service_ordered, $current_user_upage) {
        if (empty($arr_service_ordered)) {
            echo '<h5>' . esc_html__('No partner services!', 'traveler') . '</h5>';
            return;
        }

        // Active tab
        $requested = STInput::get('service', $arr_service_ordered[0]);
        $requested = strtolower(trim($requested));
        $requested = preg_replace('/^st_/', '', $requested);
        $active_tab = in_array($requested, $arr_service_ordered, true) ? $requested : $arr_service_ordered[0];

        // Tabs
        echo '<ul class="nav nav-tabs" id="">';
        foreach ($arr_service_ordered as $v) {
            if (!STUser_f::_check_service_available_partner('st_' . $v, $current_user_upage->ID)) {
                continue;
            }
            $get = $_GET;
            $get['service'] = $v;
            unset($get['pages']);
            $author_link = esc_url(get_author_posts_url($current_user_upage->ID));
            $url = esc_url(add_query_arg($get, $author_link));
            echo '<li class="' . ($active_tab === $v ? 'active' : '') . '"><a href="' . esc_url($url) . '" aria-expanded="true">';
            switch ($v) {
                case 'hotel':    echo __('Hotels', 'traveler'); break;
                case 'tours':    echo __('Tours', 'traveler'); break;
                case 'activity': echo __('Activity', 'traveler'); break;
                case 'cars':     echo __('Car', 'traveler'); break;
                case 'rental':   echo __('Rental', 'traveler'); break;
                case 'flight':   echo __('Flight', 'traveler'); break;
                default:         echo esc_html(ucfirst($v)); break;
            }
            echo '</a></li>';
        }
        echo '</ul>';

        // Content for active tab
        echo '<div class="tab-content"><div class="tab-pane fade active in author-sv-list" id="tab-all">';

        $service = $active_tab;
        $paged = (get_query_var('paged')) ? get_query_var('paged') : 1;
        $author = $current_user_upage->ID;
        $is_featured_hotel    = st()->get_option('is_featured_search_hotel', 'off');
        $is_featured_rental   = st()->get_option('is_featured_search_rental', 'off');
        $is_featured_tour     = st()->get_option('is_featured_search_tour', 'off');
        $is_featured_activity = st()->get_option('is_featured_search_activity', 'off');
        $is_featured_car      = st()->get_option('is_featured_search_car', 'off');

        $args = array(
            'post_type'      => 'st_' . esc_attr($service),
            'post_status'    => 'publish',
            'author'         => $author,
            'posts_per_page' => 6,
            'paged'          => $paged,
        );

        if ($service === 'hotel' && $is_featured_hotel === 'on') {
            $args['meta_key'] = 'is_featured'; $args['orderby'] = 'meta_value'; $args['order'] = 'DESC';
        } elseif ($service === 'tours' && $is_featured_tour === 'on') {
            $args['meta_key'] = 'is_featured'; $args['orderby'] = 'meta_value'; $args['order'] = 'DESC';
        } elseif ($service === 'activity' && $is_featured_activity === 'on') {
            $args['meta_key'] = 'is_featured'; $args['orderby'] = 'meta_value'; $args['order'] = 'DESC';
        } elseif ($service === 'cars' && $is_featured_car === 'on') {
            $args['meta_key'] = 'is_featured'; $args['orderby'] = 'meta_value'; $args['order'] = 'DESC';
        } elseif ($service === 'rental' && $is_featured_rental === 'on') {
            $args['meta_key'] = 'is_featured'; $args['orderby'] = 'meta_value'; $args['order'] = 'DESC';
        }

        $query = new WP_Query($args);

        if ($query->have_posts()) {
            switch ($service) {
                case "hotel":
                    echo '<div class="search-result-page"><div class="st-results st-hotel-result"><div class="row service-list-wrapper">';
                    break;
                case "tours":
                    echo '<div class="search-result-page st-tours"><div class="st-results st-hotel-result"><div class="row service-list-wrapper">';
                    break;
                case "activity":
                    echo '<div class="search-result-page st-tours st-activity"><div class="st-results st-hotel-result"><div class="row service-list-wrapper">';
                    break;
                case "cars":
                    echo '<div class="search-result-page st-tours"><div class="st-results st-hotel-result"><div class="row service-list-wrapper">';
                    break;
                case "rental":
                    echo '<div class="search-result-page st-rental "><div class="st-results st-hotel-result"><div class="row service-list-wrapper">';
                    break;
                // case "flight":
                //     echo '<ul class="booking-list loop-rental style_list">';
                //     break;
            }
            while ($query->have_posts()) {
                $query->the_post();
                switch ($service) {
                    case "hotel":
                        echo st()->load_template('layouts/elementor/hotel/loop/normal', 'grid', array('item_row'=> 3));
                        break;
                    case "tours":
                        echo st()->load_template('layouts/elementor/tour/loop/normal','grid',array('item_row'=> 3));
                        break;
                    case "activity":
                        echo st()->load_template('layouts/elementor/activity/loop/normal','grid',array('item_row'=> 3));
                        break;
                    case "cars":
                        echo st()->load_template('layouts/elementor/car/loop/normal','grid',array('item_row'=> 3));
                        break;
                    case "rental":
                        echo st()->load_template('layouts/elementor/rental/loop/normal','grid');
                        break;
                    case "flight":
                        echo st()->load_template('user/loop/loop', 'flight-upage');
                        break;
                }
            }
            echo "</div></div></div>";
        } else {
            echo '<h5>' . __('No data', 'traveler') . '</h5>';
        }
        wp_reset_postdata();

        echo '<br/><div class="pull-left author-pag">';
        st_paging_nav(null, $query);
        echo '</div>';

        echo '</div></div>';
    }
}

// Compute ordered services once, use for Services and Reviews
$arr_service_ordered = rt_reorder_services($arr_service);
?>

<div class="st-author-page">
    <?php
    $menu_transparent = st()->get_option('menu_transparent', '');
    if ($menu_transparent === 'on') {
        if ($img) {
            echo '<div id="st-content-wrapper" class="st-style-elementor">';
            echo stt_elementorv2()->loadView('components/banner', ['img_url' => $img, 'type_page' => 'author_page']);
            echo '</div>';
        }
    } else { ?>
        <div class="banner <?php echo esc_attr($inner_style); ?>">
            <div class="container">
                <h1><?php echo __('Partner Page', 'traveler'); ?></h1>
            </div>
        </div>
    <?php } ?>

    <div class="container">
        <div class="row">
            <div class="col-lg-3">
                <div class="author-header<?php if ($style_item_author_page == 'mod') echo ' st-border-radius-16'; ?>">
                    <div class="author-avatar">
                        <?php echo st_get_profile_avatar($current_user_upage->ID, 100); ?>
                    </div>
                    <h3 class="author-name">
                        <?php echo esc_html($current_user_upage->display_name); ?>
                    </h3>
                    <div class="author-review">
                        <?php
                        $review_data = STUser_f::getReviewsDataAuthor($arr_service, $current_user_upage);
                        if (!empty($review_data)) {
                            $avg_rating = STUser_f::getAVGRatingAuthor($review_data); ?>
                            <div class="author-review-box">
                                <div class="author-start-rating">
                                    <div class="stm-star-rating">
                                        <div class="inner">
                                            <div class="stm-star-rating-upper" style="width:<?php echo (float)$avg_rating / 5 * 100; ?>%;"></div>
                                            <div class="stm-star-rating-lower"></div>
                                        </div>
                                    </div>
                                </div>
                                <p class="author-review-label">
                                    <?php printf(__('%d Reviews', 'traveler'), count($review_data)); ?>
                                </p>
                            </div>
                        <?php } ?>
                    </div>
                    <div class="author-membersince">
                        <small><?php echo __('Member since ', 'traveler') . mysql2date('M d, Y', $current_user_upage->data->user_registered); ?></small>
                    </div>
                </div>

                <?php if (!empty($user_meta['st_is_check_show_info']) || !empty($user_meta['st_phone']) || !empty($user_meta['st_paypal_email']) || !empty($user_meta['st_address'])) : ?>
                    <div class="author-body<?php if ($style_item_author_page == 'mod') echo ' st-border-radius-16'; ?>">
                        <ul class="author-list-info">
                            <?php if (!empty($user_meta['st_is_check_show_info']) && $user_meta['st_is_check_show_info'] == 'on') : ?>
                                <?php if (in_array('all', $list_info) || in_array('email', $list_info)) { ?>
                                    <li><strong><?php _e('Email: ', 'traveler'); ?></strong><?php echo esc_html($current_user_upage->user_email); ?></li>
                                <?php } ?>
                                <?php if (!empty($user_meta['st_phone']) && (in_array('all', $list_info) || in_array('phone', $list_info))) { ?>
                                    <li><strong><?php _e('Phone: ', 'traveler'); ?></strong><?php echo esc_html($user_meta['st_phone']); ?></li>
                                <?php } ?>
                                <?php if (!empty($user_meta['st_paypal_email']) && (in_array('all', $list_info) || in_array('email_paypal', $list_info))) { ?>
                                    <li><strong><?php _e('Email Paypal: ', 'traveler'); ?></strong><?php echo esc_html($user_meta['st_paypal_email']); ?></li>
                                <?php } ?>
                            <?php endif; ?>

                            <?php if (!empty($user_meta['st_airport']) && (in_array('all', $list_info) || in_array('home_airport', $list_info))) { ?>
                                <li><strong><?php _e('Home Airport: ', 'traveler'); ?></strong><?php echo esc_html($user_meta['st_airport']); ?></li>
                            <?php } ?>

                            <?php if (!empty($user_meta['st_address']) || !empty($user_meta['st_city']) || !empty($user_meta['st_country'])) : ?>
                                <?php if (in_array('all', $list_info) || in_array('address', $list_info)) { ?>
                                    <li><strong><?php _e('Address: ', 'traveler'); ?></strong>
                                        <?php
                                        $address = '';
                                        if (isset($user_meta['st_address'])) $address .= $user_meta['st_address'];
                                        if (isset($user_meta['st_city'])) $address .= ', ' . esc_html($user_meta['st_city']);
                                        if (isset($user_meta['st_country'])) $address .= ', ' . esc_html($user_meta['st_country']);
                                        echo esc_html($address);
                                        ?>
                                    </li>
                                <?php } ?>
                            <?php endif; ?>
                        </ul>
                    </div>
                <?php endif; ?>

                <div class="author-verify<?php if ($style_item_author_page == 'mod') echo ' st-border-radius-16'; ?>">
                    <h4 class="verify-title"><?php esc_html_e('Verifications', 'traveler') ?></h4>
                    <ul>
                        <?php
                        $verifications = [
                            'phone' => 'Phone number',
                            'passport' => 'ID Card',
                            'travel_certificate' => 'Travel Certificate',
                            'email' => 'Email',
                            'social' => 'Social media'
                        ];
                        foreach ($verifications as $key => $label) {
                            $verified = st_check_user_verify($key, $current_user_upage->ID) || current_user_can('administrator') || $role === 'administrator';
                            ?>
                            <li>
                                <span class="left-icon"><?php echo TravelHelper::getNewIcon('check-1', '#A0A9B2', '15px', '15px', false); ?></span>
                                <span><?php echo esc_html__($label, 'traveler'); ?></span>
                                <span class="right-icon">
                                    <?php echo TravelHelper::getNewIcon($verified ? 'check-1' : 'remove', $verified ? '#2ECC71' : '#FA5636', '18px', '18px', false); ?>
                                </span>
                            </li>
                        <?php } ?>
                    </ul>
                </div>
            </div>

            <div class="col-lg-9">
                <?php
                // About
                $bio = '';
                if (!empty($user_meta['st_bio'])) {
                    $bio = $user_meta['st_bio'];
                } elseif (!empty($current_user_upage->description)) {
                    $bio = $current_user_upage->description;
                }

                if (!empty($bio)) { ?>
                    <div class="author-about">
                        <h3 class="title"><?php echo __('About', 'traveler'); ?></h3>
                        <div class="about-content">
                            <div class="st-cut-text" data-count="45" data-text-more="<?php echo __('More', 'traveler') ?>" data-text-less="<?php echo __('Less', 'traveler') ?>">
                                <?php echo wp_kses_post(nl2br($bio)); ?>
                            </div>
                        </div>
                    </div>
                <?php } ?>

                <?php
                // Render services with custom order
                rt_render_author_service_override($arr_service_ordered, $current_user_upage);
                ?>

                <div class="st-review-new" style="margin-top: 24px;">
                    <h5><?php echo __('Review', 'traveler'); ?></h5>
                    <?php
                    // Pass ordered services so review tabs match the same order
                    echo st()->load_template('layouts/elementor/page/elements/partner', 'review', array(
                        'current_user_upage'   => $current_user_upage,
                        'arr_service'          => $arr_service_ordered,
                        'post_per_page_review' => 5
                    ));
                    ?>
                </div>
            </div>
        </div>
    </div>
</div>

<?php get_footer(); ?>