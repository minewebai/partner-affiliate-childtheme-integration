
<?php

/**
 *   grid card v5.6
 * fixes reviews all styles not just style1  (but I changed how style_2 looks like style_3 now but only works on home page)
 * Always displays your 5-star review block for every card, for every style.
 * No need for $style checking, because it isn’t passed.
 * No risk of missing reviews on any style.
 * adds block for style 3 review testi ng
 * 5 stars  5/5 etc 
 */
$post_id = get_the_ID();
$post_translated = TravelHelper::post_translated($post_id);
$thumbnail_id = get_post_thumbnail_id($post_translated);
$duration = get_post_meta( get_the_ID(), 'duration_day', true );
$info_price = STTour::get_info_price();
$address = get_post_meta($post_translated, 'address', true);

$review_rate = floatval(STReview::get_avg_rate());
$count_review = get_comment_count($post_translated)['approved'];
$class_image = 'image-feature st-hover-grow';
$url = st_get_link_with_search(get_permalink($post_translated), array('start', 'date', 'adult_number', 'child_number'), $_GET);
?>
<div class="services-item item-elementor grid-2" itemscope itemtype="https://schema.org/TouristTrip">
    <div class="item service-border st-border-radius">
        <div class="featured-image">
            <div class="st-tag-feature-sale">
                <?php
                $is_featured = get_post_meta($post_translated, 'is_featured', true);
                if ($is_featured == 'on') { ?>
                    <div class="featured">
                        <?php
                        if (!empty(st()->get_option('st_text_featured', ''))) {
                            echo wp_kses_post(st()->get_option('st_text_featured', ''));
                        } else {?>
                            <?php echo esc_html__('Featured', 'traveler') ?>
                        <?php }
                        ?>
                    </div>
                <?php } ?>
                <?php if (!empty($info_price['discount']) && $info_price['discount'] > 0 && $info_price['price_new'] > 0) { ?>
                    <?php echo STFeatured::get_sale($info_price['discount']); ?>
                <?php } ?>
            </div>
            <?php if (is_user_logged_in()) { ?>
                <?php $data = STUser_f::get_icon_wishlist(); ?>
                <div class="service-add-wishlist login <?php echo ($data['status']) ? 'added' : ''; ?>"
                     data-id="<?php echo get_the_ID(); ?>" data-type="<?php echo get_post_type(get_the_ID()); ?>"
                     title="<?php echo ($data['status']) ? __('Remove from wishlist', 'traveler') : __('Add to wishlist', 'traveler'); ?>">
                    <?php echo TravelHelper::getNewIconV2('wishlist');?>
                    <div class="lds-dual-ring"></div>
                </div>
            <?php } else { ?>
                <a href="#" class="login" data-bs-toggle="modal" data-bs-target="#st-login-form">
                    <div class="service-add-wishlist" title="<?php echo __('Add to wishlist', 'traveler'); ?>">
                        <?php echo TravelHelper::getNewIconV2('wishlist');?>
                        <div class="lds-dual-ring"></div>
                    </div>
                </a>
            <?php } ?>
            <a href="<?php echo esc_url($url); ?>">
                <img itemprop="image" src="<?php echo wp_get_attachment_image_url($thumbnail_id, array(900, 600)); ?>"
                     alt="<?php echo TravelHelper::get_alt_image(); ?>" class="<?php echo esc_attr($class_image); ?>"/>
            </a>
            <?php do_action('st_list_compare_button', get_the_ID(), get_post_type(get_the_ID())); ?>
            <?php echo st_get_avatar_in_list_service(get_the_ID(),70)?>
        </div>
        <div class="content-item">
            <?php if ($address) { ?>
                <div class="sub-title st-address d-flex align-items-center" itemprop="itinerary" itemscope itemtype="https://schema.org/ItemList">
                    <span itemprop="itemListElement" itemtype="https://schema.org/ListItem" itemscope>
                        <div itemtype="https://schema.org/TouristAttraction" itemscope>
                            <i class="stt-icon-location1"></i>
                            <div itemprop="name" style="display: inline-block"><?php echo esc_html($address); ?></div>
                        </div>
                    </span>
                </div>
            <?php } ?>
            <h3 class="title" itemprop="name">
                <a href="<?php echo esc_url($url); ?>"
                   class="c-main"><?php echo get_the_title($post_translated) ?></a>
            </h3>
<!-- Begin People Viewing Notice -->

<?php
// People Viewing Notice
$people_viewing = rand(12, 45);
$messages = [
    "Only 5 hours left to book!",
    "Hurry, just a few spots remain!",
    "Book now, limited time offer!",
    "Limited slots available — book now!",
    "" // Empty message option
];
$message = $messages[array_rand($messages)];
?>
<div class="people-viewing-notice" style="display: block !important; opacity: 1 !important; background: #f5f5f5; padding: 12px; border: 1px solid #800020; margin-top: 8px; font-size: 14px; color: #e60000; z-index: 9999; font-weight: bold; border-radius: 8px;">
    <strong>👀 <?php echo esc_html($people_viewing); ?> people are looking at this tour</strong>
    <?php if (!empty($message)): ?>
        <br><strong>⏳ <?php echo esc_html($message); ?></strong>
    <?php endif; ?>
</div><br>
<?php
?>
<!-- End People Viewing Notice -->
<?php
// Begin cancellation code

$allow_cancel = get_post_meta(get_the_ID(), 'st_allow_cancel', true);

if (!empty($allow_cancel) && ($allow_cancel === 'on' || $allow_cancel === 'yes' || $allow_cancel == 1)) {
    echo '
    <style>
        .st-tooltip-container {
            position: relative;
            display: inline-block;
        }

        .st-tooltip-icon {
            border: 1.5px solid #888; /* grey border */
            background-color: transparent; /* transparent background */
            color: #888; /* grey "i" */
            border-radius: 50%;
            padding: 0 7px;
            font-size: 12px;
            font-weight: bold;
            display: inline-block;
            line-height: 18px;
            text-align: center;
            cursor: help;
            user-select: none;
            margin-left: 6px;
            transition: none; /* no hover bg change */
            position: relative;
        }

        /* Remove any native tooltip blue ? or default browser tooltip */
        .st-tooltip-icon[title],
        .st-tooltip-icon[title]:hover::after,
        .st-tooltip-icon:hover::after {
            content: none !important;
            display: none !important;
            pointer-events: none !important;
        }

        .st-tooltip-text {
            visibility: hidden;
            width: 260px;
            background-color: #fff; /* white background */
            color: #000; /* black text */
            text-align: left;
            border-radius: 6px;
            padding: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
            position: absolute;
            z-index: 9999;
            bottom: 125%;
            left: 50%;
            margin-left: -130px;
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 13px;
            pointer-events: none;
        }

        .st-tooltip-text::after {
            content: "";
            position: absolute;
            top: 100%;
            left: 50%;
            margin-left: -5px;
            border-width: 5px;
            border-style: solid;
            border-color: #fff transparent transparent transparent; /* white arrow */
        }

        .st-tooltip-container:hover .st-tooltip-text {
            visibility: visible;
            opacity: 1;
            pointer-events: auto;
        }
    </style>

    <div class="st-cancel-note" style="margin-bottom: 15px; font-weight: bold; color: #2e8b57; display: flex; align-items: center; gap: 6px;">
        <span style="color: #2e8b57;">🕒</span> Free cancellation available
        <div class="st-tooltip-container">
            <span class="st-tooltip-icon">i</span>
            <div class="st-tooltip-text">
Refund if cancelled within 24 hours of making the reservation 
– minus booking and processing fee.
            </div>
        </div>
    </div>';
}

// End cancellation code
?>


            <?php
            $description_tour = get_post(get_the_ID());
if (!empty($description_tour)) {
    $excerpt = get_the_excerpt();
// 1. Remove WPML block at the start
    $excerpt = preg_replace(
        '/^This post is (also )?available in:.*?(\r?\n|<br\s*\/?>|&nbsp;|\s)+/ius',
        '',
        $excerpt
    );
// Remove the exact language list phrase
    $excerpt = str_replace('简体中文 (Chinese (Simplified)) English Deutsch (German)', '', $excerpt);
    // Remove any leading whitespace, including spaces, tabs, newlines, non-breaking spaces, etc.
    $excerpt = preg_replace('/^[\s\x{00A0}\x{200B}\x{FEFF}]+/u', '', $excerpt);
    ?>
    <div class="st-tour--description"><?php echo $excerpt; ?></div>
<?php
}
            ?>   
            <?php
            // Insert review block AFTER title/description, before any "fixed-bottoms" or main features, for all styles (including style_3)
            $fullStars = floor($review_rate);
            $halfStar = ($review_rate - $fullStars) >= 0.5 ? 1 : 0;
            $emptyStars = 5 - $fullStars - $halfStar;
            ?>
            <div class="st-review">
                <?php for ($i = 0; $i < $fullStars; $i++): ?>
                    <i class="stt-icon-star1" style="color:gold;"></i>
                <?php endfor; ?>
                <?php if ($halfStar): ?>
                    <i class="stt-icon-star1" style="color:gold; opacity:0.5;"></i>
                <?php endif; ?>
                <?php for ($i = 0; $i < $emptyStars; $i++): ?>
                    <i class="stt-icon-star1" style="color:#E0E0E0;"></i>
                <?php endfor; ?>
                <span class="rating" style="margin-left:4px;"><?php echo esc_html($review_rate); ?></span>
                <span class="count">
                    (<?php echo esc_html($count_review); ?>
                    <?php echo ($count_review == 1) ? esc_html__('Review', 'traveler') : esc_html__('Reviews', 'traveler'); ?>)
                </span>
            </div>
          
            <div class="fixed-bottoms">
                <div class="st-tour--feature st-tour--tablet">
                    <div class="st-tour__item">
                        <div class="item__icon">
                            <?php echo TravelHelper::getNewIcon('icon-calendar-tour-solo', $main_color , '24px', '24px'); ?>
                        </div>
                        <div class="item__info">
                            <h4 class="info__name"><?php echo esc_html__('Duration', 'traveler'); ?></h4>
                            <p class="info__value">
                                <?php
                                $duration = get_post_meta(get_the_ID(), 'duration_day', true);
                                echo esc_html($duration);
                                ?>
                            </p>
                        </div>
                    </div>
                    <div class="st-tour__item">
                        <div class="item__icon">
                            <?php echo TravelHelper::getNewIcon('icon-service-tour-solo', $main_color , '24px', '24px'); ?>
                        </div>
                        <div class="item__info">
                            <h4 class="info__name"><?php echo esc_html__('Group Size', 'traveler'); ?></h4>
                            <p class="info__value">
                                <?php
                                $max_people = get_post_meta(get_the_ID(), 'max_people', true);
                                if (empty($max_people) or $max_people == 0 or $max_people < 0) {
                                    echo esc_html__('Unlimited', 'traveler');
                                } else {
                                    if ($max_people == 1)
                                        echo sprintf(esc_html__('%s person', 'traveler'), $max_people);
                                    else
                                        echo sprintf(esc_html__('%s people', 'traveler'), $max_people);
                                }
                                ?>
                            </p>
                        </div>
                    </div>
                </div>
            </div>
            <div class="section-footer">
                <div class="st-flex space-between st-price__wrapper">

                    <div class="right">

                        <span class=" price--tour">
                            <?php echo sprintf(esc_html__('%s', 'traveler'), STTour::get_price_html(get_the_ID())); ?>
                        </span>
                    </div>
                    <div class="st-btn--book">
                        <a href="<?php echo esc_attr(get_permalink(get_the_ID())); ?>"><?php echo esc_html__('BOOK NOW', 'traveler'); ?></a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>