<?php
wp_enqueue_script('filter-tour');
while (have_posts()) : the_post();
    $post_id = get_the_ID();
    $address = get_post_meta($post_id, 'address', true);
    $review_rate = STReview::get_avg_rate();
    $count_review = STReview::count_review($post_id);
    $gallery            = get_post_meta($post_id, 'gallery', true);
    $gallery_array      = explode(',', $gallery);
    $tour_external = get_post_meta(get_the_ID(), 'st_tour_external_booking', true);
    $tour_external_link = get_post_meta(get_the_ID(), 'st_tour_external_booking_link', true);
    $booking_type = st_get_booking_option_type();
    $tour_type = get_post_meta(get_the_ID(), 'type_tour', true); ?>
    <div id="st-content-wrapper" class="st-style-4 st-style-elementor st-single-tour st-single-tour-<?php echo esc_attr($style_single); ?>">
        <div class="container st-single-service-content">
            <?php echo stt_elementorv2()->loadView('services/tour/single/item/style-2/top-infor', array(
                'address' => $address,
                'review_rate' => $review_rate,
                'count_review' => $count_review,
            )) ?>
        </div>
        <?php
        echo stt_elementorv2()->loadView('components/banner');
        ?>
        <div class="st-content--info">
            <div class="container st-single-service-content">
                <div class="row">
                    <div class="col-12 col-sm-12 col-md-12 col-lg-8">
                    <?php echo stt_elementorv2()->loadView('services/common/single/gallery-3', array('gallery_array' => $gallery_array, 'gallery' => $gallery , 'post_id' => $post_id)) ?>
                        <div class="st-hotel-content">
                            <div class="hotel-target-book-mobile d-flex justify-content-between align-items-center">
                                <div class="price-wrapper">
                                    <div id="mobile-price">
                                        <?php echo wp_kses(sprintf(__('From:<span class="price">%s</span>', 'traveler'), STTour::get_price_html(get_the_ID())), ['span' => ['class' => []]]) ?>
                                    </div>
                                    <div class="st-review-booking-form">
                                        <div class="st-review-box-top d-flex align-items-center">
                                            <?php
                                            $count_review = get_comment_count($post_id)['approved'];
                                            $avg = STReview::get_avg_rate();
                                            for ($i = 1; $i <= 5; $i++) {
                                                echo '<span class="stt-icon-star1' . ($i <= $avg ? '' : ' empty') . '"></span>';
                                            }
                                            ?>
                                            <div class="review-score">
                                                <?php echo esc_attr($avg); ?>
                                            </div>
                                            <div class="review-score-base text-center">
                                                <span>(<?php comments_number(__('0 review', 'traveler'), __('1 review', 'traveler'), __('% reviews', 'traveler')); ?>)</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <?php
                                if ($tour_external == 'off' || empty($tour_external)) {
                                ?>
                                    <a href="" class="btn-v2 btn-primary btn-mpopup btn-green">
                                        <?php
                                        if ($booking_type == 'enquire') {
                                            echo esc_html__('Inquiry', 'traveler');
                                        } else {
                                            echo esc_html__('Check', 'traveler');
                                        }
                                        ?>
                                    </a>
                                <?php
                                } else {
                                ?>
                                    <a href="" class="btn-v2 btn btn-mpopup"><?php echo esc_html__('Check', 'traveler') ?></a>
                                <?php
                                }
                                ?>
                            </div>
                        </div>
                        <div class="st-description" id="st-description">
                            <?php
                            if (isset($title)) {
                                echo '<h2 class="st-heading-section">' . esc_html($title) . '</h2>';
                            } else { ?>
                                <h2 class="st-heading-section">
                                    <?php
                                    echo __('Overview', 'traveler');
                                    ?>
                                </h2>
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
    <strong>👀 <?php echo esc_html($people_viewing); ?> people are looking at this tour right now</strong>
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








                            <?php }
                            the_content();
                            ?>
                        </div>
                        <?php echo stt_elementorv2()->loadView('services/tour/single/item/infor', array('tour_type' => $tour_type)); ?>
                        <?php echo stt_elementorv2()->loadView('services/tour/single/item/discount'); ?>
                        <?php echo stt_elementorv2()->loadView('services/tour/single/item/style-2/include-exclude') ?>
                        <div class="st-program--wrapper st-program-parent">
                            <?php echo stt_elementorv2()->loadView('services/tour/single/item/style-2/itenirary', ['post_id' => $post_id]) ?>
                        </div>
                        <div class="st-content--hightlight">
                            <?php echo stt_elementorv2()->loadView('services/tour/single/item/style-2/highlights') ?>
                        </div>
                        <?php echo stt_elementorv2()->loadView('services/tour/single/item/style-2/faq', ['post_id' => $post_id]) ?>
                        <div id="st-attributes">
                            <?php echo stt_elementorv2()->loadView('services/tour/single/item/style-2/attributes', ['post_type' => 'st_tours']) ?>
                        </div>
						<?php echo stt_elementorv2()->loadView('services/tour/single/item/review',['post_id' => $post_id]); ?>
                        <div class="stoped-scroll-section"></div>
                    </div>
                    <div class="col-12 col-sm-12 col-md-12 col-lg-4">
                        <div class="widgets sticky-top">
                            <div class="fixed-on-mobile st-fixed-form-booking" data-screen="992px">
                                <div class="close-icon hide">
                                    <?php echo TravelHelper::getNewIcon('Ico_close'); ?>
                                </div>
                                <?php
                                $info_price = STTour::get_info_price();
                                echo stt_elementorv2()->loadView('services/tour/single/item/form-book', [
                                    'info_price' => $info_price,
                                    'tour_external' => $tour_external,
                                    'tour_external_link' => $tour_external_link,
                                    'tour_type' => $tour_type,
                                    'booking_type' => $booking_type,
                                    'review_rate' => $review_rate,
                                ]);
                                ?>
                                <?php
                                $list_badges = get_post_meta(get_the_ID(), 'list_badges', true);
                                if (!empty($list_badges)) {
                                    echo st()->load_template('layouts/modern/common/single/badge', '', array('list_badges' => $list_badges));
                                }
                                ?>
                                <?php echo st()->load_template('layouts/elementor/hotel/single/item/owner-info', '', array('size_avatar_custom' => 90)); ?>

                                <?php echo st()->load_template('layouts/modern/common/single/information-contact'); ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="related">
            <div class="container">
				<?php echo stt_elementorv2()->loadView('services/tour/single/item/style-2/relate', ['post_id' => $post_id]) ?>
            </div>
        </div>
    </div>

<?php endwhile; ?>