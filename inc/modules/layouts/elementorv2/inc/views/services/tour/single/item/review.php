<?php
/**
 * File: review.php
 * Location: inc/modules/layouts/elementorv2/inc/views/services/tour/single/item/review.php
 */
if (comments_open() and st()->get_option('activity_tour_review') == 'on') {
    $count_review = get_comment_count($post_id)['approved'];
?>
    <div class="st-section-single" id="st-reviews">
        <h2 class="st-heading-section">
            <?php echo esc_html__('Reviews', 'traveler') ?>
        </h2>
        <div id="reviews" class="st-reviews">
            <div class="st-review-form">
                <div class="information-review">
                    <div class="review-box">
                        <div class="st-review-box-top">
                            <div class="infor-avg-wrapper d-flex text-center align-items-center align-self-center flex-column">
                                <div class="review-avg d-flex text-center align-items-center">
                                    <?php
                                    $avg = STReview::get_avg_rate();
                                    for ($i = 1; $i <= 5; $i++) {
                                        echo '<span class="stt-icon-star1' . ($i <= $avg ? '' : ' empty') . '"></span>';
                                    }
                                    ?>
                                    <div class="review-score">
                                        <?php echo esc_attr($avg); ?><span class="per-total">/5</span>
                                    </div>
                                </div>
                                <div class="review-score-text"><?php echo TravelHelper::get_rate_review_text($avg, $count_review); ?></div>
                                <div class="review-score-base text-center">
                                    <span>(<?php echo sprintf(_n('%s Review', '%s Reviews', get_comments_number(), 'traveler'), get_comments_number())?>)</span>
                                </div>
                            </div>
                        </div>
                        <div class="st-summany d-flex flex-wrap justify-content-between">
                            <?php
                            $total = get_comments_number();

                            // LIVE calculation for each rating: 5, 4, 3, 2, 1
                            $comments = get_comments([
                                'post_id' => get_the_ID(),
                                'status'  => 'approve',
                            ]);
                            $review_counts = [
                                5 => 0,
                                4 => 0,
                                3 => 0,
                                2 => 0,
                                1 => 0,
                            ];
                            foreach ($comments as $comment) {
                                $rate = get_comment_meta($comment->comment_ID, 'comment_rate', true);
                                if (!$rate) $rate = get_comment_meta($comment->comment_ID, 'rating', true);
                                if (!$rate) $rate = get_comment_meta($comment->comment_ID, 'st_comment_rating', true);
                                $rate = intval($rate);
                                if ($rate >= 1 && $rate <= 5) $review_counts[$rate]++;
                            }
                            ?>
                            <div class="item d-flex align-items-center justify-content-between">
                                <div class="label"><?php echo esc_html__('Excellent', 'traveler') ?></div>
                                <div class="progress">
                                    <div class="percent green" style="width: <?php echo ($total > 0) ? TravelHelper::cal_rate($review_counts[5], $total) : 0; ?>%;"></div>
                                </div>
                                <div class="number text-end"><?php echo esc_html($review_counts[5]); ?></div>
                            </div>
                            <div class="item d-flex align-items-center justify-content-between">
                                <div class="label"><?php echo esc_html__('Very Good', 'traveler') ?></div>
                                <div class="progress">
                                    <div class="percent darkgreen" style="width: <?php echo ($total > 0) ? TravelHelper::cal_rate($review_counts[4], $total) : 0; ?>%;"></div>
                                </div>
                                <div class="number text-end"><?php echo esc_html($review_counts[4]); ?></div>
                            </div>
                            <div class="item d-flex align-items-center justify-content-between">
                                <div class="label"><?php echo esc_html__('Average', 'traveler') ?></div>
                                <div class="progress">
                                    <div class="percent yellow" style="width: <?php echo ($total > 0) ? TravelHelper::cal_rate($review_counts[3], $total) : 0; ?>%;"></div>
                                </div>
                                <div class="number text-end"><?php echo esc_html($review_counts[3]); ?></div>
                            </div>
                            <div class="item d-flex align-items-center justify-content-between">
                                <div class="label"><?php echo esc_html__('Poor', 'traveler') ?></div>
                                <div class="progress">
                                    <div class="percent orange" style="width: <?php echo ($total > 0) ? TravelHelper::cal_rate($review_counts[2], $total) : 0; ?>%;"></div>
                                </div>
                                <div class="number text-end"><?php echo esc_html($review_counts[2]); ?></div>
                            </div>
                            <div class="item d-flex align-items-center justify-content-between">
                                <div class="label"><?php echo esc_html__('Terrible', 'traveler') ?></div>
                                <div class="progress">
                                    <div class="percent red" style="width: <?php echo ($total > 0) ? TravelHelper::cal_rate($review_counts[1], $total) : 0; ?>%;"></div>
                                </div>
                                <div class="number text-end"><?php echo esc_html($review_counts[1]); ?></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="review-pagination">
                <div class="summary text-center">
                    <?php
                    $comments_count = wp_count_comments(get_the_ID());
                    $total = (int)$comments_count->approved;
                    $comment_per_page = (int)get_option('comments_per_page', 10);
                    $paged = (int)STInput::get('comment_page', 1);
                    $from = $comment_per_page * ($paged - 1) + 1;
                    $to = ($paged * $comment_per_page < $total) ? ($paged * $comment_per_page) : $total;
                    ?>
                    <?php
                    echo sprintf(_n('%s review on this Tour', '%s reviews on this Tour', get_comments_number(), 'traveler'), get_comments_number())
                    ?>
                    - <?php echo sprintf(__('Showing %s to %s', 'traveler'), $from, $to) ?>
                </div>
                <div id="reviews" class="review-list">
                    <?php
                    $offset = ($paged - 1) * $comment_per_page;
                    $args = [
                        'number' => $comment_per_page,
                        'offset' => $offset,
                        'post_id' => get_the_ID(),
                        'status' => ['approve']
                    ];
                    $comments_query = new WP_Comment_Query;
                    $comments = $comments_query->query($args);
                    if ($comments):
                        foreach ($comments as $key => $comment):
                            echo stt_elementorv2()->loadView('services/common/single/review-list', ['comment' => (object)$comment, 'post_type' => 'st_tours']);
                        endforeach;
                    endif;
                    ?>
                </div>
            </div>
            <?php TravelHelper::pagination_comment(['total' => $total, 'next_icon' => "stt-icon-arrow-right", 'prev_icon' => "stt-icon-arrow-left"]) ?>
            <?php
            if (comments_open($post_id)) {
            ?>
                <div id="write-review">
                    <h4 class="heading">
                        <a href="#" class="toggle-section c-main f16" data-target="st-review-form"><?php echo __('Write a review', 'traveler') ?>
                            <i class="stt-icon-arrow-down"></i>
                        </a>
                    </h4>
                    <?php
                    TravelHelper::comment_form();
                    ?>
                </div>
            <?php
            }
            ?>
        </div>
    </div>
<?php } ?>