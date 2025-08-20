<?php
// DEBUG MARKER
echo '<div style="background: red; color: white; padding: 10px; text-align: center; font-size: 18px;">
    DEBUG: form-booking-instant.php (ACTIVITIES) is loading!
</div>';

$post_id = get_the_ID();
$ticketinghub_widget_id = isset($ticketinghub_widget_id) ? $ticketinghub_widget_id : get_field('ticketinghub_widget_id', $post_id);
?>

<?php if (!empty($ticketinghub_widget_id)) : ?>

    <!-- Embed the TicketingHub widget -->
    <script src="https://assets.ticketinghub.com/checkout.js" data-widget="<?php echo esc_attr($ticketinghub_widget_id); ?>"></script>

<?php else : ?>

    <?php echo st()->load_template('layouts/elementor/common/loader'); ?>

    <div class="st-form-booking-action">
        <form id="form-booking-inpage" method="post" action="#booking-request" class="tour-booking-form activity-booking-form form-has-guest-name">
            <div class="st-group-form">
                <input type="hidden" name="action" value="activity_add_to_cart">
                <input type="hidden" name="item_id" value="<?php echo esc_attr($post_id); ?>">
                <input type="hidden" name="type_activity" value="<?php echo esc_attr($activity_type); ?>">

                <div class="search-form">
                    <?php echo stt_elementorv2()->loadView('services/activity/single/item/form-book/date'); ?>
                    <?php echo stt_elementorv2()->loadView('services/activity/single/item/form-book/guest'); ?>
                </div>

                <?php echo stt_elementorv2()->loadView('services/activity/single/item/form-book/guest-name'); ?>
            </div>

            <?php
            $enable_pickup = get_post_meta($post_id, 'enable_pickup', true);
            if ($enable_pickup === 'on') :
            ?>
                <div class="form-pickup">
                    <div class="pickup__item">
                        <label for="pickup"><?php echo esc_html__('Pick up', 'traveler'); ?></label>
                        <input type="text" id="pickup" name="pickup">
                    </div>
                </div>
            <?php endif; ?>

            <?php echo stt_elementorv2()->loadView('services/activity/single/item/form-book/extra'); ?>

            <div class="total-price-book d-flex justify-content-between align-items-center">
                <div id="total-text">
                    <h5><?php echo esc_html__('Total', 'traveler'); ?></h5>
                </div>
                <div id="total-value">
                    <div class="st-price-origin form-head d-flex align-self-end">
                        <h5>
                            <?php echo wp_kses(sprintf('<span class="price d-flex align-content-end flex-column">%s</span>', TravelHelper::format_money(0)), ['span' => ['class' => []]]); ?>
                        </h5>
                    </div>
                </div>
            </div>

            <div class="submit-group">
                <button class="text-center btn-v2 btn-primary btn-book-ajax" type="submit" name="submit">
                    <?php echo esc_html__('Book now', 'traveler'); ?><i class="fa fa-spinner fa-spin d-none"></i>
                </button>
                <input style="display:none;" type="submit" class="btn btn-default btn-send-message" data-id="<?php echo esc_attr($post_id); ?>" name="st_send_message" value="<?php echo __('Send message', 'traveler'); ?>">
            </div>

            <div class="message-wrapper mt30"></div>
            <div class="message-wrapper-2"></div>
        </form>
    </div>

<?php endif; ?>
