<?php
/**
 * Instant booking form for Tours (corrected to support TicketingHub widget embed)
 */

$post_id = get_the_ID();
$ticketinghub_widget_id = get_field('ticketinghub_widget_id', $post_id);
$tour_external = get_post_meta($post_id, 'st_tour_external_booking', true);
$tour_external_link = get_post_meta($post_id, 'st_tour_external_booking_link', true);
$tour_type = get_post_meta($post_id, 'type_tour', true);
?>

<?php if (empty($tour_external) || $tour_external == 'off') : ?>

    <?php echo st()->load_template('layouts/elementor/common/loader'); ?>
    <div class="st-form-booking-action">
        <form id="form-booking-inpage" method="post" action="#booking-request" class="tour-booking-form form-has-guest-name">
            <div class="st-group-form">
                <input type="hidden" name="action" value="tours_add_to_cart">
                <input type="hidden" name="item_id" value="<?php echo esc_attr($post_id); ?>">
                <input type="hidden" name="type_tour" value="<?php echo esc_attr($tour_type); ?>">

                <div class="search-form">
                    <?php echo stt_elementorv2()->loadView('services/tour/single/item/form-book/date'); ?>
                    <?php echo stt_elementorv2()->loadView('services/tour/single/item/form-book/guest'); ?>
                </div>
                <?php echo stt_elementorv2()->loadView('services/tour/single/item/form-book/guest-name'); ?>
            </div>

            <?php echo stt_elementorv2()->loadView('services/tour/single/item/form-book/extra'); ?>

            <div class="total-price-book d-flex justify-content-between align-items-center">
                <div id="total-text">
                    <h5><?php echo esc_html__('Total','traveler');?></h5>
                </div>
                <div id="total-value">
                    <div class="st-price-origin form-head d-flex align-self-end">
                        <h5>
                            <?php
                            echo wp_kses(sprintf('<span class="price d-flex align-content-end flex-column">%s</span>', TravelHelper::format_money(0)), ['span' => ['class' => []]]);
                            ?>
                        </h5>
                    </div>
                </div>
            </div>

            <div class="submit-group">
                <button class="text-center btn-v2 btn-primary btn-book-ajax" type="submit" name="submit">
                    <?php echo esc_html__('Book now', 'traveler'); ?>
                    <i class="fa fa-spinner fa-spin d-none"></i>
                </button>
                <input style="display:none;" type="submit"
                       class="btn btn-default btn-send-message"
                       data-id="<?php echo esc_attr($post_id); ?>"
                       name="st_send_message"
                       value="<?php echo esc_attr__('Send message', 'traveler'); ?>">
            </div>
            <div class="message-wrapper mt30"></div>
            <div class="message-wrapper-2"></div>
        </form>
    </div>

<?php else: ?>

    <?php if (!empty($ticketinghub_widget_id)) : ?>
        <script src="https://assets.ticketinghub.com/checkout.js" data-widget="<?php echo esc_attr($ticketinghub_widget_id); ?>"></script>
    <?php elseif (!empty($tour_external_link)) : ?>
        <div class="submit-group mb30">
            <a href="<?php echo esc_url($tour_external_link); ?>" target="_blank" rel="noopener noreferrer" class="btn btn-green btn-large btn-full upper">
                <?php echo esc_html__('Explore', 'traveler'); ?>
            </a>
        </div>
    <?php endif; ?>

<?php endif; ?>
