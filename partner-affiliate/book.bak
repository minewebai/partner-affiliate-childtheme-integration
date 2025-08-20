<?php
// File: theme_root/partner-affiliate/book.php

function pbp_affiliate_book_page($user_data) {
    echo '<div class="affiliate-book-content">';
    echo '<h2>Affiliate Book Section</h2>';
    // Your actual content here
    echo '</div>';
}


if (!defined('ABSPATH')) exit;

$user_id = get_current_user_id();
$is_partner = current_user_can('partner');
$is_affiliate = function_exists('get_field') && get_field('type', 'user_' . $user_id) === 'affiliate';

if (!($is_partner && $is_affiliate)) {
    echo '<p class="st-alert" style="color:#fff;">' . esc_html__('You must be logged in as a partner affiliate to access the booking page.', 'partner-portal') . '</p>';
    return;
}

$tours = PBP_Utils::get_partner_allowed_posts($user_id, 'st_tours');
$activities = PBP_Utils::get_partner_allowed_posts($user_id, 'st_activity');
?>

<div class="affiliate-booking">
    <h2 class="page-title"><?php echo esc_html__('Book Tour or Activity', 'partner-portal'); ?></h2>

    <ul class="pp-tabs">
        <li class="active" data-tab="tours-tab"><?php _e('Tours', 'partner-portal'); ?></li>
        <li data-tab="activities-tab"><?php _e('Activities', 'partner-portal'); ?></li>
    </ul>
<!-- Tours Tab -->
<div id="tours-tab" class="pp-tab-content active">
    <?php if ($tours): ?>
        <table class="pp-booking-table">
            <thead>
                <tr>
                    <th><?php _e('Tour Name', 'partner-portal'); ?></th>
                    <th><?php _e('Location', 'partner-portal'); ?></th>
                    <th><?php _e('Action', 'partner-portal'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($tours as $tour_id): ?>
                    <?php $tour = get_post($tour_id); ?>
                    <tr>
                        <td><?php echo esc_html($tour->post_title); ?></td>
                        <td><?php echo esc_html(get_post_meta($tour_id, 'location', true)); ?></td>
                        <td>
                            <button class="pp-book-btn" data-post-id="<?php echo esc_attr($tour_id); ?>" data-type="tour">
                                <?php _e('Book Now', 'partner-portal'); ?>
                            </button>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php else: ?>
        <p><?php _e('No tours assigned to your account.', 'partner-portal'); ?></p>
    <?php endif; ?>
</div>
<!-- Activities Tab -->
<div id="activities-tab" class="pp-tab-content">
    <?php if ($activities): ?>
        <table class="pp-booking-table">
            <thead>
                <tr>
                    <th><?php _e('Activity Name', 'partner-portal'); ?></th>
                    <th><?php _e('Location', 'partner-portal'); ?></th>
                    <th><?php _e('Action', 'partner-portal'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($activities as $activity_id): ?>
                    <?php $activity = get_post($activity_id); ?>
                    <tr>
                        <td><?php echo esc_html($activity->post_title); ?></td>
                        <td><?php echo esc_html(get_post_meta($activity_id, 'location', true)); ?></td>
                        <td>
                            <button class="pp-book-btn" data-post-id="<?php echo esc_attr($activity_id); ?>" data-type="activity">
                                <?php _e('Book Now', 'partner-portal'); ?>
                            </button>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php else: ?>
        <p><?php _e('No activities assigned to your account.', 'partner-portal'); ?></p>
    <?php endif; ?>
</div>
<!-- Booking Modal -->
<div id="pp-booking-modal" class="pp-modal" style="display:none;">
    <div class="pp-modal-content">
        <span class="pp-close">&times;</span>
        <h3><?php _e('Manual Booking', 'partner-portal'); ?></h3>

        <form id="pp-booking-form">
            <input type="hidden" name="post_id" id="pp-post-id">
            <input type="hidden" name="type" id="pp-post-type">

            <label for="pp-customer-name"><?php _e('Customer Name', 'partner-portal'); ?></label>
            <input type="text" name="customer_name" id="pp-customer-name" required>

            <label for="pp-customer-email"><?php _e('Customer Email', 'partner-portal'); ?></label>
            <input type="email" name="customer_email" id="pp-customer-email" required>

            <label for="pp-booking-date"><?php _e('Booking Date', 'partner-portal'); ?></label>
            <input type="date" name="booking_date" id="pp-booking-date" required>

            <label for="pp-booking-notes"><?php _e('Notes', 'partner-portal'); ?></label>
            <textarea name="notes" id="pp-booking-notes"></textarea>

            <button type="submit" class="pp-submit-btn"><?php _e('Confirm Booking', 'partner-portal'); ?></button>
        </form>

        <div id="pp-booking-response" style="margin-top:10px;"></div>
    </div>
</div>
<script>
document.addEventListener('DOMContentLoaded', function () {
    // Tab switching
    document.querySelectorAll('.pp-tabs li').forEach(tab => {
        tab.addEventListener('click', function () {
            document.querySelectorAll('.pp-tabs li').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.pp-tab-content').forEach(c => c.classList.remove('active'));

            this.classList.add('active');
            document.getElementById(this.dataset.tab).classList.add('active');
        });
    });

    // Modal open
    document.querySelectorAll('.pp-book-btn').forEach(btn => {
        btn.addEventListener('click', function () {
            document.getElementById('pp-post-id').value = this.dataset.postId;
            document.getElementById('pp-post-type').value = this.dataset.type;
            document.getElementById('pp-booking-modal').style.display = 'block';
        });
    });

    // Modal close
    document.querySelector('.pp-close').addEventListener('click', function () {
        document.getElementById('pp-booking-modal').style.display = 'none';
    });

    // AJAX booking form
    document.getElementById('pp-booking-form').addEventListener('submit', function (e) {
        e.preventDefault();

        const formData = new FormData(this);
        formData.append('action', 'pp_ajax_create_manual_booking_autofill');

        fetch('<?php echo admin_url('admin-ajax.php'); ?>', {
            method: 'POST',
            body: formData
        })
        .then(res => res.json())
        .then(data => {
            const responseBox = document.getElementById('pp-booking-response');
            if (data.success) {
                responseBox.innerHTML = '<p style="color:green;">' + data.message + '</p>';
                this.reset();
            } else {
                responseBox.innerHTML = '<p style="color:red;">' + data.message + '</p>';
            }
        })
        .catch(err => {
            document.getElementById('pp-booking-response').innerHTML = '<p style="color:red;">Error submitting booking.</p>';
        });
    });
});
</script>
<?php if (current_user_can('manage_options')) : ?>
    <div style="position: fixed; bottom: 10px; right: 10px; background: #2ecc71; color: white; padding: 6px 10px; z-index: 9999; font-weight: bold;">
        BOOKING PAGE ACTIVE
    </div>
<?php endif; ?>
