<?php
// ticketinghub_booking.php

// Load WordPress (Essential for ACF's get_field())
require_once($_SERVER['DOCUMENT_ROOT'] . '/wp-load.php');

// Get the current Tour ID
global $post; // Use the global $post object
$tour_id = $post->ID;



$widget_id = get_field('ticketinghub_widget_id', $tour_id); // Now with $tour_id!

if (!empty($widget_id)) {
    ?>
    <div id="ticketinghub-widget-container"></div>
    <script src="https://widget.ticketinghub.com/embedding/latest.js"></script>
    <script>
        window.addEventListener('load', function() {
            const container = document.getElementById('ticketinghub-widget-container');
            TicketingHubWidget.render({
                widgetId: '<?php echo esc_js($widget_id); ?>', 
                container
            });
        });
    </script>
    <?php
}  // else: do nothing or display an alternate message if no widget ID is found
?>
