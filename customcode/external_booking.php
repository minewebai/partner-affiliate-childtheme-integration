<?php
// ticketinghub_booking.php
// Load WordPress
require_once($_SERVER['DOCUMENT_ROOT'] . '/wp-load.php');  // <-- This line is crucial!

$widget_id = get_field('ticketinghub_widget_id');

if (!empty($widget_id)) {  // Only output if a widget ID is set

    ?>
    <div id="ticketinghub-widget-container"></div> <div id="ticketinghub-widget-container"></div>
    <script src="https://widget.ticketinghub.com/embedding/latest.js"></script>
    <script>
        window.addEventListener('load', function() {
            const container = document.getElementById('ticketinghub-widget-container');
            TicketingHubWidget.render({
                widgetId: '<?php echo esc_js($widget_id); ?>',  // Use esc_js for safety
                container
            });
        });
    </script>
    <?php
}
?>
