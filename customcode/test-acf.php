<?php
// Load WordPress
require_once($_SERVER['DOCUMENT_ROOT'] . '/wp-load.php');  // <-- This line is crucial!

$value = get_field('ticketinghub_widget_id', 6562); // Use your actual tour ID
echo $value; 
?>
