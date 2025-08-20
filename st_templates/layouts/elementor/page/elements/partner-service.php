<?php
// ===== DEBUG HELPER =====
if (!function_exists('st_debug_echo')) {
    function st_debug_echo($label, $value, $color = '#38bdf8') {
        $out = is_scalar($value) ? (string)$value : print_r($value, true);
        echo '<div style="font:12px/1.4 monospace;background:#111827;color:#e5e7eb;padding:8px 12px;margin:8px 8px 12px;border-left:4px solid '.$color.'">'
           . '<strong style="color:'.$color.'">'.$label.':</strong>'
           . '<pre style="margin:6px 0 0;white-space:pre-wrap;word-break:break-word;">'
           . htmlspecialchars($out, ENT_QUOTES, 'UTF-8')
           . '</pre></div>';
    }
}

// Top-level debug
st_debug_echo('SERVICE TEMPLATE FILE', __FILE__, '#f59e0b');
st_debug_echo('GET["service"] (raw)', isset($_GET['service']) ? $_GET['service'] : '(none)', '#f472b6');

// Ensure $arr_service is an array
$arr_service = isset($arr_service) && is_array($arr_service) ? array_values($arr_service) : array();
st_debug_echo('$arr_service (raw)', $arr_service, '#60a5fa');

// Also show a normalized view (for visibility only)
$__norm = array();
foreach ($arr_service as $__s) {
    $__n = strtolower(trim($__s));
    $__n = preg_replace('/^st_/', '', $__n);
    $__norm[] = $__n;
}
st_debug_echo('$arr_service (normalized view)', $__norm, '#34d399');

// Desired order: TOURS → ACTIVITY → CARS → HOTEL → RENTAL → FLIGHT
$desired_order = array('tours', 'activity', 'cars', 'hotel', 'rental', 'flight');
st_debug_echo('desired_order', $desired_order, '#06b6d4');

// Build ordered list from available services
$services_for_tabs = array_values(array_intersect($desired_order, $arr_service));

// Append any extra/unknown services (preserve original order)
if (count($services_for_tabs) !== count($arr_service)) {
    foreach ($arr_service as $svc) {
        if (!in_array($svc, $services_for_tabs, true)) {
            $services_for_tabs[] = $svc;
        }
    }
}
st_debug_echo('services_for_tabs (ordered)', $services_for_tabs, '#a78bfa');

// Active tab
$active_tab = '';
if (!empty($services_for_tabs)) {
    $requested = STInput::get('service', $services_for_tabs[0]);
    $active_tab = in_array($requested, $services_for_tabs, true) ? $requested : $services_for_tabs[0];
}
st_debug_echo('active_tab (final)', $active_tab, '#22c55e');

// If nothing to show, bail early (prevents fatals)
if (empty($services_for_tabs)) {
    echo '<h5>' . esc_html__('No partner services!', 'traveler') . '</h5>';
    return;
}

// DEBUG: visible bar + file path and order
echo '<div class="st-debug-note" style="padding:8px 12px; background:#fff3cd; border:1px dashed #f0ad4e; color:#8a6d3b; margin:0 0 12px;">'
     . 'Debug: ' . esc_html(basename(__FILE__)) . ' loaded — custom tab order active.'
     . ' Active tab: ' . esc_html($active_tab)
     . ' | Order: ' . esc_html(implode(' → ', $services_for_tabs))
     . '</div>';

// Also log to PHP error_log so we can confirm on the server side
if (function_exists('error_log')) {
    error_log('Partner service template loaded: ' . __FILE__ . ' | Active: ' . $active_tab . ' | Order: ' . implode(',', $services_for_tabs));
}
?>

<?php
// More debug right before the tabs render
st_debug_echo('services_for_tabs (pre-loop)', $services_for_tabs, '#fcd34d');
st_debug_echo('active_tab (pre-loop)', $active_tab, '#fcd34d');
?>

<ul class="nav nav-tabs" id="">
    <?php foreach ($services_for_tabs as $k => $v) :
        // Inline markers for each tab candidate
        echo '<span style="display:inline-block;background:#eef;border:1px solid #99f;color:#33f;padding:2px 6px;margin:2px;font:11px/1 monospace;">candidate=' . esc_html($v) . '</span>';

        $available = STUser_f::_check_service_available_partner('st_' . $v, $current_user_upage->ID);

        // Inline availability result
        echo '<span style="display:inline-block;background:' . ($available ? '#e7f8ed' : '#fde2e1') . ';border:1px solid ' . ($available ? '#34d399' : '#f87171') . ';color:' . ($available ? '#065f46' : '#7f1d1d') . ';padding:2px 6px;margin:2px;font:11px/1 monospace;">available=' . ($available ? 'yes' : 'no') . '</span>';

        if ( $available ) {
            $get = $_GET;
            $get['service'] = $v;
            unset($get['pages']);
            $author_link = esc_url(get_author_posts_url($current_user_upage->ID));
            $url = esc_url(add_query_arg($get, $author_link));
            ?>
            <li class="<?php echo ($active_tab === $v) ? 'active' : ''; ?>">
                <a href="<?php echo esc_url($url); ?>" aria-expanded="true">
                    <?php
                    switch ($v) {
                        case 'hotel':
                            echo __('Hotels', 'traveler');
                            break;
                        case 'tours':
                            echo __('Tours', 'traveler');
                            break;
                        case 'activity':
                            echo __('Activity', 'traveler');
                            break;
                        case 'cars':
                            echo __('Car', 'traveler');
                            break;
                        case 'rental':
                            echo __('Rental', 'traveler');
                            break;
                        case 'flight':
                            echo __('Flight', 'traveler');
                            break;
                        default:
                            echo esc_html(ucfirst($v));
                            break;
                    }
                    ?>
                </a>
            </li>
        <?php } endforeach; ?>
</ul>

<div class="tab-content">
    <div class="tab-pane fade active in author-sv-list" id="tab-all">
        <?php
        // Use the active_tab as the service to query
        $service = $active_tab;
        st_debug_echo('SERVICE USED FOR QUERY', $service, '#eab308');

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
            $args['meta_key'] = 'is_featured';
            $args['orderby']  = 'meta_value';
            $args['order']    = 'DESC';
        } elseif ($service === 'tours' && $is_featured_tour === 'on') {
            $args['meta_key'] = 'is_featured';
            $args['orderby']  = 'meta_value';
            $args['order']    = 'DESC';
        } elseif ($service === 'activity' && $is_featured_activity === 'on') {
            $args['meta_key'] = 'is_featured';
            $args['orderby']  = 'meta_value';
            $args['order']    = 'DESC';
        } elseif ($service === 'cars' && $is_featured_car === 'on') {
            $args['meta_key'] = 'is_featured';
            $args['orderby']  = 'meta_value';
            $args['order']    = 'DESC';
        } elseif ($service === 'rental' && $is_featured_rental === 'on') {
            $args['meta_key'] = 'is_featured';
            $args['orderby']  = 'meta_value';
            $args['order']    = 'DESC';
        }

        st_debug_echo('WP_Query args', $args, '#a78bfa');

        $query = new WP_Query($args);

        if ($query->have_posts()) {
            switch ($service) {
                case 'hotel':
                    echo '<div class="search-result-page"><div class="st-results st-hotel-result"><div class="row service-list-wrapper">';
                    break;
                case 'tours':
                    echo '<div class="search-result-page st-tours"><div class="st-results st-hotel-result"><div class="row service-list-wrapper">';
                    break;
                case 'activity':
                    echo '<div class="search-result-page st-tours st-activity"><div class="st-results st-hotel-result"><div class="row service-list-wrapper">';
                    break;
                case 'cars':
                    echo '<div class="search-result-page st-tours"><div class="st-results st-hotel-result"><div class="row service-list-wrapper">';
                    break;
                case 'rental':
                    echo '<div class="search-result-page st-rental "><div class="st-results st-hotel-result"><div class="row service-list-wrapper">';
                    break;
                // case 'flight':
                //     echo '<ul class="booking-list loop-rental style_list">';
                //     break;
            }

            while ($query->have_posts()) {
                $query->the_post();
                switch ($service) {
                    case 'hotel':
                        echo st()->load_template('layouts/elementor/hotel/loop/normal', 'grid', array('item_row' => 3));
                        break;
                    case 'tours':
                        echo st()->load_template('layouts/elementor/tour/loop/normal', 'grid', array('item_row' => 3));
                        break;
                    case 'activity':
                        echo st()->load_template('layouts/elementor/activity/loop/normal', 'grid', array('item_row' => 3));
                        break;
                    case 'cars':
                        echo st()->load_template('layouts/elementor/car/loop/normal', 'grid', array('item_row' => 3));
                        break;
                    case 'rental':
                        echo st()->load_template('layouts/elementor/rental/loop/normal', 'grid');
                        break;
                    case 'flight':
                        echo st()->load_template('user/loop/loop', 'flight-upage');
                        break;
                }
            }
            echo '</div></div></div>';
        } else {
            echo '<h5>' . esc_html__('No data', 'traveler') . '</h5>';
        }
        wp_reset_postdata();
        ?>
        <br/>
        <div class="pull-left author-pag">
            <?php st_paging_nav(null, $query); ?>
        </div>
    </div>
</div>

<div class="st-review-new">
    <h5><?php echo __('Review', 'traveler'); ?></h5>
    <?php
    // Keep the review panel in the same order
    echo st()->load_template('layouts/elementor/page/elements/partner', 'review', array(
        'current_user_upage'   => $current_user_upage,
        'arr_service'          => $services_for_tabs,
        'post_per_page_review' => 5
    ));
    ?>
</div>