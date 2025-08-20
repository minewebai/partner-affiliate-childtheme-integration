jQuery(document).ready(function($) {
    // Hide unwanted elements
    $('header, footer, .site-footer, #footer, .footer-area, .st_main_menu, .st-breadcrumb, .st-banner-solo')
        .css('display', 'none');

    // Body tweaks
    $('body').css({
        'padding-top': '0',
        'margin-bottom': '0'
    });

    // Move admin partner card to first position
    var $wrapper = $('.partner-listing-wrapper');
    var $adminCard = $wrapper.find('.partner-card.admin-partner').first();

    if ($wrapper.length && $adminCard.length) {
        $adminCard.prependTo($wrapper);
    }
});
