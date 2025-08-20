<div class="owner-info d-none d-sm-block widget-box st-border-radius">
    <h4 class="heading"><?php echo __('Owner', 'traveler') ?></h4>
    <div class="media d-flex align-items-center">
        <div class="media-left">
            <?php
            $author_id = get_post_field('post_author', get_the_ID());
            $userdata = get_userdata($author_id);
            $size_avatar = !empty($size_avatar_custom) ? $size_avatar_custom : 60;
            ?>
            <a href="<?php echo esc_url(get_author_posts_url($author_id)); ?>">
                <?php echo st_get_profile_avatar($author_id, $size_avatar); ?>
            </a>
        </div>
        <div class="media-body">
            <h4 class="media-heading">
                <a href="<?php echo esc_url(get_author_posts_url($author_id)); ?>" class="author-link">
                    <?php echo esc_html(get_the_author_meta('display_name', $author_id)); ?>
                </a>
            </h4>
            <p><?php echo sprintf(__('Member Since %s', 'traveler'), !empty($userdata->user_registered) ? date('Y', strtotime($userdata->user_registered)) : '') ?></p>
        </div>
    </div>
    <div class="question-author">
        <?php if (st()->get_option('enable_inbox') === 'on') { ?>
            <div class="st_ask_question text-center">
                <?php if (!is_user_logged_in()) { ?>
                    <a href="" class="login btn btn-primary" data-bs-toggle="modal" data-bs-target="#st-login-form"><?php echo __('Ask a Question', 'traveler'); ?></a>
                <?php } else { ?>
                    <a href="" id="btn-send-message-owner" class="btn-send-message-owner btn btn-primary" data-id="<?php echo get_the_ID(); ?>"><?php echo __('Ask a Question', 'traveler'); ?></a>
                <?php } ?>
            </div>
        <?php } ?>
    </div>
</div>
