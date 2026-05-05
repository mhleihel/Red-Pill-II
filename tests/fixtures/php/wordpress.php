<?php
// Fixture: WordPress sanitization functions

function render_wp_title() {
    $title = $_GET['title'];
    echo '<h1>' . esc_html($title) . '</h1>';
}

function render_wp_attribute() {
    $value = $_POST['value'];
    echo '<input value="' . esc_attr($value) . '">';
}

function render_wp_url() {
    $url = $_GET['url'];
    echo '<a href="' . esc_url($url) . '">Link</a>';
}

function render_unprotected_wp() {
    $data = $_GET['data'];
    // Direct echo — unprotected
    echo $data;
}

render_wp_title();
render_wp_attribute();
render_wp_url();
render_unprotected_wp();
