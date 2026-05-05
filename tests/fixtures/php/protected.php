<?php
// Fixture: properly protected output

function safe_html_body() {
    $input = $_GET['q'];
    echo "<p>" . htmlspecialchars($input, ENT_QUOTES, 'UTF-8') . "</p>";
}

function safe_html_attribute() {
    $value = $_POST['name'];
    echo "<input value=\"" . htmlspecialchars($value, ENT_QUOTES, 'UTF-8') . "\">";
}

function safe_json_output() {
    $data = $_POST['data'];
    $encoded = json_encode($data);
    echo "<script>var x = " . $encoded . ";</script>";
}

function safe_integer() {
    $page = $_GET['page'];
    echo "<a href='?page=" . intval($page) . "'>Next</a>";
}

function safe_url_param() {
    $search = $_GET['search'];
    echo "<a href='/results?q=" . urlencode($search) . "'>Search</a>";
}

safe_html_body();
safe_html_attribute();
safe_json_output();
safe_integer();
safe_url_param();
