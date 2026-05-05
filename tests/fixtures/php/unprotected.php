<?php
// Fixture: unprotected XSS — direct echo of $_GET without sanitization

function show_search_results() {
    $query = $_GET['q'];
    echo "<h1>Results for: " . $query . "</h1>";
}

function show_user_profile() {
    $name = $_GET['name'];
    echo "<div class='user'>" . $name . "</div>";
}

function show_in_attribute() {
    $value = $_POST['value'];
    echo "<input type='text' value='" . $value . "'>";
}

function show_in_script() {
    $data = $_GET['data'];
    echo "<script>var userInput = '" . $data . "';</script>";
}

show_search_results();
show_user_profile();
show_in_attribute();
show_in_script();
