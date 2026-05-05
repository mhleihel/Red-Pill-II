<?php
// Fixture: partially protected — htmlspecialchars without ENT_QUOTES in attribute context

function partial_attribute() {
    $value = $_POST['name'];
    // htmlspecialchars without ENT_QUOTES — does NOT protect single-quoted attributes
    echo "<input value='" . htmlspecialchars($value) . "'>";
}

function partial_strip_tags() {
    $comment = $_POST['comment'];
    // strip_tags is NOT sufficient for html_body in all cases
    echo "<div>" . strip_tags($comment) . "</div>";
}

partial_attribute();
partial_strip_tags();
