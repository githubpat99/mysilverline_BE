<?php
/**
 * Plugin Name: Silverline Auth 
 */

if (!defined('ABSPATH')) exit;

// HIER kommt der Cookie- / CORS-Code rein
add_filter('wp_session_expiration', function () {
  return 60 * 60 * 24 * 14; // 14 Tage
});


// Ende Cookie / CORS