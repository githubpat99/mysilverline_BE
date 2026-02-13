<?php
/**
 * Plugin Name: Silverline API
 * Description: Silverline REST API endpoints (whoami, nonce, profile-v2; relational persistence)
 * Version: 0.3.3
 *
 * Namespace: silverline/v1
 *
 * Contract:
 * - GET  /wp-json/silverline/v1/profile-v2  -> { ok:true, profile: ProfileV2 }
 * - POST /wp-json/silverline/v1/profile-v2 -> { ok:true, profile: ProfileV2 } (freshly loaded)
 *
 * New endpoints (relational, no JSON SoT):
 * - GET  /wp-json/silverline/v1/positions
 * - POST /wp-json/silverline/v1/positions/replace
 * - POST /wp-json/silverline/v1/position-targets/set
 * - GET  /wp-json/silverline/v1/profile-events
 * - POST /wp-json/silverline/v1/profile-events/replace
 *
 * Token-Auth (PWA): GET /auth-token für X-SL-Auth-Token Fallback
 */

// ------------------------------
// Routes
// ------------------------------
add_action('rest_api_init', function () {

  register_rest_route('silverline/v1', '/ping', [
    'methods'  => 'GET',
    'callback' => function () { return ['ok' => true, 'ts' => time()]; },
    'permission_callback' => '__return_true',
  ]);

  register_rest_route('silverline/v1', '/whoami', [
    'methods'  => 'GET',
    'callback' => 'sl_whoami',
    'permission_callback' => '__return_true',
  ]);

  register_rest_route('silverline/v1', '/nonce', [
    'methods'  => 'GET',
    'callback' => 'sl_nonce',
    'permission_callback' => '__return_true',
  ]);

  register_rest_route('silverline/v1', '/auth-token', [
    'methods'  => 'GET',
    'callback' => 'sl_auth_token',
    'permission_callback' => 'sl_perm_logged_in_cookie_only',
  ]);

  register_rest_route('silverline/v1', '/logout', [
    'methods'  => 'POST',
    'callback' => 'sl_logout',
    'permission_callback' => 'sl_perm_logged_in_cookie_only',
  ]);

  // ProfileV2 transport
  register_rest_route('silverline/v1', '/profile-v2', [
    'methods'  => 'GET',
    'callback' => 'sl_profile_v2_get',
    'permission_callback' => 'sl_perm_logged_in_cookie_only',
  ]);

  register_rest_route('silverline/v1', '/profile-v2', [
    'methods'  => 'POST',
    'callback' => 'sl_profile_v2_post',
    'permission_callback' => 'sl_perm_logged_in_and_nonce',
  ]);

  // New: Positions
  register_rest_route('silverline/v1', '/positions', [
    'methods'  => 'GET',
    'callback' => 'sl_positions_get',
    'permission_callback' => 'sl_perm_logged_in_cookie_only',
  ]);

  register_rest_route('silverline/v1', '/positions/replace', [
    'methods'  => 'POST',
    'callback' => 'sl_positions_replace_post',
    'permission_callback' => 'sl_perm_logged_in_and_nonce',
  ]);

  // New: Position targets
  register_rest_route('silverline/v1', '/position-targets/set', [
    'methods'  => 'POST',
    'callback' => 'sl_position_targets_set_post',
    'permission_callback' => 'sl_perm_logged_in_and_nonce',
  ]);

  // New: ProfileEvents
  register_rest_route('silverline/v1', '/profile-events', [
    'methods'  => 'GET',
    'callback' => 'sl_profile_events_get',
    'permission_callback' => 'sl_perm_logged_in_cookie_only',
  ]);

  register_rest_route('silverline/v1', '/profile-events/replace', [
    'methods'  => 'POST',
    'callback' => 'sl_profile_events_replace_post',
    'permission_callback' => 'sl_perm_logged_in_and_nonce',
  ]);
});

// CORS: X-SL-Auth-Token für PWA (insbesondere Android) erlauben
add_filter('rest_allowed_cors_headers', function ($headers) {
  $headers[] = 'X-SL-Auth-Token';
  $headers[] = 'X-WP-Nonce';
  return $headers;
}, 10, 1);

// Login-Redirect: Nach Anmeldung direkt in die Finanz-App
add_filter('login_redirect', function ($redirect_to, $requested_redirect_to, $user) {
  if (is_wp_error($user) || !$user) return $redirect_to;
  if (!empty($requested_redirect_to)) return $requested_redirect_to;
  return home_url('/app-static/finance');
}, 10, 3);

// ------------------------------
// Auth helpers (Cookie + Token für PWA)
// ------------------------------

define('SL_AUTH_TOKEN_META_KEY', 'sl_auth_token');
define('SL_AUTH_TOKEN_EXPIRY_META_KEY', 'sl_auth_token_expiry');
define('SL_AUTH_TOKEN_TTL_DAYS', 7);
define('SL_AUTH_TOKEN_HEADER', 'x-sl-auth-token');

function sl_get_token_from_request(WP_REST_Request $req) {
  $h = $req->get_header(SL_AUTH_TOKEN_HEADER);
  if (is_string($h) && trim($h) !== '') return trim($h);
  $auth = $req->get_header('authorization');
  if (is_string($auth) && preg_match('/^Bearer\s+(\S+)$/i', $auth, $m)) return trim($m[1]);
  return null;
}

function sl_validate_auth_token($token) {
  if (empty($token) || !is_string($token)) return 0;
  global $wpdb;
  $meta = $wpdb->get_results($wpdb->prepare(
    "SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value = %s LIMIT 1",
    SL_AUTH_TOKEN_META_KEY,
    $token
  ), ARRAY_A);
  if (empty($meta)) return 0;
  $uid = (int)($meta[0]['user_id'] ?? 0);
  if ($uid <= 0) return 0;
  $expiry = get_user_meta($uid, SL_AUTH_TOKEN_EXPIRY_META_KEY, true);
  if (empty($expiry) || (int)$expiry < time()) return 0;
  return $uid;
}

function sl_ensure_current_user_from_cookie_or_token(WP_REST_Request $req) {
  if (is_user_logged_in()) return;
  $token = sl_get_token_from_request($req);
  if ($token) {
    $uid = sl_validate_auth_token($token);
    if ($uid) {
      wp_set_current_user($uid);
      return;
    }
  }
  if (empty($_COOKIE[LOGGED_IN_COOKIE])) return;
  $cookie  = wp_unslash($_COOKIE[LOGGED_IN_COOKIE]);
  $user_id = wp_validate_auth_cookie($cookie, 'logged_in');
  if ($user_id) wp_set_current_user($user_id);
}

function sl_create_auth_token($user_id) {
  $token = bin2hex(random_bytes(24));
  $expiry = time() + (SL_AUTH_TOKEN_TTL_DAYS * DAY_IN_SECONDS);
  update_user_meta($user_id, SL_AUTH_TOKEN_META_KEY, $token);
  update_user_meta($user_id, SL_AUTH_TOKEN_EXPIRY_META_KEY, $expiry);
  return ['token' => $token, 'expires_at' => $expiry, 'expires_in' => SL_AUTH_TOKEN_TTL_DAYS * DAY_IN_SECONDS];
}

function sl_perm_logged_in_cookie_only(WP_REST_Request $req) {
  if (get_current_user_id() === 0) sl_ensure_current_user_from_cookie_or_token($req);
  return (get_current_user_id() > 0);
}

function sl_perm_logged_in_and_nonce(WP_REST_Request $req) {
  if (!sl_perm_logged_in_cookie_only($req)) return false;
  // Bei Token-Auth: wp_verify_nonce scheitert (keine Cookie-Session).
  $token = sl_get_token_from_request($req);
  if ($token && sl_validate_auth_token($token) > 0) return true;
  // Cookie-Auth: Nonce erforderlich
  $nonce = $req->get_header('x-wp-nonce');
  if (!$nonce) return false;
  return wp_verify_nonce($nonce, 'wp_rest') === 1;
}

/**
 * determine_current_user: Bei gültigem Token User setzen, bevor Cookie-Check läuft.
 * Entfernt rest_cookie_collect_status, damit rest_cookie_check_errors den Nonce-Skip nutzt.
 */
add_filter('determine_current_user', function ($user_id) {
  $token = sl_get_token_from_server();
  if (!$token) return $user_id;
  $uid = sl_validate_auth_token($token);
  if ($uid <= 0) return $user_id;
  remove_action('auth_cookie_valid', 'rest_cookie_collect_status');
  return $uid;
}, 5);

/**
 * Holt Token aus Request-Headern (verschiedene Server-Setups).
 */
function sl_get_token_from_server(): ?string {
  if (function_exists('getallheaders')) {
    $h = getallheaders();
    if (is_array($h)) {
      $h = array_change_key_case($h, CASE_LOWER);
      if (!empty($h['x-sl-auth-token'])) return trim((string) $h['x-sl-auth-token']);
    }
  }
  $keys = ['HTTP_X_SL_AUTH_TOKEN', 'HTTP_X-SL-AUTH-TOKEN'];
  foreach ($keys as $k) {
    if (!empty($_SERVER[$k])) return trim((string) $_SERVER[$k]);
  }
  foreach ($_SERVER as $k => $v) {
    if (stripos($k, 'X_SL_AUTH_TOKEN') !== false || stripos($k, 'X-SL-AUTH-TOKEN') !== false) {
      if (!empty($v)) return trim((string) $v);
    }
  }
  if (!empty($_SERVER['HTTP_AUTHORIZATION']) && preg_match('/^Bearer\s+(\S+)$/i', $_SERVER['HTTP_AUTHORIZATION'], $m)) {
    return trim($m[1]);
  }
  return null;
}

/**
 * Umgeht rest_cookie_invalid_nonce wenn gültiger Token gesendet wird.
 * Priority 25: nach dem Cookie-Check, damit wir den Fehler abfangen können.
 */
add_filter('rest_authentication_errors', function ($result) {
  if (!is_wp_error($result) || $result->get_error_code() !== 'rest_cookie_invalid_nonce') {
    return $result;
  }
  $token = sl_get_token_from_server();
  if (!$token) return $result;
  $uid = sl_validate_auth_token($token);
  if ($uid <= 0) return $result;
  wp_set_current_user($uid);
  return true;
}, 25);

// ------------------------------
// Public handlers
// ------------------------------

function sl_whoami(WP_REST_Request $req) {
  if (get_current_user_id() === 0) sl_ensure_current_user_from_cookie_or_token($req);

  $uid = (int)get_current_user_id();
  if ($uid <= 0) {
    return new WP_REST_Response([
      'logged_in' => false,
      'user_id'   => 0,
      'name'      => null,
      'email'     => null,
      'roles'     => [],
    ], 200);
  }

  $u = wp_get_current_user();
  return new WP_REST_Response([
    'logged_in' => true,
    'user_id'   => (int)$u->ID,
    'name'      => $u->display_name ?: $u->user_login,
    'email'     => $u->user_email,
    'roles'     => array_values((array)$u->roles),
  ], 200);
}

function sl_nonce(WP_REST_Request $req) {
  if (get_current_user_id() === 0) sl_ensure_current_user_from_cookie_or_token($req);
  return new WP_REST_Response([
    'ok'        => true,
    'logged_in' => (get_current_user_id() > 0),
    'user_id'   => (int)get_current_user_id(),
    'nonce'     => wp_create_nonce('wp_rest'),
  ], 200);
}

function sl_auth_token(WP_REST_Request $req) {
  $uid = (int) get_current_user_id();
  if ($uid <= 0) return new WP_REST_Response(['ok' => false, 'error' => 'not_logged_in'], 401);
  $data = sl_create_auth_token($uid);
  return new WP_REST_Response(['ok' => true, 'token' => $data['token'], 'expires_in' => $data['expires_in']], 200);
}

function sl_logout(WP_REST_Request $req) {
  wp_logout();
  return new WP_REST_Response(['ok' => true], 200);
}

// ------------------------------
// ProfileV2 transport (GET/POST)
// ------------------------------

function sl_profile_v2_get(WP_REST_Request $req) {
  global $wpdb;

  $uid  = (int)get_current_user_id();
  $year = (int)gmdate('Y');

  $t_basic = $wpdb->prefix . 'sl_finance_basic';
  $t_pos   = $wpdb->prefix . 'sl_position';

  $has_basic = sl_table_exists($t_basic);
  $has_pos   = sl_table_exists($t_pos);

  $profile = [
    'household'    => ['persons' => []],
    'instruments'  => [],
    'annualsV2'    => ['income' => [], 'expense' => [], 'indexation' => 'inflation'],
    'events'       => [], // now ProfileEvents shape
    'meta'         => [
      'startYear' => $year,
      'forecastHorizonYears' => 55,
    ],
  ];

  if ($has_basic) {
    $cols = $wpdb->get_col("SHOW COLUMNS FROM {$t_basic}", 0);
    $has_horizon_col = is_array($cols) && in_array('forecast_horizon_years', $cols, true);

    if ($has_horizon_col) {
      $row = $wpdb->get_row(
        $wpdb->prepare("SELECT forecast_horizon_years FROM {$t_basic} WHERE user_id=%d LIMIT 1", $uid),
        ARRAY_A
      );
      if ($row && array_key_exists('forecast_horizon_years', $row) && $row['forecast_horizon_years'] !== null) {
        $h = sl_sanitize_horizon_years($row['forecast_horizon_years']);
        if ($h !== null) $profile['meta']['forecastHorizonYears'] = $h;
      }
    }

    $profile['household'] = sl_basic_load_household($uid, $t_basic);
    $profile['annualsV2'] = sl_annuals_v2_load($uid, $t_basic, (int)$profile['meta']['startYear']);
  }

  /*
  if ($has_pos) {
    $profile['instruments'] = sl_positions_load_as_instruments_v3($uid, $t_pos);
    // attach targetIds (IDs-only, relational)
    sl_positions_attach_targets($uid, $profile['instruments']);
  }
*/

  // ProfileEvents (new tables)
  $profile['events'] = sl_profile_events_load($uid);

  return new WP_REST_Response([
    'ok'         => true,
    'profile'    => $profile,
    'updated_at' => current_time('mysql', 1),
  ], 200);
}

function sl_profile_v2_post(WP_REST_Request $req) {
  global $wpdb;

  $uid     = (int)get_current_user_id();
  $body    = json_decode($req->get_body(), true);
  $profile = $body['profile'] ?? null;

  if (!$profile || !is_array($profile)) {
    return new WP_REST_Response(['ok' => false, 'error' => 'invalid_payload'], 400);
  }

  $t_basic   = $wpdb->prefix . 'sl_finance_basic';
  $t_pos     = $wpdb->prefix . 'sl_position';

  $has_basic = sl_table_exists($t_basic);
  $has_pos   = sl_table_exists($t_pos);

  $now = current_time('mysql', 1);

  $meta = is_array($profile['meta'] ?? null) ? $profile['meta'] : [];
  $h = sl_sanitize_horizon_years($meta['forecastHorizonYears'] ?? null);

  $wpdb->query('START TRANSACTION');

  try {
    if ($has_basic) {
      sl_write_basic_from_profile_v2($uid, $profile, $t_basic, $now);
      sl_write_annuals_from_profile_v2($uid, $profile, $t_basic, $now);

      $cols = $wpdb->get_col("SHOW COLUMNS FROM {$t_basic}", 0);
      $has_horizon_col = is_array($cols) && in_array('forecast_horizon_years', $cols, true);
      if ($has_horizon_col) {
        $ok = $wpdb->update(
          $t_basic,
          ['forecast_horizon_years' => $h, 'updated_at' => $now],
          ['user_id' => $uid],
          ['%d','%s'],
          ['%d']
        );
        if ($ok === false) throw new Exception('horizon_update_failed');
      }
    }

/*
    if ($has_pos) {
      // Replace-all: safe for rollout; you can move to per-instrument upsert later.
      sl_positions_replace_from_profile_v2($uid, $profile, $t_pos, $now);
      // Targets replace-all per instrument (IDs only)
      sl_position_targets_replace_from_profile_v2($uid, $profile);
    }
*/

    // ProfileEvents replace-all (IDs only)
    $events = $profile['events'] ?? [];
    sl_profile_events_replace($uid, $events);

    $wpdb->query('COMMIT');
    return sl_profile_v2_get($req);

  } catch (Throwable $e) {
    $wpdb->query('ROLLBACK');
    return new WP_REST_Response(['ok' => false, 'error' => $e->getMessage()], 500);
  }
}

// ------------------------------
// New endpoints: Positions / Targets / ProfileEvents
// ------------------------------

function sl_positions_get(WP_REST_Request $req) {
  global $wpdb;
  $uid  = (int)get_current_user_id();
  $t_pos = $wpdb->prefix . 'sl_position';
  $positions = [];

  if (sl_table_exists($t_pos)) {
    // Ensure Liquidität and Schulden exist (is_system=1) before loading
    sl_ensure_system_positions($uid, $t_pos);
    $positions = sl_positions_load_as_instruments_v3($uid, $t_pos);
    if (!empty($positions)) {
      sl_positions_attach_targets($uid, $positions);
    }
  }

  // Fallback when table missing
  if (empty($positions)) {
    $positions = sl_get_default_system_positions();
  }

  return new WP_REST_Response(['ok'=>true,'positions'=>$positions], 200);
}

function sl_positions_replace_post(WP_REST_Request $req) {

  global $wpdb;
  $uid  = (int)get_current_user_id();
  $t_pos = $wpdb->prefix . 'sl_position';

  if (!sl_table_exists($t_pos)) return new WP_REST_Response(['ok'=>false,'error'=>'table_missing'], 500);

  $body = json_decode($req->get_body(), true);
  $positions = $body['positions'] ?? null;
  if (!is_array($positions)) return new WP_REST_Response(['ok'=>false,'error'=>'invalid_payload'], 400);

  $now = current_time('mysql', 1);

  $wpdb->query('START TRANSACTION');
  try {
    // Ensure system positions exist before replace
    sl_ensure_system_positions($uid, $t_pos);

    // delete user positions, but keep is_system=1 (Liquidität, Schulden)
    if (sl_table_has_column($t_pos, 'is_system')) {
      $del = $wpdb->query($wpdb->prepare(
        "DELETE FROM {$t_pos} WHERE user_id=%d AND (is_system=0 OR is_system IS NULL)",
        (int) $uid
      ));
    } else {
      $del = $wpdb->delete($t_pos, ['user_id' => $uid]);
    }
    if ($del === false) throw new Exception('positions_delete_failed');

    foreach ($positions as $ins) {
      $inst_id = isset($ins['id']) ? trim((string)$ins['id']) : '';
      $is_system_inst = ($inst_id === SL_SYSTEM_INSTRUMENT_LIQUIDITY || $inst_id === SL_SYSTEM_INSTRUMENT_DEBT);
      if ($is_system_inst && sl_table_has_column($t_pos, 'is_system')) {
        sl_position_update_from_payload($uid, $ins, $t_pos, $now);
      } else {
        sl_position_insert_v3($uid, $ins, $t_pos, $now);
      }
    }

    // optional: targets in same call if provided
    sl_position_targets_replace_from_positions_payload($uid, $positions);

    $wpdb->query('COMMIT');

    $out = sl_positions_load_as_instruments_v3($uid, $t_pos);
    sl_positions_attach_targets($uid, $out);
    return new WP_REST_Response(['ok'=>true,'positions'=>$out], 200);

  } catch (Throwable $e) {
    $wpdb->query('ROLLBACK');
    return new WP_REST_Response(['ok'=>false,'error'=>$e->getMessage()], 500);
  }
}

function sl_position_targets_set_post(WP_REST_Request $req) {
  global $wpdb;
  $uid = (int)get_current_user_id();

  $body = json_decode($req->get_body(), true);
  $from = isset($body['fromInstrumentId']) ? trim((string)$body['fromInstrumentId']) : '';
  $targets = $body['targetIds'] ?? null;

  if ($from === '' || !is_array($targets)) {
    return new WP_REST_Response(['ok'=>false,'error'=>'invalid_payload'], 400);
  }

  sl_position_targets_set($uid, $from, $targets);
  return new WP_REST_Response(['ok'=>true], 200);
}

function sl_profile_events_get(WP_REST_Request $req) {
  $uid = (int)get_current_user_id();
  return new WP_REST_Response(['ok'=>true,'events'=>sl_profile_events_load($uid)], 200);
}

function sl_profile_events_replace_post(WP_REST_Request $req) {
  global $wpdb;
  $uid = (int)get_current_user_id();
  $body = json_decode($req->get_body(), true);
  $events = $body['events'] ?? null;
  if (!is_array($events)) return new WP_REST_Response(['ok'=>false,'error'=>'invalid_payload'], 400);

  $wpdb->query('START TRANSACTION');
  try {
    sl_profile_events_replace($uid, $events);
    $wpdb->query('COMMIT');
    return new WP_REST_Response(['ok'=>true,'events'=>sl_profile_events_load($uid)], 200);
  } catch (Throwable $e) {
    $wpdb->query('ROLLBACK');
    return new WP_REST_Response(['ok'=>false,'error'=>$e->getMessage()], 500);
  }
}

// ------------------------------
// Relational: BASIC (household/self)
// ------------------------------

function sl_basic_load_household($uid, $t_basic) {
  global $wpdb;

  $row = $wpdb->get_row($wpdb->prepare(
    "SELECT birth_date, retire_at_age FROM {$t_basic} WHERE user_id=%d LIMIT 1",
    $uid
  ), ARRAY_A);

  if (!$row) {
    return [
      'persons' => [[
        'id' => 'self',
        'role' => 'self',
        'birthDate' => null,
        'retireAtAge' => 65,
      ]],
    ];
  }

  $birthDate = sl_norm_birth_date($row['birth_date'] ?? null);
  $retireAt  = (int)($row['retire_at_age'] ?? 65);

  return [
    'persons' => [[
      'id' => 'self',
      'role' => 'self',
      'birthDate' => $birthDate,
      'retireAtAge' => $retireAt > 0 ? $retireAt : 65,
    ]],
  ];
}

function sl_write_basic_from_profile_v2($user_id, $profile, $t_basic, $now) {
  global $wpdb;

  $p0 = $profile['household']['persons'][0] ?? [];

  $birthDate = sl_norm_birth_date($p0['birthDate'] ?? null);
  $retireAt  = (int)($p0['retireAtAge'] ?? 65);

  $data = [
    'birth_date'    => $birthDate,
    'retire_at_age' => ($retireAt > 0 ? $retireAt : 65),
    'updated_at'    => $now,
  ];

  $updated = $wpdb->update(
    $t_basic,
    $data,
    ['user_id' => (int)$user_id],
    ['%s','%d','%s'],
    ['%d']
  );
  if ($updated === false) throw new Exception('basic_update_failed');

  $exists = (int)$wpdb->get_var($wpdb->prepare(
    "SELECT COUNT(1) FROM {$t_basic} WHERE user_id=%d",
    (int)$user_id
  ));

  if ($exists === 0) {
    $rowIns = array_merge(['user_id' => (int)$user_id], $data);
    $ins = $wpdb->insert($t_basic, $rowIns, ['%d','%s','%d','%s']);
    if ($ins === false) throw new Exception('basic_insert_failed');
  }
}

// ------------------------------
// Relational: ANNUALS V2
// ------------------------------

function sl_annuals_v2_load($uid, $t_basic, $startYear) {
  global $wpdb;

  $row = $wpdb->get_row($wpdb->prepare(
    "SELECT
        annual_income_today,
        annual_income_destination,
        annual_spending_today,
        annual_spending_strategy,
        annual_spending_source_1,
        annual_spending_source_2,
        min_liquidity_chf,
        annuals_indexation
     FROM {$t_basic}
     WHERE user_id=%d
     LIMIT 1",
    (int)$uid
  ), ARRAY_A);

  if (!$row) {
    return [
      'income' => [],
      'expense' => [],
      'indexation' => 'inflation',
    ];
  }

  $idx = 'inflation';
  if (isset($row['annuals_indexation'])) {
    $v = trim((string)$row['annuals_indexation']);
    if (in_array($v, ['inflation','fixed_real','fixed_nominal'], true)) $idx = $v;
  }

  $incomeAmt = isset($row['annual_income_today']) ? (int)$row['annual_income_today'] : 0;
  $needAmt   = isset($row['annual_spending_today']) ? (int)$row['annual_spending_today'] : 0;

  $dest = null;
  if (isset($row['annual_income_destination'])) {
    $v = trim((string)$row['annual_income_destination']);
    if ($v !== '') $dest = $v;
  }

  $strategy = null;
  if (isset($row['annual_spending_strategy'])) {
    $v = trim((string)$row['annual_spending_strategy']);
    if ($v !== '') $strategy = $v;
  }

  $s1 = null;
  if (isset($row['annual_spending_source_1'])) {
    $v = trim((string)$row['annual_spending_source_1']);
    if ($v !== '') $s1 = $v;
  }

  $s2 = null;
  if (isset($row['annual_spending_source_2'])) {
    $v = trim((string)$row['annual_spending_source_2']);
    if ($v !== '') $s2 = $v;
  }

  $minLiq = 0;
  if (array_key_exists('min_liquidity_chf', $row) && $row['min_liquidity_chf'] !== null) {
    $minLiq = (int)$row['min_liquidity_chf'];
    if ($minLiq < 0) $minLiq = 0;
  }

  $income = [];
  if ($incomeAmt > 0 || $dest !== null) {
    $income[] = [
      'id' => 'ai_total',
      'label' => 'Annual Income Total',
      'amountCHF' => (int)$incomeAmt,
      'destination' => $dest,
    ];
  }

  $expense = [];
  $fundingSources = [];
  if ($s1 !== null) $fundingSources[] = ['source' => $s1];
  if ($s2 !== null) $fundingSources[] = ['source' => $s2];

  if ($needAmt > 0 || $strategy !== null || !empty($fundingSources) || $minLiq > 0) {
    $expense[] = [
      'id' => 'ae_total',
      'label' => 'Annual Expense Total',
      'amountCHF' => (int)$needAmt,
      'fundingStrategy' => $strategy,
      'fundingSources' => $fundingSources,
      'minLiquidityCHF' => (int)$minLiq,
    ];
  }

  return [
    'income' => $income,
    'expense' => $expense,
    'indexation' => $idx,
  ];
}

function sl_write_annuals_from_profile_v2($user_id, $profile, $t_basic, $now) {
  global $wpdb;

  $a = $profile['annualsV2'] ?? null;
  if (!is_array($a)) return;

  // ---- indexation (FIX: was missing in your version)
  $hasIdxKey = array_key_exists('indexation', $a);
  $idxToWrite = null;
  if ($hasIdxKey) {
    $v = is_string($a['indexation']) ? trim((string)$a['indexation']) : '';
    if (in_array($v, ['inflation','fixed_real','fixed_nominal'], true)) $idxToWrite = $v;
    else $idxToWrite = 'inflation';
  }

  // ---- Income total + destination
  $incomeToday = null;
  $incomeDest  = null;
  $hasIncomeDestKey = false;

  $incomeArr = $a['income'] ?? null;
  if (is_array($incomeArr) && count($incomeArr) > 0 && is_array($incomeArr[0])) {
    $it = $incomeArr[0];

    if (array_key_exists('amountCHF', $it)) {
      $n = sl_norm_money_int($it['amountCHF']);
      $incomeToday = ($n > 0 ? $n : null);
    }

    if (array_key_exists('destination', $it)) {
      $hasIncomeDestKey = true;
      $v = is_string($it['destination']) ? trim((string)$it['destination']) : '';
      $incomeDest = ($v !== '' ? $v : null);
    }
  }

  // ---- Expense total + funding
  $needToday = null;
  $spStrategy = null;
  $src1 = null;
  $src2 = null;
  $minLiq = null;

  $hasSpStrategyKey = false;
  $hasSpSourcesKey  = false;
  $hasMinLiqKey     = false;

  $expArr = $a['expense'] ?? null;
  if (is_array($expArr) && count($expArr) > 0 && is_array($expArr[0])) {
    $ex = $expArr[0];

    if (array_key_exists('amountCHF', $ex)) {
      $n = sl_norm_money_int($ex['amountCHF']);
      $needToday = ($n > 0 ? $n : null);
    }

    if (array_key_exists('fundingStrategy', $ex)) {
      $hasSpStrategyKey = true;
      $v = is_string($ex['fundingStrategy']) ? trim((string)$ex['fundingStrategy']) : '';
      $spStrategy = ($v !== '' ? $v : null);
    }

    if (array_key_exists('fundingSources', $ex) && is_array($ex['fundingSources'])) {
      $hasSpSourcesKey = true;
      $fs = $ex['fundingSources'];

      $v1 = (is_array($fs[0] ?? null) && array_key_exists('source', $fs[0])) ? trim((string)$fs[0]['source']) : '';
      $v2 = (is_array($fs[1] ?? null) && array_key_exists('source', $fs[1])) ? trim((string)$fs[1]['source']) : '';

      $src1 = ($v1 !== '' ? $v1 : null);
      $src2 = ($v2 !== '' ? $v2 : null);
    }

    if (array_key_exists('minLiquidityCHF', $ex)) {
      $hasMinLiqKey = true;
      $n = sl_norm_money_int($ex['minLiquidityCHF']);
      $minLiq = ($n >= 0 ? $n : 0);
    }
  }

  $data = ['updated_at' => $now];
  $formats = ['%s'];

  $data['annual_income_today']   = $incomeToday;
  $data['annual_spending_today'] = $needToday;
  $formats[] = '%d';
  $formats[] = '%d';

  if ($hasIdxKey) {
    $data['annuals_indexation'] = $idxToWrite;
    $formats[] = '%s';
  }

  if ($hasIncomeDestKey) {
    $data['annual_income_destination'] = $incomeDest;
    $formats[] = '%s';
  }

  if ($hasSpStrategyKey) {
    $data['annual_spending_strategy'] = $spStrategy;
    $formats[] = '%s';
  }

  if ($hasSpSourcesKey) {
    $data['annual_spending_source_1'] = $src1;
    $data['annual_spending_source_2'] = $src2;
    $formats[] = '%s';
    $formats[] = '%s';
  }

  if ($hasMinLiqKey) {
    $data['min_liquidity_chf'] = $minLiq;
    $formats[] = '%d';
  }

  $ok = $wpdb->update(
    $t_basic,
    $data,
    ['user_id' => (int)$user_id],
    $formats,
    ['%d']
  );
  if ($ok === false) throw new Exception('annuals_update_failed');

  $exists = (int)$wpdb->get_var($wpdb->prepare(
    "SELECT COUNT(1) FROM {$t_basic} WHERE user_id=%d",
    (int)$user_id
  ));
  if ($exists === 0) {
    $rowIns = array_merge(['user_id' => (int)$user_id], $data);
    $insFormats = array_merge(['%d'], $formats);
    $ins = $wpdb->insert($t_basic, $rowIns, $insFormats);
    if ($ins === false) throw new Exception('annuals_insert_failed');
  }
}

// ------------------------------
// Relational: POSITIONS (instruments) v3 + targets
// ------------------------------

/**
 * System instrument IDs (cannot be deleted in GUI).
 */
define('SL_SYSTEM_INSTRUMENT_LIQUIDITY', 'liquidity');
define('SL_SYSTEM_INSTRUMENT_DEBT', 'debt');

/**
 * Default system positions when user has none (fallback when table missing).
 * Only Liquidität (active) and Schulden (passive, kurzfristig).
 */
function sl_get_default_system_positions() {
  return [
    [
      'id' => SL_SYSTEM_INSTRUMENT_LIQUIDITY,
      'kind' => 'asset',
      'label' => 'Liquidität',
      'bucket' => 'instant',
      'assetType' => 'other',
      'valueCHF' => 0,
      'annualFlowCHF' => null,
      'goal' => 'liq',
      'note' => null,
      'targetIds' => [],
      'source_account_key' => null,
      'target_account_key' => null,
      'isSystem' => true,
    ],
    [
      'id' => SL_SYSTEM_INSTRUMENT_DEBT,
      'kind' => 'debt',
      'label' => 'Schulden',
      'bucket' => 'short',
      'debtType' => 'other',
      'valueCHF' => 0,
      'annualFlowCHF' => null,
      'note' => null,
      'targetIds' => [],
      'source_account_key' => null,
      'target_account_key' => null,
      'isSystem' => true,
    ],
  ];
}

/**
 * Ensure is_system column exists in sl_position table.
 */
function sl_maybe_add_is_system_column($t_pos) {
  if (sl_table_has_column($t_pos, 'is_system')) return;
  global $wpdb;
  $wpdb->query("ALTER TABLE {$t_pos} ADD COLUMN is_system TINYINT(1) NOT NULL DEFAULT 0");
}

/**
 * Ensure system positions (Liquidität, Schulden) exist for user.
 * Inserts them with is_system=1 if missing.
 */
function sl_ensure_system_positions($uid, $t_pos) {
  global $wpdb;

  if (!sl_table_exists($t_pos)) return;
  sl_maybe_add_is_system_column($t_pos);

  $existing = $wpdb->get_col($wpdb->prepare(
    "SELECT instrument_id FROM {$t_pos} WHERE user_id=%d AND instrument_id IN (%s, %s)",
    (int) $uid,
    SL_SYSTEM_INSTRUMENT_LIQUIDITY,
    SL_SYSTEM_INSTRUMENT_DEBT
  ));
  $has_liquidity = in_array(SL_SYSTEM_INSTRUMENT_LIQUIDITY, (array)$existing, true);
  $has_debt = in_array(SL_SYSTEM_INSTRUMENT_DEBT, (array)$existing, true);

  $now = current_time('mysql', 1);

  if (!$has_liquidity) {
    sl_position_insert_system($uid, [
      'id' => SL_SYSTEM_INSTRUMENT_LIQUIDITY,
      'kind' => 'asset',
      'label' => 'Liquidität',
      'bucket' => 'instant',
      'assetType' => 'other',
      'valueCHF' => 0,
    ], $t_pos, $now);
  }
  if (!$has_debt) {
    sl_position_insert_system($uid, [
      'id' => SL_SYSTEM_INSTRUMENT_DEBT,
      'kind' => 'debt',
      'label' => 'Schulden',
      'bucket' => 'short',
      'debtType' => 'other',
      'valueCHF' => 0,
    ], $t_pos, $now);
  }
}

/**
 * Insert a system position (is_system=1). Used for Liquidität and Schulden.
 */
function sl_position_insert_system($user_id, $ins, $t_pos, $now) {
  sl_position_insert_v3($user_id, $ins, $t_pos, $now, true);
}

/**
 * Update system position (Liquidität/Schulden) from payload. Preserves is_system=1.
 */
function sl_position_update_from_payload($user_id, $ins, $t_pos, $now) {
  global $wpdb;

  if (!is_array($ins)) return;
  $instrument_id = isset($ins['id']) ? trim((string)$ins['id']) : '';
  if ($instrument_id === '' || ($instrument_id !== SL_SYSTEM_INSTRUMENT_LIQUIDITY && $instrument_id !== SL_SYSTEM_INSTRUMENT_DEBT)) {
    return;
  }

  $kind = isset($ins['kind']) ? strtolower(trim((string)$ins['kind'])) : '';
  if ($kind !== 'asset' && $kind !== 'debt') return;

  $label = sanitize_text_field($ins['label'] ?? ($instrument_id === SL_SYSTEM_INSTRUMENT_LIQUIDITY ? 'Liquidität' : 'Schulden'));
  $availability = isset($ins['bucket']) ? trim((string)$ins['bucket']) : (isset($ins['availability']) ? trim((string)$ins['availability']) : null);
  if ($availability === '') $availability = ($kind === 'asset' ? 'instant' : 'short');

  $notes = isset($ins['note']) ? (string)$ins['note'] : (isset($ins['notes']) ? (string)$ins['notes'] : null);
  $notes = ($notes !== null ? sanitize_text_field($notes) : null);
  if ($notes === '') $notes = null;

  $annualFlowCHF = null;
  if (array_key_exists('annualFlowCHF', $ins)) $annualFlowCHF = (int) sl_norm_money_int($ins['annualFlowCHF']);
  else if (array_key_exists('annualFlow', $ins)) $annualFlowCHF = (int) sl_norm_money_int($ins['annualFlow']);

  $amount = 0;
  if ($kind === 'asset') {
    $amount = sl_norm_money_int($ins['valueCHF'] ?? ($ins['value'] ?? 0));
  } else {
    $amount = sl_norm_money_int($ins['valueCHF'] ?? ($ins['balance'] ?? 0));
  }

  $asset_type = ($kind === 'asset') ? sanitize_text_field($ins['assetType'] ?? ($ins['asset_type'] ?? 'other')) : 'other';
  if ($asset_type === '') $asset_type = 'other';
  $debt_type = ($kind === 'debt') ? sanitize_text_field($ins['debtType'] ?? ($ins['debt_type'] ?? 'other')) : 'other';
  if ($debt_type === '') $debt_type = 'other';

  $row = [
    'label' => $label,
    'amount_chf' => (int) $amount,
    'availability' => $availability,
    'cashflow_pa' => ($annualFlowCHF !== null ? (int) $annualFlowCHF : null),
    'notes' => $notes,
    'meta_json' => wp_json_encode(['notes' => ($notes ?? '')], JSON_UNESCAPED_UNICODE),
    'updated_at' => $now,
    'asset_type' => ($kind === 'asset' ? $asset_type : null),
    'debt_type' => ($kind === 'debt' ? $debt_type : null),
    'is_system' => 1,
  ];

  if ($kind === 'debt') {
    $row['interest_rate_pct'] = array_key_exists('interestRatePct', $ins) ? sl_norm_percent($ins['interestRatePct']) : (array_key_exists('interestRate', $ins) ? sl_norm_percent($ins['interestRate']) : null);
    $am = $ins['amortization'] ?? null;
    $row['amortization_type'] = (is_array($am) ? sl_norm_amort_type($am['type'] ?? null) : 'none');
    $row['amortization_pa_chf'] = null;
    if (is_array($am) && array_key_exists('amountAnnualCHF', $am)) {
      $n = sl_norm_money_int($am['amountAnnualCHF']);
      $row['amortization_pa_chf'] = ($n > 0 ? $n : null);
    }
    if (sl_table_has_column($t_pos, 'amortization_source_instrument_id')) {
      $row['amortization_source_instrument_id'] = (is_array($am) && !empty($am['sourceInstrumentId']) ? trim((string)$am['sourceInstrumentId']) : null);
    }
  } else {
    $row['interest_rate_pct'] = null;
    $row['amortization_type'] = 'none';
    $row['amortization_pa_chf'] = null;
    if (sl_table_has_column($t_pos, 'goal')) {
      $g = isset($ins['goal']) ? strtolower(trim((string)$ins['goal'])) : 'liq';
      $row['goal'] = ($g === 'reinvest' ? 'reinvest' : 'liq');
    }
  }

  $exists = (int) $wpdb->get_var($wpdb->prepare(
    "SELECT COUNT(1) FROM {$t_pos} WHERE user_id=%d AND instrument_id=%s",
    (int) $user_id,
    $instrument_id
  ));
  if ($exists === 0) {
    sl_position_insert_system($user_id, $ins, $t_pos, $now);
    return;
  }

  $ok = $wpdb->update($t_pos, $row, [
    'user_id' => (int) $user_id,
    'instrument_id' => $instrument_id,
  ], null, ['%d', '%s']);
  if ($ok === false) throw new Exception('position_update_failed');
}

function sl_positions_replace_from_profile_v2($user_id, $profile, $t_pos, $now) {
  global $wpdb;

  if (sl_table_has_column($t_pos, 'is_system')) {
    $del = $wpdb->query($wpdb->prepare(
      "DELETE FROM {$t_pos} WHERE user_id=%d AND (is_system=0 OR is_system IS NULL)",
      (int) $user_id
    ));
  } else {
    $del = $wpdb->delete($t_pos, ['user_id' => (int)$user_id]);
  }
  if ($del === false) throw new Exception('positions_delete_failed');

  $instruments = $profile['instruments'] ?? [];
  if (!is_array($instruments)) $instruments = [];

  sl_ensure_system_positions($user_id, $t_pos);

  foreach ($instruments as $ins) {
    $inst_id = isset($ins['id']) ? trim((string)$ins['id']) : '';
    $is_system_inst = ($inst_id === SL_SYSTEM_INSTRUMENT_LIQUIDITY || $inst_id === SL_SYSTEM_INSTRUMENT_DEBT);
    if ($is_system_inst && sl_table_has_column($t_pos, 'is_system')) {
      sl_position_update_from_payload($user_id, $ins, $t_pos, $now);
    } else {
      sl_position_insert_v3($user_id, $ins, $t_pos, $now);
    }
  }
} 

function sl_position_insert_v3($user_id, $ins, $t_pos, $now, $is_system = false) {
  global $wpdb;

  if (!is_array($ins)) return;

  $kind = isset($ins['kind']) ? strtolower(trim((string)$ins['kind'])) : '';
  if ($kind !== 'asset' && $kind !== 'debt') return;

  // Stable instrument ID MUST be ins.id
  $instrument_id = isset($ins['id']) ? trim((string)$ins['id']) : '';
  if ($instrument_id === '') return;

  $label = sanitize_text_field($ins['label'] ?? '');
  if ($label === '') $label = ($kind === 'asset' ? 'Asset' : 'Debt');

  $availability = isset($ins['bucket'])
    ? trim((string)$ins['bucket'])
    : (isset($ins['availability']) ? trim((string)$ins['availability']) : '');
  if ($availability === '') $availability = null;

  $notes = isset($ins['note']) ? (string)$ins['note'] : (isset($ins['notes']) ? (string)$ins['notes'] : null);
  $notes = ($notes !== null ? sanitize_text_field($notes) : null);
  if ($notes === '') $notes = null;

  $annualFlowCHF = null;
  if (array_key_exists('annualFlowCHF', $ins)) $annualFlowCHF = (int) sl_norm_money_int($ins['annualFlowCHF']);
  else if (array_key_exists('annualFlow', $ins)) $annualFlowCHF = (int) sl_norm_money_int($ins['annualFlow']);
  else if (array_key_exists('cashflow_pa', $ins)) $annualFlowCHF = (int) sl_norm_money_int($ins['cashflow_pa']);

  // amount_chf: asset.valueCHF / debt.valueCHF or legacy value/balance
  $amount = 0;
  if ($kind === 'asset') {
    $amount = sl_norm_money_int($ins['valueCHF'] ?? ($ins['value'] ?? 0));
  } else {
    $amount = sl_norm_money_int($ins['valueCHF'] ?? ($ins['balance'] ?? 0));
  }

  $asset_type = null;
  $debt_type = null;

  if ($kind === 'asset') {
    $asset_type = sanitize_text_field($ins['assetType'] ?? ($ins['asset_type'] ?? 'other'));
    if ($asset_type === '') $asset_type = 'other';
  } else {
    $debt_type = sanitize_text_field($ins['debtType'] ?? ($ins['debt_type'] ?? 'other'));
    if ($debt_type === '') $debt_type = 'other';
  }

  $interest_rate_pct = null;
  $amortization_type = 'none';
  $amortization_pa_chf = null;
  $amort_source_id = null;

  if ($kind === 'debt') {
    if (array_key_exists('interestRatePct', $ins)) $interest_rate_pct = sl_norm_percent($ins['interestRatePct']);
    else if (array_key_exists('interestRate', $ins)) $interest_rate_pct = sl_norm_percent($ins['interestRate']);

    $am = $ins['amortization'] ?? null;
    if (is_array($am)) {
      $amortization_type = sl_norm_amort_type($am['type'] ?? null);
      if (array_key_exists('amountAnnualCHF', $am)) {
        $n = sl_norm_money_int($am['amountAnnualCHF']);
        $amortization_pa_chf = ($n > 0 ? $n : 0);
      } else if (array_key_exists('amountAnnual', $am)) {
        $n = sl_norm_money_int($am['amountAnnual']);
        $amortization_pa_chf = ($n > 0 ? $n : 0);
      }
      if (array_key_exists('sourceInstrumentId', $am)) {
        $v = trim((string)$am['sourceInstrumentId']);
        $amort_source_id = ($v !== '' ? $v : null);
      }
    }
  }

  // --- NEW: goal (liq | reinvest) for assets
  $goal = null;
  if (array_key_exists('goal', $ins)) {
    $v = strtolower(trim((string)$ins['goal']));
    if ($v === 'liq' || $v === 'reinvest') $goal = $v;
  }
  // Default for assets (robust against old payloads)
  if ($kind === 'asset' && $goal === null) $goal = 'liq';

  // --- NEW: source_account_key / target_account_key (snake + camel support)
  $source_account_key = null;
  $target_account_key = null;

  if (array_key_exists('source_account_key', $ins)) {
    $v = trim((string)$ins['source_account_key']);
    $source_account_key = ($v !== '' ? $v : null);
  } else if (array_key_exists('sourceAccountKey', $ins)) {
    $v = trim((string)$ins['sourceAccountKey']);
    $source_account_key = ($v !== '' ? $v : null);
  }

  if (array_key_exists('target_account_key', $ins)) {
    $v = trim((string)$ins['target_account_key']);
    $target_account_key = ($v !== '' ? $v : null);
  } else if (array_key_exists('targetAccountKey', $ins)) {
    $v = trim((string)$ins['targetAccountKey']);
    $target_account_key = ($v !== '' ? $v : null);
  }

  // Defensiv: source darf nie self sein. target darf self sein bei goal=reinvest.
  if ($source_account_key !== null && $source_account_key === ('asset:' . $instrument_id)) {
    $source_account_key = null;
  }
  if ($goal !== 'reinvest' && $target_account_key !== null && $target_account_key === ('asset:' . $instrument_id)) {
    $target_account_key = null;
  }

  // meta_json: keep minimal
  $meta_json = wp_json_encode(['notes' => ($notes ?? '')], JSON_UNESCAPED_UNICODE);

  $row = [
    'user_id'       => (int) $user_id,
    'instrument_id' => $instrument_id,
    'ui_id'         => $instrument_id, // keep equal for now
    'kind'          => $kind . ':' . ($kind === 'asset' ? $asset_type : $debt_type),
    'label'         => $label,
    'amount_chf'    => (int) $amount,
    'currency'      => 'CHF',
    'availability'  => $availability,
    'cashflow_pa'   => ($annualFlowCHF !== null ? (int) $annualFlowCHF : null),
    'notes'         => $notes,
    'meta_json'     => $meta_json,
    'updated_at'    => $now,
  ];

  if ($kind === 'asset') {
    $row['asset_type'] = $asset_type;
    $row['debt_type']  = null;
    $row['interest_rate_pct'] = null;
    $row['amortization_type'] = 'none';
    $row['amortization_pa_chf'] = null;

    // new:
    if (sl_table_has_column($t_pos, 'amortization_source_instrument_id')) {
      $row['amortization_source_instrument_id'] = null;
    }
    if (sl_table_has_column($t_pos, 'source_account_key')) {
      $row['source_account_key'] = $source_account_key;
    }
    if (sl_table_has_column($t_pos, 'target_account_key')) {
      $row['target_account_key'] = $target_account_key;
    }
    if (sl_table_has_column($t_pos, 'goal')) {
      $row['goal'] = $goal;
    }
    if (sl_table_has_column($t_pos, 'is_system')) {
      $row['is_system'] = $is_system ? 1 : 0;
    }

  } else {
    $row['asset_type'] = null;
    $row['debt_type']  = $debt_type;
    $row['interest_rate_pct'] = $interest_rate_pct;
    $row['amortization_type'] = $amortization_type;
    $row['amortization_pa_chf'] = $amortization_pa_chf;

    if (sl_table_has_column($t_pos, 'amortization_source_instrument_id')) {
      $row['amortization_source_instrument_id'] = $amort_source_id;
    }
    if (sl_table_has_column($t_pos, 'source_account_key')) {
      $row['source_account_key'] = $source_account_key;
    }
    if (sl_table_has_column($t_pos, 'target_account_key')) {
      $row['target_account_key'] = $target_account_key;
    }
    if (sl_table_has_column($t_pos, 'is_system')) {
      $row['is_system'] = $is_system ? 1 : 0;
    }
    // goal is ignored for debts (leave unset)
  }

  $ok = $wpdb->insert($t_pos, $row);
  if ($ok === false) throw new Exception('positions_insert_failed');
}

function sl_positions_load_as_instruments_v3($uid, $t_pos) {
  global $wpdb;

  $has_amort_src = sl_table_has_column($t_pos, 'amortization_source_instrument_id');

  $has_source_key = sl_table_has_column($t_pos, 'source_account_key');
  $has_target_key = sl_table_has_column($t_pos, 'target_account_key');

  // NEW: goal column (assets)
  $has_goal = sl_table_has_column($t_pos, 'goal');

  $has_is_system = sl_table_has_column($t_pos, 'is_system');

  $select = "id, instrument_id, kind, label, amount_chf, availability, cashflow_pa, notes, asset_type, debt_type, interest_rate_pct, amortization_type, amortization_pa_chf";
  if ($has_amort_src)  $select .= ", amortization_source_instrument_id";
  if ($has_source_key) $select .= ", source_account_key";
  if ($has_target_key) $select .= ", target_account_key";
  if ($has_goal)       $select .= ", goal";
  if ($has_is_system)  $select .= ", is_system";

  $rows = $wpdb->get_results($wpdb->prepare(
    "SELECT {$select} FROM {$t_pos} WHERE user_id=%d ORDER BY id ASC",
    (int)$uid
  ), ARRAY_A);

  if (!$rows) return [];

  // error_log("sl_positions_load_as_instruments_v3: " . print_r($rows, true));

  $out = [];

  foreach ($rows as $r) {
    $instrument_id = !empty($r['instrument_id']) ? (string)$r['instrument_id'] : null;
    if (!$instrument_id) continue;

    $parts = explode(':', (string)($r['kind'] ?? ''));
    $dir = $parts[0] ?? 'asset';
    if ($dir !== 'asset' && $dir !== 'debt') $dir = 'asset';

    $bucket = (isset($r['availability']) && $r['availability'] !== '') ? (string)$r['availability'] : null;
    $annualFlow = ($r['cashflow_pa'] !== null && $r['cashflow_pa'] !== '') ? (int)$r['cashflow_pa'] : null;

    // NEW: derive keys from row (only if columns exist)
    $sourceKey = ($has_source_key && isset($r['source_account_key']) && $r['source_account_key'] !== '')
      ? (string)$r['source_account_key']
      : null;

    $targetKey = ($has_target_key && isset($r['target_account_key']) && $r['target_account_key'] !== '')
      ? (string)$r['target_account_key']
      : null;

    // NEW: goal (assets)
    $goal = null;
    if ($has_goal && isset($r['goal']) && $r['goal'] !== '') {
      $g = strtolower(trim((string)$r['goal']));
      if ($g === 'liq' || $g === 'reinvest') $goal = $g;
    }
    if ($dir === 'asset' && $goal === null) $goal = 'liq';

    $isSystem = ($has_is_system && isset($r['is_system']) && (int)$r['is_system'] === 1);

    if ($dir === 'asset') {
      $out[] = [
        'id' => $instrument_id,
        'kind' => 'asset',
        'label' => (string)($r['label'] ?? 'Asset'),
        'bucket' => $bucket,
        'assetType' => (string)($r['asset_type'] ?? 'other'),
        'valueCHF' => (int)($r['amount_chf'] ?? 0),
        'annualFlowCHF' => $annualFlow,

        // NEW
        'goal' => $goal,

        'note' => (!empty($r['notes']) ? (string)$r['notes'] : null),
        'targetIds' => [],
        'source_account_key' => $sourceKey,
        'target_account_key' => $targetKey,
        'isSystem' => $isSystem,
      ];
      continue;
    }

    $inst = [
      'id' => $instrument_id,
      'kind' => 'debt',
      'label' => (string)($r['label'] ?? 'Debt'),
      'bucket' => $bucket,
      'debtType' => (string)($r['debt_type'] ?? 'other'),
      'valueCHF' => (int)($r['amount_chf'] ?? 0),
      'annualFlowCHF' => $annualFlow,
      'note' => (!empty($r['notes']) ? (string)$r['notes'] : null),
      'targetIds' => [],
      'source_account_key' => $sourceKey,
      'target_account_key' => $targetKey,
      'isSystem' => $isSystem,
    ];

    if ($r['interest_rate_pct'] !== null && $r['interest_rate_pct'] !== '') {
      $inst['interestRatePct'] = (float)$r['interest_rate_pct'];
    }

    $t = sl_norm_amort_type($r['amortization_type'] ?? 'none');
    $a = ($r['amortization_pa_chf'] !== null && $r['amortization_pa_chf'] !== '') ? (int)$r['amortization_pa_chf'] : null;

    if ($t !== 'none' || ($a !== null && $a > 0) || ($has_amort_src && !empty($r['amortization_source_instrument_id']))) {
      $am = ['type' => ($t !== 'none' ? $t : 'direct')];
      if ($a !== null && $a > 0) $am['amountAnnualCHF'] = $a;
      if ($has_amort_src && !empty($r['amortization_source_instrument_id'])) {
        $am['sourceInstrumentId'] = (string)$r['amortization_source_instrument_id'];
      }
      $inst['amortization'] = $am;
    }

    $out[] = $inst;
  }

  return $out;
}

function sl_positions_attach_targets($uid, &$positions) {
  global $wpdb;

  $t = $wpdb->prefix . 'sl_position_target';
  if (!sl_table_exists($t)) return;
  if (!is_array($positions) || count($positions) === 0) return;

  $byId = [];
  foreach ($positions as $i => $p) {
    if (is_array($p) && !empty($p['id'])) $byId[(string)$p['id']] = $i;
  }

  $rows = $wpdb->get_results($wpdb->prepare(
    "SELECT from_instrument_id, to_instrument_id FROM {$t} WHERE user_id=%d",
    (int)$uid
  ), ARRAY_A);

  if (!$rows) return;

  foreach ($rows as $r) {
    $from = (string)$r['from_instrument_id'];
    $to   = (string)$r['to_instrument_id'];
    if (!isset($byId[$from])) continue;
    $idx = $byId[$from];
    if (!isset($positions[$idx]['targetIds']) || !is_array($positions[$idx]['targetIds'])) {
      $positions[$idx]['targetIds'] = [];
    }
    $positions[$idx]['targetIds'][] = $to;
  }

  // de-dupe
  foreach ($positions as &$p) {
    if (isset($p['targetIds']) && is_array($p['targetIds'])) {
      $p['targetIds'] = array_values(array_unique(array_filter($p['targetIds'], fn($x)=>is_string($x) && trim($x)!=='')));
    }
  }
}

function sl_position_targets_replace_from_profile_v2($uid, $profile) {
  $positions = $profile['instruments'] ?? [];
  if (!is_array($positions)) $positions = [];
  sl_position_targets_replace_from_positions_payload($uid, $positions);
}

function sl_position_targets_replace_from_positions_payload($uid, $positions) {
  if (!is_array($positions)) return;
  foreach ($positions as $p) {
    if (!is_array($p)) continue;
    $from = isset($p['id']) ? trim((string)$p['id']) : '';
    if ($from === '') continue;
    $targets = $p['targetIds'] ?? null;
    if (is_array($targets)) sl_position_targets_set($uid, $from, $targets);
  }
}

function sl_position_targets_set($uid, $fromInstrumentId, $targetIds) {
  global $wpdb;

  $t = $wpdb->prefix . 'sl_position_target';
  if (!sl_table_exists($t)) return;

  $from = trim((string)$fromInstrumentId);
  if ($from === '') return;

  $targets = array_values(array_unique(array_filter($targetIds, fn($x)=>is_string($x) && trim($x)!=='')));

  $del = $wpdb->query($wpdb->prepare(
    "DELETE FROM {$t} WHERE user_id=%d AND from_instrument_id=%s",
    (int)$uid, $from
  ));
  if ($del === false) throw new Exception('position_targets_delete_failed');

  foreach ($targets as $to) {
    $ok = $wpdb->insert(
      $t,
      [
        'user_id' => (int)$uid,
        'from_instrument_id' => $from,
        'to_instrument_id' => $to,
      ],
      ['%d','%s','%s']
    );
    if ($ok === false) throw new Exception('position_targets_insert_failed');
  }
}

// ------------------------------
// Relational: ProfileEvents (sl_profile_event + sl_profile_event_line)
// ------------------------------

function sl_profile_events_load($uid) {
  global $wpdb;

  $t_e = $wpdb->prefix . 'sl_profile_event';
  $t_l = $wpdb->prefix . 'sl_profile_event_line';

  if (!sl_table_exists($t_e) || !sl_table_exists($t_l)) return [];

  $events = $wpdb->get_results($wpdb->prepare(
    "SELECT event_id, label, start_year, end_year, recurrence, event_type, note
     FROM {$t_e}
     WHERE user_id=%d
     ORDER BY start_year ASC, id ASC",
    (int)$uid
  ), ARRAY_A);

  if (!$events) return [];

  $lines = $wpdb->get_results($wpdb->prepare(
    "SELECT event_id, line_id, amount_chf, from_instrument_id, to_instrument_id, year, note
     FROM {$t_l}
     WHERE user_id=%d
     ORDER BY id ASC",
    (int)$uid
  ), ARRAY_A);

  $byEvent = [];
  foreach ($events as $e) {
    $eid = (string)$e['event_id'];
    $byEvent[$eid] = [
      'id' => $eid,
      'label' => (string)$e['label'],
      'startYear' => (int)$e['start_year'],
      'endYear' => ($e['end_year'] !== null ? (int)$e['end_year'] : null),
      'recurrence' => (string)$e['recurrence'], // once|yearly|monthly (monthly later)
      'eventType' => ($e['event_type'] !== null ? (string)$e['event_type'] : null),
      'note' => ($e['note'] !== null ? (string)$e['note'] : null),
      'lines' => [],
    ];
  }

  foreach (($lines ?: []) as $l) {
    $eid = (string)$l['event_id'];
    if (!isset($byEvent[$eid])) continue;

    $byEvent[$eid]['lines'][] = [
      'id' => (string)$l['line_id'],
      'amountCHF' => (int)$l['amount_chf'],
      'fromInstrumentId' => (!empty($l['from_instrument_id']) ? (string)$l['from_instrument_id'] : null),
      'toInstrumentId' => (!empty($l['to_instrument_id']) ? (string)$l['to_instrument_id'] : null),
      'year' => ($l['year'] !== null ? (int)$l['year'] : null),
      'note' => ($l['note'] !== null ? (string)$l['note'] : null),
    ];
  }

  return array_values($byEvent);
}

function sl_profile_events_replace($uid, $events) {
  global $wpdb;

  $t_e = $wpdb->prefix . 'sl_profile_event';
  $t_l = $wpdb->prefix . 'sl_profile_event_line';

  if (!sl_table_exists($t_e) || !sl_table_exists($t_l)) return;
  if ($events === null) return;
  if (!is_array($events)) return;

  // replace-all per user
  $ok1 = $wpdb->delete($t_l, ['user_id' => (int)$uid], ['%d']);
  if ($ok1 === false) throw new Exception('profile_event_lines_delete_failed');

  $ok2 = $wpdb->delete($t_e, ['user_id' => (int)$uid], ['%d']);
  if ($ok2 === false) throw new Exception('profile_events_delete_failed');

  foreach ($events as $ev) {
    if (!is_array($ev)) continue;

    $event_id = isset($ev['id']) ? trim((string)$ev['id']) : '';
    $label = isset($ev['label']) ? trim((string)$ev['label']) : '';
    $startYear = isset($ev['startYear']) ? (int)$ev['startYear'] : 0;

    if ($event_id === '' || $label === '' || $startYear <= 0) continue;

    $endYear = (array_key_exists('endYear', $ev) && $ev['endYear'] !== null && $ev['endYear'] !== '') ? (int)$ev['endYear'] : null;
    $rec = isset($ev['recurrence']) ? strtolower(trim((string)$ev['recurrence'])) : 'once';
    if (!in_array($rec, ['once','yearly','monthly'], true)) $rec = 'once';

    $eventType = (array_key_exists('eventType', $ev) && $ev['eventType'] !== null) ? trim((string)$ev['eventType']) : null;
    if ($eventType === '') $eventType = null;

    $note = (array_key_exists('note', $ev) && $ev['note'] !== null) ? trim((string)$ev['note']) : null;
    if ($note === '') $note = null;

    $ins = $wpdb->insert(
      $t_e,
      [
        'user_id' => (int)$uid,
        'event_id' => $event_id,
        'label' => $label,
        'start_year' => $startYear,
        'end_year' => $endYear,
        'recurrence' => $rec,
        'event_type' => $eventType,
        'note' => $note,
      ],
      ['%d','%s','%s','%d','%d','%s','%s','%s']
    );
    if ($ins === false) throw new Exception('profile_event_insert_failed');

    $lines = $ev['lines'] ?? [];
    if (!is_array($lines)) $lines = [];

    foreach ($lines as $ln) {
      if (!is_array($ln)) continue;
      $line_id = isset($ln['id']) ? trim((string)$ln['id']) : '';
      $amount = isset($ln['amountCHF']) ? (int)$ln['amountCHF'] : 0;
      if ($line_id === '' || $amount <= 0) continue;

      $from = (array_key_exists('fromInstrumentId', $ln) && $ln['fromInstrumentId'] !== null) ? trim((string)$ln['fromInstrumentId']) : null;
      $to   = (array_key_exists('toInstrumentId', $ln) && $ln['toInstrumentId'] !== null) ? trim((string)$ln['toInstrumentId']) : null;
      if ($from === '') $from = null;
      if ($to === '') $to = null;

      $year = (array_key_exists('year', $ln) && $ln['year'] !== null && $ln['year'] !== '') ? (int)$ln['year'] : null;

      $ln_note = (array_key_exists('note', $ln) && $ln['note'] !== null) ? trim((string)$ln['note']) : null;
      if ($ln_note === '') $ln_note = null;

      $ok = $wpdb->insert(
        $t_l,
        [
          'user_id' => (int)$uid,
          'event_id' => $event_id,
          'line_id' => $line_id,
          'amount_chf' => $amount,
          'currency' => 'CHF',
          'from_instrument_id' => $from,
          'to_instrument_id' => $to,
          'year' => $year,
          'note' => $ln_note,
        ],
        ['%d','%s','%s','%d','%s','%s','%s','%d','%s']
      );
      if ($ok === false) throw new Exception('profile_event_line_insert_failed');
    }
  }
}

// ------------------------------
// Helpers
// ------------------------------

function sl_table_exists($table_name) {
  global $wpdb;
  $like = $wpdb->esc_like($table_name);
  $sql = $wpdb->prepare("SHOW TABLES LIKE %s", $like);
  $found = $wpdb->get_var($sql);
  return !empty($found);
}

function sl_table_has_column($table, $col) {
  global $wpdb;
  $existing = $wpdb->get_col("SHOW COLUMNS FROM {$table}", 0);
  return is_array($existing) && in_array($col, $existing, true);
}

function sl_norm_percent($v) {
  if ($v === null) return null;
  if (is_int($v) || is_float($v)) return (float)$v;
  if (!is_string($v)) return null;
  $s = trim($v);
  if ($s === '') return null;
  $s = str_replace(',', '.', $s);
  if (!is_numeric($s)) return null;
  return (float)$s;
}

function sl_norm_amort_type($v) {
  $s = is_string($v) ? strtolower(trim($v)) : '';
  if (in_array($s, ['none','direct','indirect'], true)) return $s;
  return 'none';
}

function sl_norm_birth_date($v) {
  if (!$v || !is_string($v)) return null;
  if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $v)) return $v;
  return null;
}

function sl_norm_money_int($v) {
  if (is_int($v)) return $v;
  if (is_float($v)) return (int)round($v);
  if (is_numeric($v)) return (int)round((float)$v);
  if (!is_string($v)) return 0;

  $s = str_replace(["'", " ", ","], "", $v);
  $s = preg_replace('/\..*$/', '', $s);
  if ($s === '' || !preg_match('/^-?\d+$/', $s)) return 0;
  return (int)$s;
}

function sl_sanitize_horizon_years($v) {
  if (!isset($v)) return null;
  $n = (int)$v;
  if ($n <= 0) return null;
  if ($n > 120) $n = 120;
  return $n;
}
