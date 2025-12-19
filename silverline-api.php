<?php
/**
 * Plugin Name: Silverline API
 * Version: 0.3.0
 * Description: Persistiert Silverline Workflow-Daten (Steps 1-6) für eingeloggte User.
 */

if (!defined('ABSPATH')) exit;

/**
 * Fallback: Wenn REST Cookie-Auth ohne Nonce/Hardening nicht greift,
 * validieren wir das WP Login-Cookie direkt und setzen den aktuellen User.
 */
function sl_resolve_user_id_from_logged_in_cookie(): int {
  if (!defined('LOGGED_IN_COOKIE')) return 0;
  $cookie = $_COOKIE[ LOGGED_IN_COOKIE ] ?? '';
  if (!$cookie) return 0;

  $user_id = wp_validate_auth_cookie($cookie, 'logged_in');
  return $user_id ? (int)$user_id : 0;
}

function sl_ensure_current_user_from_cookie(): int {
  $user_id = sl_resolve_user_id_from_logged_in_cookie();
  if ($user_id > 0) wp_set_current_user($user_id);
  return $user_id;
}

function sl_check_rest_nonce(WP_REST_Request $req): bool {
  $nonce = $req->get_header('X-WP-Nonce');
  return (bool)($nonce && wp_verify_nonce($nonce, 'wp_rest'));
}

/**
 * "Eingeloggt" für unsere API = entweder WP kennt den User bereits,
 * oder wir können ihn über das logged_in Cookie auflösen.
 */
function sl_is_logged_in_api(): bool {
  if (is_user_logged_in()) return true;
  return sl_resolve_user_id_from_logged_in_cookie() > 0;
}

add_action('rest_api_init', function () {

  // ---------- WHOAMI (ohne Nonce; nutzt Cookie-Fallback) ----------
  register_rest_route('silverline/v1', '/whoami', [
    'methods'  => 'GET',
    'callback' => 'sl_whoami',
    'permission_callback' => '__return_true', // kein 401, sondern logged_in false
  ]);

  // ---------- NONCE (Bridge: ohne Nonce, aber nur wenn logged_in Cookie gültig) ----------
  register_rest_route('silverline/v1', '/nonce', [
    'methods'  => 'GET',
    'callback' => function () {
      // Falls REST Auth den User schon kennt, ok. Sonst Cookie-Fallback.
      if (!is_user_logged_in()) sl_ensure_current_user_from_cookie();

      if (!is_user_logged_in()) {
        return new WP_REST_Response([
          'ok' => false,
          'logged_in' => false,
          'user_id' => 0,
        ], 200);
      }

      return new WP_REST_Response([
        'ok' => true,
        'logged_in' => true,
        'user_id' => (int)get_current_user_id(),
        'nonce' => wp_create_nonce('wp_rest'),
      ], 200);
    },
    'permission_callback' => '__return_true', // wichtig: kein Nonce/kein is_user_logged_in hier
  ]);

  // ---------- ME (mit Nonce; nutzt Cookie-Fallback + Nonce) ----------
  register_rest_route('silverline/v1', '/me', [
    'methods'  => 'GET',
    'callback' => function () {
      if (!is_user_logged_in()) sl_ensure_current_user_from_cookie();

      $u = wp_get_current_user();
      return new WP_REST_Response([
        'logged_in' => is_user_logged_in(),
        'user_id'   => (int)get_current_user_id(),
        'roles'     => $u ? array_values((array)$u->roles) : [],
        'email'     => $u ? $u->user_email : null,
        'name'      => $u ? ($u->display_name ?: $u->user_login) : null,
      ], 200);
    },
    'permission_callback' => function (WP_REST_Request $req) {
      if (!sl_is_logged_in_api()) return false;
      return sl_check_rest_nonce($req);
    },
  ]);

  // ---------- LOGOUT (mit Nonce; nutzt Cookie-Fallback + Nonce) ----------
  register_rest_route('silverline/v1', '/logout', [
    'methods'  => 'POST',
    'callback' => function () {
      // Wenn REST Auth nicht gesetzt ist, setzen wir ihn kurz via Cookie,
      // damit wp_logout sauber auf den aktuellen User wirkt.
      if (!is_user_logged_in()) sl_ensure_current_user_from_cookie();

      wp_logout();
      wp_clear_auth_cookie();
      return new WP_REST_Response(['ok' => true], 200);
    },
    'permission_callback' => function (WP_REST_Request $req) {
      if (!sl_is_logged_in_api()) return false;
      return sl_check_rest_nonce($req);
    },
  ]);

  // ---------- PROFILE (GET/POST: eingeloggter User + Nonce) ----------
  register_rest_route('silverline/v1', '/profile', [
    'methods'  => 'GET',
    'callback' => 'sl_get_profile',
    'permission_callback' => function (WP_REST_Request $req) {
      if (!sl_is_logged_in_api()) return false;
      return sl_check_rest_nonce($req);
    },
  ]);

  register_rest_route('silverline/v1', '/profile', [
    'methods'  => 'POST',
    'callback' => 'sl_save_profile',
    'permission_callback' => function (WP_REST_Request $req) {
      if (!sl_is_logged_in_api()) return false;
      return sl_check_rest_nonce($req);
    },
  ]);

});


// ---------- Shortcode: App starten + Nonce in localStorage ----------
add_shortcode('silverline_bootstrap', function($atts) {
  $atts = shortcode_atts(['to' => '/app-static/finance/'], $atts);

  if (!is_user_logged_in()) return '<p>Bitte zuerst einloggen.</p>';

  // Hinweis: Dieser Nonce kann "alt" werden. Besser ist in der App beim Start /nonce zu holen.
  $nonce = wp_create_nonce('wp_rest');
  $to = esc_url($atts['to']);

  return '
    <button id="sl-go-app" style="padding:10px 14px;border-radius:8px;">
      Zur Silverline App
    </button>
    <script>
      document.getElementById("sl-go-app").addEventListener("click", function () {
        localStorage.setItem("sl_wp_nonce", ' . json_encode($nonce) . ');
        window.location.href = ' . json_encode($to) . ';
      });
    </script>
  ';
});


// ---------- Core callbacks ----------
function sl_whoami(WP_REST_Request $req) {
  // REST kann "ausgeloggt" wirken; wir versuchen Cookie-Fallback
  if (!is_user_logged_in()) sl_ensure_current_user_from_cookie();

  if (!is_user_logged_in()) {
    return new WP_REST_Response([
      'logged_in' => false,
      'user_id' => 0,
      'name' => null,
      'email' => null,
      'roles' => [],
    ], 200);
  }

  $u = wp_get_current_user();

  return new WP_REST_Response([
    'logged_in' => true,
    'user_id' => (int) $u->ID,
    'name' => $u->display_name ?: $u->user_login,
    'email' => $u->user_email,
    'roles' => array_values((array) $u->roles),
  ], 200);
}

function sl_table() {
  // Achtung: KEIN wp_ prefix bei dir, daher ohne $wpdb->prefix
  return 'sl_finance_profile';
}

/**
 * "1’234.50", "1'234.50", "1 234,50", "1234" -> float|null
 */
function sl_parse_chf($v) {
  if ($v === null) return null;
  $s = trim((string)$v);
  if ($s === '') return null;

  $s = str_replace(["\xC2\xA0", " ", "’", "'"], "", $s);

  if (strpos($s, ',') !== false && strpos($s, '.') === false) {
    $s = str_replace(',', '.', $s);
  } else {
    $s = str_replace(',', '', $s);
  }

  return is_numeric($s) ? (float)$s : null;
}

function sl_num_or_zero($v) {
  $n = sl_parse_chf($v);
  return ($n === null) ? 0.0 : $n;
}

function sl_get_profile(WP_REST_Request $req) {
  // Sicherstellen, dass current_user_id stimmt (auch wenn REST Auth nicht greift)
  if (!is_user_logged_in()) sl_ensure_current_user_from_cookie();

  global $wpdb;
  $user_id = get_current_user_id();
  $table = sl_table();

  $row = $wpdb->get_row(
    $wpdb->prepare("SELECT * FROM {$table} WHERE user_id = %d LIMIT 1", $user_id),
    ARRAY_A
  );

  if (!$row) {
    return new WP_REST_Response([
      'ok' => true,
      'schemaVersion' => 2,
      'form' => null,
      'completed_step' => 0
    ], 200);
  }

  $form = [
    'step1' => [
      'cash' => (string)($row['cash_chf'] ?? ''),
      'bankSavings' => (string)($row['bank_savings_chf'] ?? ''),
      'securities' => (string)($row['securities_chf'] ?? ''),
      'otherInvest' => (string)($row['other_invest_chf'] ?? ''),
    ],
    'step2' => [
      'creditCard' => (string)($row['credit_card_chf'] ?? ''),
      'consumerLoan' => (string)($row['consumer_loan_chf'] ?? ''),
      'otherShort' => (string)($row['other_short_chf'] ?? ''),
      'mortgage' => (string)($row['mortgage_chf'] ?? ''),
      'loan' => (string)($row['loan_chf'] ?? ''),
      'otherLong' => (string)($row['other_long_chf'] ?? ''),
    ],
    'step3' => [
      'futureIncome' => (string)($row['future_income_chf'] ?? ''),
      'futureExpense' => (string)($row['future_expense_chf'] ?? ''),
      'notes' => (string)($row['notes'] ?? ''),
    ],
    'step4' => [
      'goal' => (string)($row['investment_goal'] ?? ''),
      'risk' => $row['risk_tolerance'] !== null ? intval($row['risk_tolerance']) : null,
      'horizonYears' => $row['time_horizon_years'] !== null ? intval($row['time_horizon_years']) : null,
    ],
    'step5' => [
      'preferred' => ($row['preferred_assets_csv'] ?? '') !== '' ? explode(',', $row['preferred_assets_csv']) : [],
      'avoided' => ($row['avoided_assets_csv'] ?? '') !== '' ? explode(',', $row['avoided_assets_csv']) : [],
    ],
    'step6' => [
      'minLiquidity' => (string)($row['min_liquidity_chf'] ?? ''),
      'monthlySaving' => (string)($row['monthly_saving_chf'] ?? ''),
    ],
  ];

  return new WP_REST_Response([
    'ok' => true,
    'schemaVersion' => 2,
    'form' => $form,
    'completed_step' => intval($row['completed_step'] ?? 0),
  ], 200);
}

function sl_save_profile(WP_REST_Request $req) {
  // Sicherstellen, dass current_user_id stimmt (auch wenn REST Auth nicht greift)
  if (!is_user_logged_in()) sl_ensure_current_user_from_cookie();

  global $wpdb;
  $user_id = get_current_user_id();
  $table = sl_table();

  $body = $req->get_json_params();
  if (!is_array($body)) $body = [];

  $s1 = (isset($body['step1']) && is_array($body['step1'])) ? $body['step1'] : [];
  $s2 = (isset($body['step2']) && is_array($body['step2'])) ? $body['step2'] : [];
  $s3 = (isset($body['step3']) && is_array($body['step3'])) ? $body['step3'] : [];
  $s4 = (isset($body['step4']) && is_array($body['step4'])) ? $body['step4'] : [];
  $s5 = (isset($body['step5']) && is_array($body['step5'])) ? $body['step5'] : [];
  $s6 = (isset($body['step6']) && is_array($body['step6'])) ? $body['step6'] : [];

  $preferred = (isset($s5['preferred']) && is_array($s5['preferred'])) ? $s5['preferred'] : [];
  $avoided   = (isset($s5['avoided']) && is_array($s5['avoided'])) ? $s5['avoided'] : [];

  $completed_step = isset($body['completed_step']) ? intval($body['completed_step']) : 0;
  if ($completed_step < 0) $completed_step = 0;
  if ($completed_step > 6) $completed_step = 6;

  // Ensure row exists
  $wpdb->query($wpdb->prepare("INSERT IGNORE INTO {$table} (user_id) VALUES (%d)", $user_id));

  $data = [
    'cash_chf'          => sl_num_or_zero($s1['cash'] ?? ''),
    'bank_savings_chf'  => sl_num_or_zero($s1['bankSavings'] ?? ''),
    'securities_chf'    => sl_num_or_zero($s1['securities'] ?? ''),
    'other_invest_chf'  => sl_num_or_zero($s1['otherInvest'] ?? ''),

    'credit_card_chf'   => sl_num_or_zero($s2['creditCard'] ?? ''),
    'consumer_loan_chf' => sl_num_or_zero($s2['consumerLoan'] ?? ''),
    'other_short_chf'   => sl_num_or_zero($s2['otherShort'] ?? ''),
    'mortgage_chf'      => sl_num_or_zero($s2['mortgage'] ?? ''),
    'loan_chf'          => sl_num_or_zero($s2['loan'] ?? ''),
    'other_long_chf'    => sl_num_or_zero($s2['otherLong'] ?? ''),

    'future_income_chf'  => sl_num_or_zero($s3['futureIncome'] ?? ''),
    'future_expense_chf' => sl_num_or_zero($s3['futureExpense'] ?? ''),
    'notes'              => isset($s3['notes']) ? sanitize_textarea_field($s3['notes']) : '',

    'investment_goal'    => isset($s4['goal']) ? sanitize_text_field($s4['goal']) : '',
    'risk_tolerance'     => array_key_exists('risk', $s4) && $s4['risk'] !== null ? intval($s4['risk']) : null,
    'time_horizon_years' => array_key_exists('horizonYears', $s4) && $s4['horizonYears'] !== null ? intval($s4['horizonYears']) : null,

    'preferred_assets_csv' => sanitize_text_field(implode(',', array_map('strval', $preferred))),
    'avoided_assets_csv'   => sanitize_text_field(implode(',', array_map('strval', $avoided))),

    'min_liquidity_chf'  => sl_num_or_zero($s6['minLiquidity'] ?? ''),
    'monthly_saving_chf' => sl_num_or_zero($s6['monthlySaving'] ?? ''),
  ];

  $formats = [
    '%f','%f','%f','%f',
    '%f','%f','%f','%f','%f','%f',
    '%f','%f','%s',
    '%s','%d','%d',
    '%s','%s',
    '%f','%f',
  ];

  $updated = $wpdb->update($table, $data, ['user_id' => $user_id], $formats, ['%d']);
  if ($updated === false) {
    return new WP_REST_Response(['ok' => false, 'error' => 'db_write_failed'], 500);
  }

  $wpdb->query($wpdb->prepare(
    "UPDATE {$table} SET completed_step = GREATEST(completed_step, %d) WHERE user_id = %d",
    $completed_step,
    $user_id
  ));

  return new WP_REST_Response(['ok' => true], 200);
}
