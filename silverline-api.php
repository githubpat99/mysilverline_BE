<?php
/**
 * Plugin Name: Silverline API
 * Description: Silverline REST API endpoints (whoami, nonce, profile-v2)
 * Version: 0.2.1
 *
 * Silverline API (ProfileV2 transport-only JSON; relational persistence)
 * Namespace: silverline/v1
 *
 * Contract:
 * - GET  /wp-json/silverline/v1/profile-v2  -> { ok:true, profile: ProfileV2 }
 * - POST /wp-json/silverline/v1/profile-v2  -> { ok:true, profile: ProfileV2 } (freshly loaded, incl. DB ids)
 *
 * Persistence (relational SoT):
 * - wp_XXXX_sl_finance_basic  (optional; stores basic household/self data if exists)
 * - wp_XXXX_sl_position       (optional; stores instruments if exists)
 * - wp_XXXX_sl_event          (optional; stores events header if exists)
 * - wp_XXXX_sl_event_line     (optional; stores 1 line per event if exists)
 *
 * Notes:
 * - This file does NOT persist JSON blobs as source of truth.
 * - Parts of ProfileV2 that do not have relational tables yet will be returned with defaults (empty arrays/objects).
 *
 * IMPORTANT (Indexation):
 * - annuals.indexation is persisted ONLY in sl_finance_basic.annuals_indexation
 * - NO meta_load / meta annualsIndexation mapping anymore.
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

  // Public: cookie-only identity check
  register_rest_route('silverline/v1', '/whoami', [
    'methods'  => 'GET',
    'callback' => 'sl_whoami',
    'permission_callback' => '__return_true',
  ]);

  // Public: fetch nonce
  register_rest_route('silverline/v1', '/nonce', [
    'methods'  => 'GET',
    'callback' => 'sl_nonce',
    'permission_callback' => '__return_true',
  ]);

  // ProfileV2 (transport contract)
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

  // Logout (optional)
  register_rest_route('silverline/v1', '/logout', [
    'methods'  => 'POST',
    'callback' => 'sl_logout',
    'permission_callback' => 'sl_perm_logged_in_cookie_only',
  ]);
});

// ------------------------------
// Auth helpers
// ------------------------------

function sl_ensure_current_user_from_cookie() {
  // In REST context WP sometimes has user_id=0 even with valid cookies.
  // Force-validate logged_in cookie.
  if (is_user_logged_in()) return;

  if (empty($_COOKIE[LOGGED_IN_COOKIE])) return;

  $cookie  = wp_unslash($_COOKIE[LOGGED_IN_COOKIE]);
  $user_id = wp_validate_auth_cookie($cookie, 'logged_in');
  if ($user_id) {
    wp_set_current_user($user_id);
  }
}

function sl_perm_logged_in_cookie_only(WP_REST_Request $req) {
  if (get_current_user_id() === 0) sl_ensure_current_user_from_cookie();
  return (get_current_user_id() > 0);
}

function sl_perm_logged_in_and_nonce(WP_REST_Request $req) {
  if (!sl_perm_logged_in_cookie_only($req)) return false;

  $nonce = $req->get_header('x-wp-nonce');
  if (!$nonce) return false;

  return wp_verify_nonce($nonce, 'wp_rest') === 1;
}

// ------------------------------
// Handlers
// ------------------------------

function sl_whoami(WP_REST_Request $req) {
  if (get_current_user_id() === 0) sl_ensure_current_user_from_cookie();

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
  if (get_current_user_id() === 0) sl_ensure_current_user_from_cookie();

  $logged_in = (get_current_user_id() > 0);
  return new WP_REST_Response([
    'ok'        => true,
    'logged_in' => $logged_in,
    'user_id'   => (int)get_current_user_id(),
    'nonce'     => wp_create_nonce('wp_rest'),
  ], 200);
}

function sl_logout(WP_REST_Request $req) {
  wp_logout();
  return new WP_REST_Response(['ok' => true], 200);
}

/**
 * GET /profile-v2
 * Assembles ProfileV2 from relational tables.
 */
function sl_profile_v2_get(WP_REST_Request $req) {
  global $wpdb;

  $uid  = (int)get_current_user_id();
  $year = (int)gmdate('Y');

  // Tables (optional)
  $t_basic = $wpdb->prefix . 'sl_finance_basic';
  $t_pos   = $wpdb->prefix . 'sl_position';
  $t_event = $wpdb->prefix . 'sl_event';
  $t_line  = $wpdb->prefix . 'sl_event_line';

  $has_basic = sl_table_exists($t_basic);
  $has_pos   = sl_table_exists($t_pos);
  $has_evt   = sl_table_exists($t_event) && sl_table_exists($t_line);

  // Defaults (contract stability)
  $profile = [
    'household'    => ['persons' => []],
    'instruments'  => [],
    'annuals'      => ['income' => [], 'need' => []], // indexation is optional
    'events'       => [],
    'meta'         => [
      'startYear' => $year,
      // default only; if DB has value -> overwritten below
      'forecastHorizonYears' => 55,
    ],
  ];

  if ($has_basic) {
    // --- load horizon from DB (if column exists)
    // If your table might not yet have the column in all envs, guard it:
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

    // annuals includes optional indexation, sourced from sl_finance_basic.annuals_indexation
    $profile['annuals'] = sl_annuals_load($uid, $t_basic, (int)$profile['meta']['startYear']);
  }

  if ($has_pos) {
    $profile['instruments'] = sl_positions_load_as_instruments($uid, $t_pos);
  }

  if ($has_evt) {
    $profile['events'] = sl_events_load($uid);
  }

  return new WP_REST_Response([
    'ok'         => true,
    'profile'    => $profile,
    'updated_at' => current_time('mysql', 1),
  ], 200);
}

/**
 * POST /profile-v2
 * Body: { "profile": { ...ProfileV2... } }
 *
 * Persists relationally (SoT):
 * - basic household/self -> sl_finance_basic (if exists)
 * - annuals (income/need + indexation) -> sl_finance_basic (if exists)
 * - instruments -> sl_position (if exists)
 * - events -> sl_event + sl_event_line (if exists)
 *
 * Returns freshly assembled profile from DB (ensures DB ids for events).
 */
function sl_profile_v2_post(WP_REST_Request $req) {
  global $wpdb;

  $uid     = (int)get_current_user_id();
  $body    = json_decode($req->get_body(), true);
  $profile = $body['profile'] ?? null;

  if (!$profile || !is_array($profile)) {
    return new WP_REST_Response(['ok' => false, 'error' => 'invalid_payload'], 400);
  }

  // Tables (optional)
  $t_basic = $wpdb->prefix . 'sl_finance_basic';
  $t_pos   = $wpdb->prefix . 'sl_position';
  $t_event = $wpdb->prefix . 'sl_event';
  $t_line  = $wpdb->prefix . 'sl_event_line';

  $has_basic = sl_table_exists($t_basic);
  $has_pos   = sl_table_exists($t_pos);
  $has_evt   = sl_table_exists($t_event) && sl_table_exists($t_line);

  $now = current_time('mysql', 1);

  // --- sanitize meta horizon (NO business rule like min=10; only safety)
  $meta = is_array($profile['meta'] ?? null) ? $profile['meta'] : [];
  $h = sl_sanitize_horizon_years($meta['forecastHorizonYears'] ?? null);

  $wpdb->query('START TRANSACTION');

  try {
    if ($has_basic) {
      // Write basic + annuals
      sl_write_basic_from_profile_v2($uid, $profile, $t_basic, $now);
      sl_write_annuals_from_profile_v2($uid, $profile, $t_basic, $now);

      // Persist horizon if column exists (and keep it optional for older DBs)
      $cols = $wpdb->get_col("SHOW COLUMNS FROM {$t_basic}", 0);
      $has_horizon_col = is_array($cols) && in_array('forecast_horizon_years', $cols, true);

      if ($has_horizon_col) {
        // store NULL if not set; otherwise store sanitized int
        $wpdb->update(
          $t_basic,
          ['forecast_horizon_years' => $h],
          ['user_id' => $uid],
          ['%d'],
          ['%d']
        );
      }
    }

    if ($has_pos) {
      sl_write_positions_from_profile_v2($uid, $profile, $t_pos, $now);
    }

    if ($has_evt) {
      $events = $profile['events'] ?? [];
      sl_events_save($uid, $events); // MUST NOT start/commit its own transaction
    }

    $wpdb->query('COMMIT');

    // return freshly loaded profile (ensures ids)
    return sl_profile_v2_get($req);

  } catch (Throwable $e) {
    $wpdb->query('ROLLBACK');
    return new WP_REST_Response(['ok' => false, 'error' => $e->getMessage()], 500);
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

  // Return at least "self" person if nothing exists (contract stability)
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

/**
 * Expects ProfileV2 snippet:
 * profile.household.persons[0].birthDate (YYYY-MM-DD) OPTIONAL
 * profile.household.persons[0].retireAtAge            OPTIONAL
 */
function sl_write_basic_from_profile_v2($user_id, $profile, $t_basic, $now) {
  global $wpdb;

  $p0 = $profile['household']['persons'][0] ?? [];

  $birthDate = sl_norm_birth_date($p0['birthDate'] ?? null); // do NOT invent
  $retireAt  = (int)($p0['retireAtAge'] ?? 65);

  $row = [
    'user_id'       => (int)$user_id,
    'birth_date'    => $birthDate, // NULL if not provided
    'retire_at_age' => ($retireAt > 0 ? $retireAt : 65),
    'updated_at'    => $now,
  ];

  $updated = $wpdb->update($t_basic, $row, ['user_id' => (int)$user_id]);
  if ($updated === false) throw new Exception('basic_update_failed');

  if ($updated === 0) {
    $ins = $wpdb->insert($t_basic, $row);
    if ($ins === false) throw new Exception('basic_insert_failed');
  }
}

// ------------------------------
// Relational: ANNUALS (income/need/indexation)
// ------------------------------
/**
 * ProfileV2 transport:
 * profile.annuals = {
 *   indexation?: "inflation"|"fixed_real"|"fixed_nominal",
 *   income: AnnualItem[],
 *   need: AnnualItem[]
 * }
 *
 * DB:
 * - sl_finance_basic.annual_income_today (BIGINT)
 * - sl_finance_basic.annual_spending_today (BIGINT)
 * - sl_finance_basic.annuals_indexation (VARCHAR/ENUM)
 */
function sl_annuals_load($uid, $t_basic, $startYear) {
  global $wpdb;

  $row = $wpdb->get_row($wpdb->prepare(
    "SELECT annual_income_today, annual_spending_today, annuals_indexation
     FROM {$t_basic} WHERE user_id=%d LIMIT 1",
    (int)$uid
  ), ARRAY_A);

  // Always return indexation (default)
  $idx = 'inflation';

  if (!$row) {
    return ['income' => [], 'need' => [], 'indexation' => $idx];
  }

  $incomeToday = isset($row['annual_income_today']) ? (int)$row['annual_income_today'] : 0;
  $needToday   = isset($row['annual_spending_today']) ? (int)$row['annual_spending_today'] : 0;

  if (isset($row['annuals_indexation'])) {
    $v = trim((string)$row['annuals_indexation']);
    if (in_array($v, ['inflation','fixed_real','fixed_nominal'], true)) $idx = $v;
  }

  $income = [];
  $need = [];

  if ($incomeToday > 0) {
    $income[] = [
      'id' => 'ui:annual:income_today',
      'label' => 'Jahreseinkommen heute (UI)',
      'amount' => (int)$incomeToday,
      'startYear' => (int)$startYear,
    ];
  }

  if ($needToday > 0) {
    $need[] = [
      'id' => 'ui:annual:need_today',
      'label' => 'Jahresbedarf heute (UI)',
      'amount' => (int)$needToday,
      'startYear' => (int)$startYear,
    ];
  }

  return ['income' => $income, 'need' => $need, 'indexation' => $idx];
}

/**
 * Expects ProfileV2 snippet:
 * profile.annuals.income[] (look for id="ui:annual:income_today")
 * profile.annuals.need[]   (look for id="ui:annual:need_today")
 * profile.annuals.indexation (optional)
 */

function sl_write_annuals_from_profile_v2($user_id, $profile, $t_basic, $now) {
  global $wpdb;

  $annuals = $profile['annuals'] ?? null;
  if (!is_array($annuals)) return;

  $incomeItems = $annuals['income'] ?? [];
  $needItems   = $annuals['need'] ?? [];

  $incomeToday = 0;
  foreach ($incomeItems as $it) {
    if (!is_array($it)) continue;
    if (($it['id'] ?? '') === 'ui:annual:income_today') {
      $incomeToday = sl_norm_money_int($it['amount'] ?? 0);
      break;
    }
  }

  $needToday = 0;
  foreach ($needItems as $it) {
    if (!is_array($it)) continue;
    if (($it['id'] ?? '') === 'ui:annual:need_today') {
      $needToday = sl_norm_money_int($it['amount'] ?? 0);
      break;
    }
  }

  // Indexation comes from annuals.indexation and is persisted to sl_finance_basic.annuals_indexation
  // IMPORTANT: Only write it if the client actually sent the key.
  $idxToWrite = null;
  $hasIdxKey = array_key_exists('indexation', $annuals);

  if ($hasIdxKey) {
    $idxToWrite = is_string($annuals['indexation']) ? trim((string)$annuals['indexation']) : '';
    if ($idxToWrite === '') $idxToWrite = null;
    if ($idxToWrite !== null && !in_array($idxToWrite, ['inflation','fixed_real','fixed_nominal'], true)) {
      $idxToWrite = null;
    }
  }

  // Build update row (only provided columns get updated)
  $row = [
    'annual_income_today'     => ($incomeToday > 0 ? (int)$incomeToday : null),
    'annual_spending_today'   => ($needToday > 0 ? (int)$needToday : null),
    'updated_at'              => $now,
  ];

  if ($hasIdxKey) {
    $row['annuals_indexation'] = $idxToWrite; // may be NULL (explicit clear)
  }

  $ok = $wpdb->update($t_basic, $row, ['user_id' => (int)$user_id]);
  if ($ok === false) throw new Exception('annuals_update_failed');

  // update can be 0 although row exists (no change) -> do NOT insert blindly.
  // Insert only if row does not exist.
  $exists = (int)$wpdb->get_var($wpdb->prepare(
    "SELECT COUNT(1) FROM {$t_basic} WHERE user_id=%d",
    (int)$user_id
  ));

  if ($exists === 0) {
    $rowIns = array_merge(['user_id' => (int)$user_id], $row);
    $ins = $wpdb->insert($t_basic, $rowIns);
    if ($ins === false) throw new Exception('annuals_insert_failed');
  }
}

// ------------------------------
// Relational: POSITIONS (instruments)
// ------------------------------

/**
 * Writes instruments -> sl_position (replace strategy).
 *
 * Expects instruments like:
 * - asset: { id, kind:"asset", assetType, label, value }
 * - debt:  { id, kind:"debt",  debtType,  label, balance }
 */
function sl_write_positions_from_profile_v2($user_id, $profile, $t_pos, $now) {
  global $wpdb;

  // Replace strategy (stable during buildout)
  $del = $wpdb->delete($t_pos, ['user_id' => (int)$user_id]);
  if ($del === false) throw new Exception('positions_delete_failed');

  $instruments = $profile['instruments'] ?? [];
  if (!is_array($instruments)) $instruments = [];

  foreach ($instruments as $ins) {
    if (!is_array($ins)) continue;

    $dir = sanitize_text_field($ins['kind'] ?? ''); // "asset" | "debt"
    if ($dir === '') continue;

    // Map type
    $assetType = '';
    $amount = 0;
    if ($dir === 'asset') {
      $assetType = sanitize_text_field($ins['assetType'] ?? '');
      $amount    = sl_norm_money_int($ins['value'] ?? 0);
    } else {
      $assetType = sanitize_text_field($ins['debtType'] ?? '');
      $amount    = sl_norm_money_int($ins['balance'] ?? 0);
    }

    $kind  = $dir . ':' . ($assetType !== '' ? $assetType : 'other');
    $label = sanitize_text_field($ins['label'] ?? '');

    $is_liquid = 0;
    if ($dir === 'asset' && in_array($assetType, ['cash', 'bank'], true)) $is_liquid = 1;

    $meta = [
      'instrument_id' => $ins['id'] ?? null,
      'dir'           => $dir,
      'assetType'     => ($assetType !== '' ? $assetType : null),
    ];
    $meta_json = wp_json_encode($meta, JSON_UNESCAPED_UNICODE);

    $row = [
      'user_id'    => (int)$user_id,
      'kind'       => $kind,
      'label'      => ($label !== '' ? $label : null),
      'amount_chf' => (int)$amount,
      'currency'   => 'CHF',
      'is_liquid'  => (int)$is_liquid,
      'meta_json'  => $meta_json,
      'updated_at' => $now,
    ];

    $ok = $wpdb->insert($t_pos, $row);
    if ($ok === false) throw new Exception('positions_insert_failed');
  }
}

/**
 * Loads sl_position rows and maps back to ProfileV2.instruments[]
 * Uses meta_json where possible; falls back to splitting "kind" like "asset:cash".
 */
function sl_positions_load_as_instruments($uid, $t_pos) {
  global $wpdb;

  $rows = $wpdb->get_results($wpdb->prepare(
    "SELECT kind, label, amount_chf, meta_json FROM {$t_pos} WHERE user_id=%d ORDER BY id ASC",
    $uid
  ), ARRAY_A);

  if (!$rows) return [];

  $out = [];
  foreach ($rows as $r) {
    $meta = $r['meta_json'] ? json_decode($r['meta_json'], true) : [];
    $dir = $meta['dir'] ?? null;               // "asset" | "debt"
    $type = $meta['assetType'] ?? null;        // cash/bank/... or other
    $instrument_id = $meta['instrument_id'] ?? null;

    if (!$dir || !$type) {
      $parts = explode(':', (string)($r['kind'] ?? ''));
      $dir  = $dir ?: ($parts[0] ?? 'asset');
      $type = $type ?: ($parts[1] ?? 'other');
    }

    $id = $instrument_id ?: ('pos:' . $dir . ':' . ($type ?: 'other'));
    $label = $r['label'] ?: null;
    $amt = intval($r['amount_chf'] ?? 0);

    if ($dir === 'asset') {
      $out[] = [
        'id' => $id,
        'kind' => 'asset',
        'assetType' => $type ?: 'other',
        'label' => $label ?: 'Asset',
        'value' => $amt,
      ];
    } else {
      $out[] = [
        'id' => $id,
        'kind' => 'debt',
        'debtType' => $type ?: 'other',
        'label' => $label ?: 'Debt',
        'balance' => $amt,
      ];
    }
  }

  return $out;
}

// ------------------------------
// Relational: EVENTS (sl_event + sl_event_line)
// ------------------------------

function sl_events_load($uid) {
  global $wpdb;

  $t_event = $wpdb->prefix . 'sl_event';
  $t_line  = $wpdb->prefix . 'sl_event_line';

  $sql = "
    SELECT
      e.id,
      e.client_id,
      e.title,
      e.start_date,
      e.end_date,
      e.recurrence,
      e.active,
      e.meta_json,
      l.id AS line_id,
      l.line_type,
      l.amount_chf,
      l.indexation,
      l.category,
      l.meta_json AS line_meta_json
    FROM {$t_event} e
    JOIN {$t_line} l
      ON l.event_id = e.id AND l.user_id = e.user_id
    WHERE e.user_id = %d
    ORDER BY e.start_date ASC, e.id ASC
  ";

  $rows = $wpdb->get_results($wpdb->prepare($sql, $uid), ARRAY_A);
  if (!$rows) return [];

  $out = [];
  foreach ($rows as $r) {
    $out[] = [
      'id' => intval($r['id']),
      'client_id' => $r['client_id'] ? (string)$r['client_id'] : null,
      'title' => $r['title'],
      'start_date' => $r['start_date'],
      'end_date' => $r['end_date'] ? $r['end_date'] : null,
      'recurrence' => $r['recurrence'],
      'active' => intval($r['active']) ? 1 : 0,
      'meta_json' => $r['meta_json'] ? json_decode($r['meta_json'], true) : null,
      'line' => [
        'id' => intval($r['line_id']),
        'line_type' => $r['line_type'],
        'amount_chf' => intval($r['amount_chf']),
        'indexation' => $r['indexation'] ? $r['indexation'] : null,
        'category' => $r['category'] ? $r['category'] : null,
        'meta_json' => $r['line_meta_json'] ? json_decode($r['line_meta_json'], true) : null,
      ],
    ];
  }

  return $out;
}

/**
 * Saves events from ProfileV2.events[] into sl_event/sl_event_line.
 * Source-of-truth: payload list (upsert + delete missing).
 *
 * IMPORTANT:
 * - NO internal START/COMMIT/ROLLBACK here. The caller controls the transaction.
 */
function sl_events_save($uid, $events) {

  if ($events === null) return;        // <- kein "delete all" bei null
  if (!is_array($events)) return;      // <- nur arbeiten, wenn wirklich Array

  global $wpdb;

  $t_event = $wpdb->prefix . 'sl_event';
  $t_line  = $wpdb->prefix . 'sl_event_line';

  if (!is_array($events)) $events = [];

  // --- Existing in DB (both keys) ---
  $existing = $wpdb->get_results($wpdb->prepare(
    "SELECT id, client_id FROM {$t_event} WHERE user_id=%d",
    $uid
  ), ARRAY_A);

  $existing_ids = [];
  $existing_client_ids = [];
  foreach (($existing ?: []) as $row) {
    $existing_ids[] = intval($row['id']);
    if (!empty($row['client_id'])) $existing_client_ids[] = (string)$row['client_id'];
  }

  // --- Payload keys ---
  $payload_ids = [];
  $payload_client_ids = [];

  foreach ($events as $ev) {
    if (!is_array($ev)) continue;

    $cid = isset($ev['client_id']) ? trim((string)$ev['client_id']) : '';
    if ($cid !== '') $payload_client_ids[] = $cid;

    $id = isset($ev['id']) ? intval($ev['id']) : 0;
    if ($id > 0) $payload_ids[] = $id;
  }

  // --- Upsert ---
  foreach ($events as $ev) {
    if (!is_array($ev)) continue;

    // keys
    $client_id = isset($ev['client_id']) ? trim((string)$ev['client_id']) : '';
    $id = isset($ev['id']) ? intval($ev['id']) : 0;

    $title = trim((string)($ev['title'] ?? ''));
    $start_date = (string)($ev['start_date'] ?? '');
    $end_date = $ev['end_date'] ?? null;
    $recurrence = (string)($ev['recurrence'] ?? 'none');
    $active = isset($ev['active']) ? (intval($ev['active']) ? 1 : 0) : 1;
    $meta_json = array_key_exists('meta_json', $ev) ? $ev['meta_json'] : null;

    $line = $ev['line'] ?? null;
    if (!$line || !is_array($line)) continue;

    $line_type = (string)($line['line_type'] ?? '');
    $amount_chf = isset($line['amount_chf']) ? intval($line['amount_chf']) : 0;
    $indexation = $line['indexation'] ?? null;
    $category = $line['category'] ?? null;
    $line_meta_json = array_key_exists('meta_json', $line) ? $line['meta_json'] : null;

    // validation
    if ($title === '') continue;
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $start_date)) continue;

    if ($end_date !== null && $end_date !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)$end_date)) {
      $end_date = null;
    }

    if (!in_array($recurrence, ['none','yearly','monthly'], true)) $recurrence = 'none';
    if (!in_array($line_type, ['income','spending'], true)) continue;
    if ($amount_chf <= 0) continue;

    if ($indexation !== null && $indexation !== '' && !in_array($indexation, ['inflation','fixed_real','fixed_nominal'], true)) {
      $indexation = null;
    }

    $meta_json_str = $meta_json !== null ? wp_json_encode($meta_json) : null;
    $line_meta_json_str = $line_meta_json !== null ? wp_json_encode($line_meta_json) : null;

    // --- resolve target event row ---
    $event_id = 0;

    if ($client_id !== '') {
      // Preferred: stable UI key
      $event_id = intval($wpdb->get_var($wpdb->prepare(
        "SELECT id FROM {$t_event} WHERE user_id=%d AND client_id=%s",
        $uid, $client_id
      )));
    } else if ($id > 0) {
      // Legacy: numeric id must belong to user
      $own = $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(1) FROM {$t_event} WHERE id=%d AND user_id=%d",
        $id, $uid
      ));
      if (intval($own) === 1) $event_id = $id;
    }

    // --- write event ---
    if ($event_id > 0) {
      // UPDATE
      $data = [
        'title' => $title,
        'start_date' => $start_date,
        'end_date' => ($end_date === '' ? null : $end_date),
        'recurrence' => $recurrence,
        'active' => $active,
        'meta_json' => $meta_json_str,
      ];
      $format = ['%s','%s','%s','%s','%d','%s'];

      if ($client_id !== '') {
        $data['client_id'] = $client_id;
        $format[] = '%s';
      }

      $ok = $wpdb->update(
        $t_event,
        $data,
        ['id' => $event_id, 'user_id' => $uid],
        $format,
        ['%d','%d']
      );
      if ($ok === false) throw new Exception('event_update_failed');

    } else {
      // INSERT (requires client_id to prevent duplicates in UI use-cases)
      if ($client_id === '') {
        continue;
      }

      $ok = $wpdb->insert(
        $t_event,
        [
          'user_id' => $uid,
          'client_id' => $client_id,
          'title' => $title,
          'start_date' => $start_date,
          'end_date' => ($end_date === '' ? null : $end_date),
          'recurrence' => $recurrence,
          'active' => $active,
          'meta_json' => $meta_json_str,
        ],
        ['%d','%s','%s','%s','%s','%s','%d','%s']
      );
      if ($ok === false) throw new Exception('event_insert_failed');

      $event_id = intval($wpdb->insert_id);
    }

    // --- write line (1 line per event) ---
    $okd = $wpdb->delete($t_line, ['event_id' => $event_id, 'user_id' => $uid], ['%d','%d']);
    if ($okd === false) throw new Exception('event_line_delete_failed');

    $ok2 = $wpdb->insert(
      $t_line,
      [
        'event_id' => $event_id,
        'user_id' => $uid,
        'line_type' => $line_type,
        'amount_chf' => $amount_chf,
        'indexation' => ($indexation === '' ? null : $indexation),
        'category' => ($category === '' ? null : $category),
        'meta_json' => $line_meta_json_str,
      ],
      ['%d','%d','%s','%d','%s','%s','%s']
    );
    if ($ok2 === false) throw new Exception('event_line_insert_failed');
  }

  // --- Delete missing (source-of-truth) ---
  $payload_client_ids = array_values(array_unique(array_filter($payload_client_ids, fn($x) => $x !== '')));
  $payload_ids = array_values(array_unique(array_map('intval', $payload_ids)));

  // 1) Delete by client_id
  if (!empty($existing_client_ids)) {
    if (empty($payload_client_ids)) {
      $ok = $wpdb->query($wpdb->prepare(
        "DELETE FROM {$t_event} WHERE user_id=%d AND client_id IS NOT NULL",
        $uid
      ));
      if ($ok === false) throw new Exception('event_delete_failed');
    } else {
      $ph = implode(',', array_fill(0, count($payload_client_ids), '%s'));
      $args = array_merge([$uid], $payload_client_ids);
      $sql = "DELETE FROM {$t_event} WHERE user_id=%d AND client_id IS NOT NULL AND client_id NOT IN ($ph)";
      $ok = $wpdb->query($wpdb->prepare($sql, ...$args));
      if ($ok === false) throw new Exception('event_delete_failed');
    }
  }

  // 2) Legacy delete by numeric id for rows where client_id is NULL
  if (!empty($existing_ids)) {
    $existing_legacy_ids = $wpdb->get_col($wpdb->prepare(
      "SELECT id FROM {$t_event} WHERE user_id=%d AND (client_id IS NULL OR client_id='')",
      $uid
    ));
    $existing_legacy_ids = array_map('intval', $existing_legacy_ids ?: []);

    $to_delete = array_diff($existing_legacy_ids, $payload_ids);
    if (!empty($to_delete)) {
      $placeholders = implode(',', array_fill(0, count($to_delete), '%d'));
      $args = array_merge([$uid], array_values($to_delete));
      $sql = "DELETE FROM {$t_event} WHERE user_id=%d AND id IN ($placeholders)";
      $ok = $wpdb->query($wpdb->prepare($sql, ...$args));
      if ($ok === false) throw new Exception('event_delete_failed');
    }
  }
}

// ------------------------------
// Helpers
// ------------------------------

function sl_norm_birth_date($v) {
  if (!$v || !is_string($v)) return null;
  if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $v)) return $v;
  return null;
}

/**
 * Money norm:
 * - store as whole CHF integer (no cents)
 * - accept int/float or strings like "3'500", "3500", "3 500"
 */
function sl_norm_money_int($v) {
  if (is_int($v)) return $v;
  if (is_float($v)) return (int)round($v);
  if (!is_string($v)) return 0;

  $s = str_replace(["'", " ", ","], "", $v);
  $s = preg_replace('/\..*$/', '', $s);
  if ($s === '' || !preg_match('/^-?\d+$/', $s)) return 0;
  return (int)$s;
}

function sl_table_exists($table_name) {
  global $wpdb;
  $like = $wpdb->esc_like($table_name);
  $sql = $wpdb->prepare("SHOW TABLES LIKE %s", $like);
  $found = $wpdb->get_var($sql);
  return !empty($found);
}

function sl_sanitize_horizon_years($v) {
  if (!isset($v)) return null;
  $n = (int)$v;
  if ($n <= 0) return null;
  if ($n > 120) $n = 120; // safety only
  return $n;
}
