<?php

// This script runs as a CLI process — never via HTTP
// Called by stream.php for each engine in parallel
//
// Usage: php run_engine.php <engine_name> <audit_id> <tmp_dir>

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('CLI only');
}

// ── Arguments ────────────────────────────────────────────────
$engineName = $argv[1] ?? null;
$auditId    = (int) ($argv[2] ?? 0);
$tmpDir     = $argv[3] ?? null;

if (!$engineName || !$auditId || !$tmpDir) {
    error_log('run_engine.php: missing arguments');
    exit(1);
}

// ── Bootstrap ────────────────────────────────────────────────
require_once __DIR__ . '/../../lib/DB.php';
require_once __DIR__ . '/../../engines/Engine.php';
require_once __DIR__ . '/../../engines/RedirectTrail.php';
require_once __DIR__ . '/../../engines/DNSPropagation.php';
require_once __DIR__ . '/../../engines/TLSTimeline.php';
require_once __DIR__ . '/../../engines/CookieAudit.php';
require_once __DIR__ . '/../../engines/PacketJourney.php';
require_once __DIR__ . '/../../engines/DNSResolutionTree.php';

// ── Fetch audit record ────────────────────────────────────────
try {
    $pdo  = DB::connect();
    $stmt = $pdo->prepare("SELECT * FROM audits WHERE id = ?");
    $stmt->execute([$auditId]);
    $audit = $stmt->fetch();
} catch (Exception $e) {
    error_log("run_engine.php DB error: " . $e->getMessage());
    exit(1);
}

if (!$audit) {
    error_log("run_engine.php: audit {$auditId} not found");
    exit(1);
}

// ── Instantiate the correct engine ───────────────────────────
$engine = match($engineName) {
    'redirect_trail'      => new RedirectTrail($audit),
    'dns_propagation'     => new DNSPropagation($audit),
    'tls_timeline'        => new TLSTimeline($audit),
    'cookie_audit'        => new CookieAudit($audit),
    'packet_journey'      => new PacketJourney($audit),
    'dns_resolution_tree' => new DNSResolutionTree($audit),
    default               => null,
};

if (!$engine) {
    error_log("run_engine.php: unknown engine {$engineName}");
    exit(1);
}

// ── Mark engine as running ────────────────────────────────────
$pdo->prepare("
    UPDATE engine_results
    SET status = 'running'
    WHERE audit_id = ? AND engine = ?
")->execute([$auditId, $engineName]);

// ── Run the engine ────────────────────────────────────────────
$engineOutput = $engine->run();

$result     = $engineOutput['data'];
$score      = $engineOutput['score'];
$durationMs = $engineOutput['duration_ms'];
$status     = $engineOutput['status'];

// ── Update DB ─────────────────────────────────────────────────
$pdo->prepare("
    UPDATE engine_results
    SET
        status       = ?,
        result       = ?,
        score        = ?,
        duration_ms  = ?,
        completed_at = NOW()
    WHERE audit_id = ? AND engine = ?
")->execute([
    $status,
    json_encode($result),
    $score,
    $durationMs,
    $auditId,
    $engineName
]);

// ── Write result to temp file ─────────────────────────────────
if (!is_dir($tmpDir)) {
    mkdir($tmpDir, 0700, true);
}

$payload = json_encode([
    'engine'      => $engineName,
    'status'      => $status,
    'data'        => $result,
    'score'       => $score,
    'duration_ms' => $durationMs,
]);

file_put_contents("{$tmpDir}/{$engineName}.json", $payload);

exit(0);