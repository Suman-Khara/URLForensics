<?php

// ── Bootstrap ────────────────────────────────────────────────
require_once __DIR__ . '/../../lib/DB.php';
require_once __DIR__ . '/../../lib/SSE.php';

// ── Get the slug from the URL ────────────────────────────────
// Request will be GET /api/audit/stream.php?slug=R7XDGZz9
$slug = trim($_GET['slug'] ?? '');

if (empty($slug)) {
    http_response_code(400);
    echo json_encode(['error' => 'Slug is required']);
    exit;
}

// ── Look up the audit ────────────────────────────────────────
try {
    $pdo  = DB::connect();
    $stmt = $pdo->prepare("
        SELECT id, url, domain, status
        FROM audits
        WHERE slug = ?
    ");
    $stmt->execute([$slug]);
    $audit = $stmt->fetch();

} catch (Exception $e) {
    error_log('stream.php DB error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Database error']);
    exit;
}

if (!$audit) {
    http_response_code(404);
    echo json_encode(['error' => 'Audit not found']);
    exit;
}

// Don't re-run a completed audit — return cached result
if ($audit['status'] === 'complete') {
    header('Content-Type: application/json');
    $stmt = $pdo->prepare("
        SELECT engine, status, result, score, duration_ms
        FROM engine_results
        WHERE audit_id = ?
    ");
    $stmt->execute([$audit['id']]);
    $results = $stmt->fetchAll();

    echo json_encode([
        'cached'      => true,
        'audit'       => $audit,
        'results'     => $results
    ]);
    exit;
}

// ── Start the SSE stream ─────────────────────────────────────
SSE::start();

SSE::send('status', [
    'message' => 'Audit started',
    'url'     => $audit['url'],
    'domain'  => $audit['domain']
]);

// ── Mark audit as running ────────────────────────────────────
$pdo->prepare("
    UPDATE audits SET status = 'running' WHERE id = ?
")->execute([$audit['id']]);

// ── Define the engines ───────────────────────────────────────
// Each engine is a callable that receives the audit data
// and returns a result array.
// Right now these are PLACEHOLDERS — real engine classes come next.
// The pipeline, SSE flow, and DB updates are all real.

// ── Load engine classes ──────────────────────────────────────
require_once __DIR__ . '/../../engines/Engine.php';
// At the top, add the require:
require_once __DIR__ . '/../../engines/RedirectTrail.php';
require_once __DIR__ . '/../../engines/DNSPropagation.php';
require_once __DIR__ . '/../../engines/TLSTimeline.php';
// ── Define the engines ───────────────────────────────────────
// Maps engine name → instantiated engine object
// As real engines are built, swap the placeholder closure
// for: new EngineClassName($audit)

$engines = [
    'redirect_trail' => new RedirectTrail($audit),
    'dns_propagation' => new DNSPropagation($audit),

    'tls_timeline' => new TLSTimeline($audit),

    'cookie_audit' => new class($audit) extends Engine {
        protected function analyze(): array {
            sleep(1);
            return [
                'total_cookies'    => 4,
                'tracking_cookies' => 1,
                'third_party'      => 2,
                'privacy_grade'    => 'B',
                'score'            => 75
            ];
        }
    },

    'packet_journey' => new class($audit) extends Engine {
        protected function analyze(): array {
            sleep(4);
            return [
                'hops'       => 12,
                'avg_rtt_ms' => 18.4,
                'countries'  => ['IN', 'SG', 'US'],
                'score'      => 82
            ];
        }
    },

    'dns_resolution_tree' => new class($audit) extends Engine {
        protected function analyze(): array {
            sleep(2);
            return [
                'root'          => '.',
                'tld'           => 'com',
                'authoritative' => 'ns1.github.com',
                'steps'         => 4,
                'score'         => 92
            ];
        }
    },
];

// ── Run engines sequentially for now ────────────────────────
// We will replace this with parallel execution in Phase 2.
// Sequential first so the flow is easy to understand and debug.

$scores = [];

foreach ($engines as $engineName => $engineFn) {

    // Tell frontend this engine is starting
    SSE::send('engine_start', [
        'engine' => $engineName
    ]);

    // Mark as running in DB
    $pdo->prepare("
        UPDATE engine_results
        SET status = 'running'
        WHERE audit_id = ? AND engine = ?
    ")->execute([$audit['id'], $engineName]);

    // Send a heartbeat so connection stays alive during long engines
    SSE::heartbeat();

    $startTime = microtime(true);

    try {
        // run() handles timing and error catching internally
        $engineOutput = $engineFn->run();
        $result       = $engineOutput['data'];
        $score        = $engineOutput['score'];
        $durationMs   = $engineOutput['duration_ms'];

        // Store result in DB
        $pdo->prepare("
            UPDATE engine_results
            SET
                status       = 'complete',
                result       = ?,
                score        = ?,
                duration_ms  = ?,
                completed_at = NOW()
            WHERE audit_id = ? AND engine = ?
        ")->execute([
            json_encode($result),
            $score,
            $durationMs,
            $audit['id'],
            $engineName
        ]);

        // Collect score for trust score calculation
        if ($score !== null) {
            $scores[] = $score;
        }

        // Stream result to frontend
        SSE::send('engine_result', [
            'engine'      => $engineName,
            'status'      => $engineOutput['status'],
            'data'        => $result,
            'duration_ms' => $durationMs
        ]);

    } catch (Exception $e) {
        error_log("stream.php error for {$engineName}: " . $e->getMessage());

        $pdo->prepare("
            UPDATE engine_results
            SET status = 'failed'
            WHERE audit_id = ? AND engine = ?
        ")->execute([$audit['id'], $engineName]);

        SSE::send('engine_result', [
            'engine'  => $engineName,
            'status'  => 'failed',
            'message' => 'Engine failed'
        ]);
    }
}

// ── Compute composite trust score ───────────────────────────
// Simple average for now — we'll add weighting in Phase 6
$trustScore = count($scores) > 0
    ? (int) round(array_sum($scores) / count($scores))
    : null;

// ── Mark audit complete ──────────────────────────────────────
$pdo->prepare("
    UPDATE audits
    SET
        status       = 'complete',
        trust_score  = ?,
        completed_at = NOW()
    WHERE id = ?
")->execute([$trustScore, $audit['id']]);

// ── Signal completion ────────────────────────────────────────
SSE::done([
    'trust_score' => $trustScore,
    'audit_id'    => $audit['id'],
    'slug'        => $slug
]);