<?php

require_once __DIR__ . '/../../lib/DB.php';
require_once __DIR__ . '/../../lib/SignalAnalyzer.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$slug = trim($_GET['slug'] ?? '');

if (empty($slug)) {
    http_response_code(400);
    echo json_encode(['error' => 'Slug is required']);
    exit;
}

try {
    $pdo = DB::connect();

    // Fetch the audit
    $stmt = $pdo->prepare("
        SELECT id, slug, url, domain, status, trust_score,
               created_at, completed_at
        FROM audits
        WHERE slug = ?
    ");
    $stmt->execute([$slug]);
    $audit = $stmt->fetch();

    if (!$audit) {
        http_response_code(404);
        echo json_encode(['error' => 'Report not found']);
        exit;
    }

    // Fetch all engine results
    $stmt = $pdo->prepare("
        SELECT engine, status, result, score, duration_ms, completed_at
        FROM engine_results
        WHERE audit_id = ?
        ORDER BY completed_at ASC
    ");
    $stmt->execute([$audit['id']]);
    $engineRows = $stmt->fetchAll();

    // Structure engine results — decode JSON result field
    $engines = [];
    foreach ($engineRows as $row) {
        $engines[$row['engine']] = [
            'status'      => $row['status'],
            'data'        => $row['result']
                             ? json_decode($row['result'], true)
                             : null,
            'score'       => $row['score'],
            'duration_ms' => $row['duration_ms'],
            'completed_at'=> $row['completed_at'],
        ];
    }

    $analyzer = new SignalAnalyzer($engines);
    $signals  = $analyzer->analyze();

    echo json_encode([
        'success' => true,
        'audit'   => $audit,
        'engines' => $engines,
        'signals' => $signals,
    ]);

} catch (Exception $e) {
    error_log('report/get.php error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Failed to fetch report']);
}