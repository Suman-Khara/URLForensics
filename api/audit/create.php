<?php

// ── Bootstrap ────────────────────────────────────────────────
require_once __DIR__ . '/../../lib/DB.php';
require_once __DIR__ . '/../../lib/RateLimiter.php';

// All responses from this endpoint are JSON
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

// ── Only accept POST requests ────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// ── Rate limiting ─────────────────────────────────────────
$pdo         = null;
$rateLimiter = null;

try {
    $pdo         = DB::connect();
    $rateLimiter = new RateLimiter($pdo);
    $clientIP    = RateLimiter::getClientIP();

    if (!$rateLimiter->check($clientIP)) {
        $retryAfter = $rateLimiter->retryAfter($clientIP);
        http_response_code(429);
        header("Retry-After: {$retryAfter}");
        echo json_encode([
            'error'       => 'Rate limit exceeded',
            'message'     => 'Maximum 10 audits per hour.',
            'retry_after' => $retryAfter,
        ]);
        exit;
    }
    
    // Inform client of their rate limit status
    if ($rateLimiter) {
        $remaining = max(0, 10 - $rateLimiter->countRecent($clientIP));
        header("X-RateLimit-Limit: 10");
        header("X-RateLimit-Remaining: {$remaining}");
        header("X-RateLimit-Window: 3600");
    }

} catch (Exception $e) {
    error_log('Rate limiter error: ' . $e->getMessage());
    // If rate limiter fails, allow the request
    // Better to serve than to block on a limiter bug
}

// ── Parse the request body ───────────────────────────────────
// Vue will send JSON in the request body, not a form POST
$body = json_decode(file_get_contents('php://input'), true);
$url  = trim($body['url'] ?? '');

// ── Validate ─────────────────────────────────────────────────
if (empty($url)) {
    http_response_code(400);
    echo json_encode(['error' => 'URL is required']);
    exit;
}

// Add https:// if no scheme provided — quality of life for users
if (!preg_match('/^https?:\/\//i', $url)) {
    $url = 'https://' . $url;
}

// PHP's built-in URL validator
if (!filter_var($url, FILTER_VALIDATE_URL)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid URL format']);
    exit;
}

// Extract the domain from the URL
$domain = strtolower(parse_url($url, PHP_URL_HOST));

if (empty($domain)) {
    http_response_code(400);
    echo json_encode(['error' => 'Could not extract domain from URL']);
    exit;
}

// ── Generate a unique slug ───────────────────────────────────
// This becomes the shareable URL: /report/aB3xKq
function generateSlug(int $length = 8): string {
    // URL-safe characters only
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $slug  = '';
    for ($i = 0; $i < $length; $i++) {
        $slug .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $slug;
}

// ── Write to database ────────────────────────────────────────
$pdo = null;
try {
    $pdo = DB::connect();

    // Generate a slug that doesn't already exist
    // Collision probability is astronomically low but we check anyway
    do {
        $slug = generateSlug();
        $stmt = $pdo->prepare("SELECT id FROM audits WHERE slug = ?");
        $stmt->execute([$slug]);
    } while ($stmt->fetch());

    // Wrap both inserts in a transaction
    // Either both succeed or neither does — no half-created audits
    $pdo->beginTransaction();

    // ── Insert the audit job ─────────────────────────────────
    $stmt = $pdo->prepare("
        INSERT INTO audits (slug, url, domain, status)
        VALUES (?, ?, ?, 'pending')
    ");
    $stmt->execute([$slug, $url, $domain]);

    // The auto-incremented ID of the row we just inserted
    $auditId = (int) $pdo->lastInsertId();

    // ── Insert 6 engine subtask rows ─────────────────────────
    // All start as 'pending' — stream.php will update them
    $engines = [
        'redirect_trail',
        'dns_propagation',
        'tls_timeline',
        'cookie_audit',
        'packet_journey',
        'dns_resolution_tree'
    ];

    $stmt = $pdo->prepare("
        INSERT INTO engine_results (audit_id, engine, status)
        VALUES (?, ?, 'pending')
    ");

    foreach ($engines as $engine) {
        $stmt->execute([$auditId, $engine]);
    }

    $pdo->commit();

    // ── Return success ───────────────────────────────────────
    http_response_code(201);
    echo json_encode([
        'success'  => true,
        'slug'     => $slug,
        'audit_id' => $auditId,
        'url'      => $url,
        'domain'   => $domain,
        'stream'   => "/api/audit/stream/{$slug}"
    ]);

} catch (Exception $e) {
    // Roll back if anything failed mid-transaction
    if ($pdo && $pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log('create.php error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Failed to create audit']);
}