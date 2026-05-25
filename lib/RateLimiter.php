<?php

class RateLimiter {

    // Maximum requests allowed per window
    private const MAX_REQUESTS = 10;

    // Window size in seconds (1 hour)
    private const WINDOW_SECONDS = 3600;

    private PDO $pdo;

    public function __construct(PDO $pdo) {
        $this->pdo = $pdo;
    }

    // ── Main check — call this at the start of any endpoint ──
    // Returns true if request is allowed
    // Returns false if rate limit exceeded
    public function check(string $ip, string $endpoint = 'audit'): bool {

        // Clean up old rows for this IP first
        // Keeps the table lean — no need for a separate cron for this
        $this->cleanup($ip);

        // Count requests from this IP in the last window
        $count = $this->countRecent($ip, $endpoint);

        if ($count >= self::MAX_REQUESTS) {
            return false;
        }

        // Record this request
        $this->record($ip, $endpoint);
        return true;
    }

    // ── How many requests has this IP made recently? ─────────
    public function countRecent(string $ip, string $endpoint = 'audit'): int {

        $windowStart = date('Y-m-d H:i:s', time() - self::WINDOW_SECONDS);

        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) as count
            FROM rate_limits
            WHERE ip_address = ?
              AND endpoint   = ?
              AND created_at > ?
        ");
        $stmt->execute([$ip, $endpoint, $windowStart]);
        $row = $stmt->fetch();

        return (int) ($row['count'] ?? 0);
    }

    // ── How many seconds until the oldest request expires? ───
    // Used to tell the client when they can try again
    public function retryAfter(string $ip, string $endpoint = 'audit'): int {

        $windowStart = date('Y-m-d H:i:s', time() - self::WINDOW_SECONDS);

        $stmt = $this->pdo->prepare("
            SELECT MIN(created_at) as oldest
            FROM rate_limits
            WHERE ip_address = ?
              AND endpoint   = ?
              AND created_at > ?
        ");
        $stmt->execute([$ip, $endpoint, $windowStart]);
        $row = $stmt->fetch();

        if (empty($row['oldest'])) return 0;

        // Time until oldest request falls outside the window
        $oldestTime  = strtotime($row['oldest']);
        $expiresAt   = $oldestTime + self::WINDOW_SECONDS;
        $retryAfter  = $expiresAt - time();

        return max(0, $retryAfter);
    }

    // ── Record a new request ──────────────────────────────────
    private function record(string $ip, string $endpoint): void {
        $this->pdo->prepare("
            INSERT INTO rate_limits (ip_address, endpoint)
            VALUES (?, ?)
        ")->execute([$ip, $endpoint]);
    }

    // ── Delete old rows for this IP (older than window) ──────
    // Called on every request — keeps table clean without cron
    private function cleanup(string $ip): void {

        $cutoff = date('Y-m-d H:i:s', time() - self::WINDOW_SECONDS);

        $this->pdo->prepare("
            DELETE FROM rate_limits
            WHERE ip_address = ?
              AND created_at < ?
        ")->execute([$ip, $cutoff]);
    }

    // ── Get the client's real IP address ─────────────────────
    // Handles proxies and load balancers correctly
    public static function getClientIP(): string {

        // Check for IP forwarded by proxy/load balancer
        // X-Forwarded-For can contain multiple IPs — take the first
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip  = trim($ips[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }

        // Direct connection IP
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
}