<?php

abstract class Engine {

    // Every engine receives the full audit record from the DB
    protected array $audit;

    // Subclasses set this to cap their own execution time
    protected int $timeoutSeconds = 15;

    public function __construct(array $audit) {
        $this->audit = $audit;
    }

    // ── The one method every engine MUST implement ───────────
    // abstract means: "I don't know how to do this —
    // each subclass must define it for themselves"
    abstract protected function analyze(): array;

    // ── The public interface — called by stream.php ──────────
    // Every engine is run the same way: $engine->run()
    // This handles timing, error catching, score validation
    // so each engine class only needs to focus on its own logic
    public function run(): array {

        $start = microtime(true);

        try {
            $result = $this->analyze();

            // Enforce score exists and is in valid range
            if (!isset($result['score'])) {
                $result['score'] = 50; // neutral default
            }
            $result['score'] = max(0, min(100, (int) $result['score']));

            return [
                'status'      => 'complete',
                'data'        => $result,
                'score'       => $result['score'],
                'duration_ms' => $this->elapsed($start),
            ];

        } catch (Exception $e) {
            error_log(static::class . ' engine error: ' . $e->getMessage());

            return [
                'status'      => 'failed',
                'data'        => null,
                'score'       => null,
                'duration_ms' => $this->elapsed($start),
                'error'       => $e->getMessage(),
            ];
        }
    }

    // ── Shared utilities available to all engines ────────────

    // Milliseconds elapsed since $start
    protected function elapsed(float $start): int {
        return (int) round((microtime(true) - $start) * 1000);
    }

    // Make an HTTP request with consistent timeout + user agent
    // Returns [statusCode, headers, body] or throws on failure
    protected function httpGet(string $url, int $timeout = 10): array {

        $ch = curl_init();

        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_FOLLOWLOCATION => false, // engines handle redirects manually
            CURLOPT_HEADER         => true,  // include response headers
            CURLOPT_USERAGENT      => 'URLForensics/1.0 (diagnostic tool)',
            CURLOPT_SSL_VERIFYPEER => true,
        ]);

        $response   = curl_exec($ch);
        $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $error      = curl_error($ch);

        if ($response === false) {
            throw new RuntimeException("HTTP request failed: {$error}");
        }

        // Split raw response into headers and body
        $rawHeaders = substr($response, 0, $headerSize);
        $body       = substr($response, $headerSize);

        return [
            'status'  => $statusCode,
            'headers' => $this->parseHeaders($rawHeaders),
            'body'    => $body,
        ];
    }

    // Parse raw HTTP header string into associative array
    private function parseHeaders(string $raw): array {
        $headers = [];
        foreach (explode("\r\n", $raw) as $line) {
            if (str_contains($line, ':')) {
                [$key, $value]         = explode(':', $line, 2);
                $headers[strtolower(trim($key))] = trim($value);
            }
        }
        return $headers;
    }

    // Extract domain from the audit URL
    protected function getDomain(): string {
        return $this->audit['domain'];
    }

    // Extract full URL from the audit record
    protected function getUrl(): string {
        return $this->audit['url'];
    }
}