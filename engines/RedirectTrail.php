<?php

require_once __DIR__ . '/Engine.php';

class RedirectTrail extends Engine {

    // CDN fingerprints — HTTP response headers that identify each CDN
    // Each CDN leaves distinctive headers on responses it serves
    private const CDN_SIGNATURES = [
        'Cloudflare'  => ['cf-ray', 'cf-cache-status'],
        'Fastly'      => ['x-fastly-request-id', 'x-served-by'],
        'Akamai'      => ['x-akamai-request-id', 'akamai-cache-status'],
        'AWS CloudFront' => ['x-amz-cf-id', 'x-amz-cf-pop'],
        'Google'      => ['x-goog-backend-server', 'server-timing'],
        'Vercel'      => ['x-vercel-id', 'x-vercel-cache'],
        'Netlify'     => ['x-nf-request-id'],
        'Bunny CDN'   => ['cdn-pullzone', 'cdn-uid'],
    ];

    // Known tracking parameters — their presence in a URL is a privacy signal
    private const TRACKING_PARAMS = [
        'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
        'fbclid',    // Facebook click ID
        'gclid',     // Google click ID
        'msclkid',   // Microsoft click ID
        'ttclid',    // TikTok click ID
        'twclid',    // Twitter click ID
        '_ga',       // Google Analytics
        'mc_eid',    // Mailchimp email ID
        'igshid',    // Instagram share ID
    ];

    protected function analyze(): array {

        $url   = $this->getUrl();
        $hops  = [];
        $seen  = []; // prevent infinite redirect loops

        // ── Follow the redirect chain ────────────────────────
        // We manually follow each hop so we can inspect every step
        $currentUrl = $url;
        $maxHops    = 15; // safety limit

        while (count($hops) < $maxHops) {

            // Prevent loops — if we've seen this URL, stop
            $normalised = strtolower(rtrim($currentUrl, '/'));
            if (in_array($normalised, $seen)) {
                break;
            }
            $seen[] = $normalised;

            // Fetch this hop — don't follow redirects (we do it manually)
            try {
                $response = $this->httpGet($currentUrl, 10);
            } catch (RuntimeException $e) {
                // Record the failed hop and stop
                $hops[] = [
                    'url'    => $currentUrl,
                    'status' => 0,
                    'error'  => $e->getMessage(),
                ];
                break;
            }

            $status  = $response['status'];
            $headers = $response['headers'];

            // Build the hop record
            $hop = [
                'url'     => $currentUrl,
                'status'  => $status,
                'cdn'     => $this->detectCDN($headers),
                'trackers'=> $this->detectTrackers($currentUrl),
            ];

            $hops[] = $hop;

            // 3xx = redirect — follow the Location header
            if ($status >= 300 && $status < 400) {
                $location = $headers['location'] ?? null;

                if (!$location) {
                    break; // redirect with no Location header — stop
                }

                // Location can be relative (e.g. /new-path) — make it absolute
                $currentUrl = $this->resolveUrl($currentUrl, $location);
                continue;
            }

            // 2xx = final destination — stop following
            if ($status >= 200 && $status < 300) {
                break;
            }

            // 4xx/5xx — record and stop
            break;
        }

        // ── Aggregate results ────────────────────────────────
        $finalHop     = end($hops) ?: [];
        $finalUrl     = $finalHop['url'] ?? $url;
        $finalStatus  = $finalHop['status'] ?? 0;

        // Collect all CDNs seen across the chain
        $cdns = array_values(array_unique(
            array_filter(array_column($hops, 'cdn'))
        ));

        // Collect all trackers seen across the chain
        $allTrackers = array_values(array_unique(array_merge(
            ...array_map(fn($h) => $h['trackers'], $hops)
        )));

        // ── Privacy risk assessment ──────────────────────────
        $privacyRisk = $this->assessPrivacyRisk($hops, $allTrackers);

        // ── Score calculation ────────────────────────────────
        $score = $this->calculateScore($hops, $allTrackers, $privacyRisk);

        return [
            'hop_count'    => count($hops),
            'hops'         => $hops,
            'final_url'    => $finalUrl,
            'final_status' => $finalStatus,
            'cdns'         => $cdns,
            'trackers'     => $allTrackers,
            'privacy_risk' => $privacyRisk,
            'score'        => $score,
        ];
    }

    // ── CDN Detection ────────────────────────────────────────
    private function detectCDN(array $headers): ?string {
        foreach (self::CDN_SIGNATURES as $cdn => $signatures) {
            foreach ($signatures as $headerName) {
                if (isset($headers[$headerName])) {
                    return $cdn;
                }
            }
        }
        return null; // no CDN detected
    }

    // ── Tracker Detection ────────────────────────────────────
    private function detectTrackers(string $url): array {
        $parsed = parse_url($url);
        if (empty($parsed['query'])) {
            return [];
        }

        // Parse query string into key => value pairs
        parse_str($parsed['query'], $params);
        $paramKeys = array_map('strtolower', array_keys($params));

        // Return any tracking params found in this URL
        return array_values(array_intersect(
            array_map('strtolower', self::TRACKING_PARAMS),
            $paramKeys
        ));
    }

    // ── Privacy Risk Assessment ──────────────────────────────
    private function assessPrivacyRisk(array $hops, array $trackers): string {

        $riskScore = 0;

        // Long redirect chains are suspicious
        $hopCount = count($hops);
        if ($hopCount >= 5) $riskScore += 3;
        elseif ($hopCount >= 3) $riskScore += 1;

        // Each tracker parameter adds risk
        $riskScore += count($trackers) * 2;

        // Mixed HTTP/HTTPS in the chain is a risk
        $protocols = array_map(
            fn($h) => parse_url($h['url'], PHP_URL_SCHEME),
            $hops
        );
        if (in_array('http', $protocols) && in_array('https', $protocols)) {
            $riskScore += 2;
        }

        // Classify
        if ($riskScore === 0) return 'none';
        if ($riskScore <= 2)  return 'low';
        if ($riskScore <= 5)  return 'medium';
        return 'high';
    }

    // ── Score Calculation ────────────────────────────────────
    private function calculateScore(
        array $hops,
        array $trackers,
        string $privacyRisk
    ): int {

        $score = 100;

        // Penalise long chains
        $hopCount = count($hops);
        if ($hopCount >= 10) $score -= 30;
        elseif ($hopCount >= 5) $score -= 15;
        elseif ($hopCount >= 3) $score -= 5;

        // Penalise trackers
        $score -= count($trackers) * 10;

        // Penalise privacy risk level
        $score -= match($privacyRisk) {
            'high'   => 30,
            'medium' => 15,
            'low'    => 5,
            default  => 0,
        };

        // Penalise if final hop was not 200
        $finalStatus = end($hops)['status'] ?? 0;
        if ($finalStatus !== 200) $score -= 10;

        return max(0, $score);
    }

    // ── Resolve relative URLs ────────────────────────────────
    // Location: /new-path  →  https://example.com/new-path
    // Location: https://other.com  →  https://other.com (already absolute)
    private function resolveUrl(string $base, string $location): string {

        // Already absolute
        if (preg_match('/^https?:\/\//i', $location)) {
            return $location;
        }

        $parsed = parse_url($base);
        $scheme = $parsed['scheme'] ?? 'https';
        $host   = $parsed['host']   ?? '';

        // Root-relative: /path
        if (str_starts_with($location, '/')) {
            return "{$scheme}://{$host}{$location}";
        }

        // Protocol-relative: //example.com/path
        if (str_starts_with($location, '//')) {
            return "{$scheme}:{$location}";
        }

        // Relative path — resolve against current directory
        $basePath = dirname($parsed['path'] ?? '/');
        return "{$scheme}://{$host}{$basePath}/{$location}";
    }
}