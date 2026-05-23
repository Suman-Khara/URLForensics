<?php

require_once __DIR__ . '/Engine.php';

class CookieAudit extends Engine {

    // Disconnect.me tracker database — same list Firefox uses
    private const DISCONNECT_URL = 'https://raw.githubusercontent.com/nicowillis/disconnect-tracking-protection/master/disconnect.json';

    // Known tracking cookie name patterns
    private const TRACKING_PATTERNS = [
        '_ga'        => 'Google Analytics',
        '_gid'       => 'Google Analytics',
        '_gat'       => 'Google Analytics',
        '__utma'     => 'Google Analytics (legacy)',
        '__utmb'     => 'Google Analytics (legacy)',
        '__utmz'     => 'Google Analytics (legacy)',
        '_fbp'       => 'Facebook Pixel',
        '_fbc'       => 'Facebook Click',
        'fr'         => 'Facebook',
        '_gcl_au'    => 'Google Ads',
        '_gcl_aw'    => 'Google Ads',
        '__cfduid'   => 'Cloudflare (deprecated)',
        'cf_clearance'=> 'Cloudflare',
        '_hjid'      => 'Hotjar',
        '_hjFirstSeen'=> 'Hotjar',
        'ajs_user_id'=> 'Segment',
        'ajs_group_id'=> 'Segment',
        '__hssc'     => 'HubSpot',
        '__hssrc'    => 'HubSpot',
        '__hstc'     => 'HubSpot',
        'hubspotutk' => 'HubSpot',
        '_ttp'       => 'TikTok Pixel',
        '_uetsid'    => 'Microsoft Ads',
        '_uetvid'    => 'Microsoft Ads',
        'IDE'        => 'Google DoubleClick',
        'NID'        => 'Google',
        'ANID'       => 'Google Ads',
        'DSID'       => 'Google DoubleClick',
    ];

    protected function analyze(): array {

        $url    = $this->getUrl();
        $domain = $this->getDomain();

        // ── 1. Fetch the page and capture cookies ────────────
        $cookieData = $this->fetchCookies($url);

        // ── 2. Parse each cookie's attributes ────────────────
        $parsedCookies = $this->parseCookies($cookieData['raw_cookies']);

        // ── 3. Classify each cookie ──────────────────────────
        $classified = $this->classifyCookies($parsedCookies, $domain);

        // ── 4. Compute privacy grade ─────────────────────────
        $grade = $this->computeGrade($classified);

        // ── 5. Score ──────────────────────────────────────────
        $score = $this->calculateScore($classified, $grade);

        return [
            'domain'            => $domain,
            'total_cookies'     => count($parsedCookies),
            'tracking_cookies'  => $classified['tracking_count'],
            'third_party'       => $classified['third_party_count'],
            'session_cookies'   => $classified['session_count'],
            'secure_cookies'    => $classified['secure_count'],
            'httponly_cookies'  => $classified['httponly_count'],
            'samesite_cookies'  => $classified['samesite_count'],
            'cookies'           => $classified['cookies'],
            'trackers_found'    => $classified['trackers_found'],
            'privacy_grade'     => $grade,
            'score'             => $score,
        ];
    }

    // ── Fetch page and capture Set-Cookie headers ────────────
    private function fetchCookies(string $url): array {

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_FOLLOWLOCATION => true,  // follow redirects
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_USERAGENT      => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_CAINFO         => '/etc/ssl/certs/ca-certificates.crt',
        ]);

        $response   = curl_exec($ch);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $httpCode   = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($response === false) {
            throw new RuntimeException('Failed to fetch URL: ' . curl_error($ch));
        }

        $rawHeaders = substr($response, 0, $headerSize);

        // Extract all Set-Cookie headers
        // Can't use parseHeaders() from base class — it deduplicates,
        // but a response can have multiple Set-Cookie headers
        $rawCookies = [];
        foreach (explode("\r\n", $rawHeaders) as $line) {
            if (stripos($line, 'set-cookie:') === 0) {
                $rawCookies[] = trim(substr($line, strlen('set-cookie:')));
            }
        }

        return [
            'raw_cookies' => $rawCookies,
            'http_code'   => $httpCode,
        ];
    }

    // ── Parse raw Set-Cookie strings into structured data ────
    private function parseCookies(array $rawCookies): array {

        $parsed = [];

        foreach ($rawCookies as $raw) {

            // Cookie format:
            // name=value; Path=/; Domain=.example.com; Secure; HttpOnly; SameSite=Lax; Expires=...
            $parts = array_map('trim', explode(';', $raw));

            if (empty($parts[0])) continue;

            // First part is name=value
            $nameValue = explode('=', $parts[0], 2);
            $name      = trim($nameValue[0]);
            $value     = trim($nameValue[1] ?? '');

            // Parse attributes from remaining parts
            $attributes = [];
            for ($i = 1; $i < count($parts); $i++) {
                $attr = explode('=', $parts[$i], 2);
                $key  = strtolower(trim($attr[0]));
                $val  = trim($attr[1] ?? 'true');
                $attributes[$key] = $val;
            }

            // Calculate expiry duration in days
            $expiryDays = null;
            if (isset($attributes['expires'])) {
                $expiryTime = strtotime($attributes['expires']);
                if ($expiryTime) {
                    $expiryDays = (int) round(($expiryTime - time()) / 86400);
                }
            } elseif (isset($attributes['max-age'])) {
                $expiryDays = (int) round((int)$attributes['max-age'] / 86400);
            }

            $parsed[] = [
                'name'        => $name,
                'value_length'=> strlen($value), // don't store actual value
                'domain'      => $attributes['domain']   ?? null,
                'path'        => $attributes['path']     ?? '/',
                'secure'      => isset($attributes['secure']),
                'httponly'    => isset($attributes['httponly']),
                'samesite'    => $attributes['samesite'] ?? null,
                'expiry_days' => $expiryDays,
                'session'     => $expiryDays === null, // no expiry = session cookie
                'raw'         => $raw,
            ];
        }

        return $parsed;
    }

    // ── Classify cookies ──────────────────────────────────────
    private function classifyCookies(array $cookies, string $domain): array {

        $trackingCount   = 0;
        $thirdPartyCount = 0;
        $sessionCount    = 0;
        $secureCount     = 0;
        $httponlyCount   = 0;
        $samesiteCount   = 0;
        $trackersFound   = [];
        $classified      = [];

        foreach ($cookies as $cookie) {

            $isTracking   = false;
            $trackerName  = null;
            $isThirdParty = false;

            // ── Check against known tracking patterns ─────────
            $cookieName = strtolower($cookie['name']);
            foreach (self::TRACKING_PATTERNS as $pattern => $tracker) {
                if (
                    $cookieName === strtolower($pattern) ||
                    str_starts_with($cookieName, strtolower($pattern))
                ) {
                    $isTracking  = true;
                    $trackerName = $tracker;
                    if (!in_array($tracker, $trackersFound)) {
                        $trackersFound[] = $tracker;
                    }
                    break;
                }
            }

            // ── Check if third-party ──────────────────────────
            // A cookie is third-party if its domain differs from
            // the site's domain
            if ($cookie['domain']) {
                $cookieDomain = ltrim($cookie['domain'], '.');
                $isThirdParty = !str_ends_with(
                    $domain,
                    $cookieDomain
                ) && !str_ends_with(
                    $cookieDomain,
                    $domain
                );
            }

            // ── Count attributes ──────────────────────────────
            if ($isTracking)         $trackingCount++;
            if ($isThirdParty)       $thirdPartyCount++;
            if ($cookie['session'])  $sessionCount++;
            if ($cookie['secure'])   $secureCount++;
            if ($cookie['httponly']) $httponlyCount++;
            if ($cookie['samesite']) $samesiteCount++;

            // ── Privacy risk per cookie ───────────────────────
            $risk = $this->assessCookieRisk($cookie, $isTracking, $isThirdParty);

            $classified[] = array_merge($cookie, [
                'is_tracking'   => $isTracking,
                'tracker_name'  => $trackerName,
                'is_third_party'=> $isThirdParty,
                'risk'          => $risk,
            ]);
        }

        return [
            'cookies'           => $classified,
            'tracking_count'    => $trackingCount,
            'third_party_count' => $thirdPartyCount,
            'session_count'     => $sessionCount,
            'secure_count'      => $secureCount,
            'httponly_count'    => $httponlyCount,
            'samesite_count'    => $samesiteCount,
            'trackers_found'    => $trackersFound,
        ];
    }

    // ── Assess risk level for a single cookie ────────────────
    private function assessCookieRisk(
        array $cookie,
        bool $isTracking,
        bool $isThirdParty
    ): string {

        $risk = 0;

        if ($isTracking)               $risk += 3;
        if ($isThirdParty)             $risk += 2;
        if (!$cookie['secure'])        $risk += 2;
        if (!$cookie['httponly'])       $risk += 1;
        if ($cookie['samesite'] === null) $risk += 1;
        if ($cookie['samesite'] === 'none') $risk += 2;

        // Long-lived cookies are more of a privacy concern
        if ($cookie['expiry_days'] !== null) {
            if ($cookie['expiry_days'] > 365) $risk += 2;
            elseif ($cookie['expiry_days'] > 90) $risk += 1;
        }

        if ($risk === 0) return 'none';
        if ($risk <= 2)  return 'low';
        if ($risk <= 5)  return 'medium';
        return 'high';
    }

    // ── Compute privacy letter grade ─────────────────────────
    private function computeGrade(array $classified): string {

        $total    = count($classified['cookies']);
        $tracking = $classified['tracking_count'];
        $secure   = $classified['secure_count'];
        $httponly = $classified['httponly_count'];

        if ($total === 0) return 'A';

        // Tracking ratio — what fraction of cookies are trackers
        $trackingRatio = $tracking / $total;

        // Security ratio — what fraction have Secure + HttpOnly
        $securityRatio = $total > 0
            ? min($secure, $httponly) / $total
            : 1;

        // Grade based on tracking ratio primarily
        if ($trackingRatio === 0 && $securityRatio >= 0.8) return 'A';
        if ($trackingRatio === 0)                          return 'B';
        if ($trackingRatio <= 0.25)                        return 'C';
        if ($trackingRatio <= 0.5)                         return 'D';
        return 'F';
    }

    // ── Score calculation ─────────────────────────────────────
    private function calculateScore(array $classified, string $grade): int {

        $score = 100;
        $total = count($classified['cookies']);

        if ($total === 0) return 100; // no cookies = perfect score

        // Grade penalty
        $score -= match($grade) {
            'A' => 0,
            'B' => 5,
            'C' => 15,
            'D' => 30,
            'F' => 50,
        };

        // Each tracker
        $score -= $classified['tracking_count'] * 8;

        // Each third-party cookie
        $score -= $classified['third_party_count'] * 5;

        // Reward good security practices
        // Cookies without Secure flag
        $insecure = $total - $classified['secure_count'];
        $score   -= $insecure * 3;

        // Cookies without HttpOnly
        $noHttpOnly = $total - $classified['httponly_count'];
        $score     -= $noHttpOnly * 2;

        return max(0, $score);
    }
}