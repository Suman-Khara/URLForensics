<?php

require_once __DIR__ . '/Engine.php';

class PacketJourney extends Engine {

    // ip-api.com — free, no key, 45 requests/minute limit
    // batch endpoint lets us geo-locate up to 100 IPs in one request
    private const GEOIP_BATCH_URL = 'http://ip-api.com/batch';

    // Fields we want back from ip-api
    private const GEOIP_FIELDS = 'status,country,countryCode,regionName,city,isp,org,as,lat,lon,query';

    // Private/reserved IP ranges — these are internal routers
    // we can't geo-locate them and shouldn't try
    private const PRIVATE_RANGES = [
        '/^10\./',
        '/^172\.(1[6-9]|2[0-9]|3[01])\./',
        '/^192\.168\./',
        '/^127\./',
        '/^169\.254\./',
        '/^fc00:/',
        '/^fe80:/',
    ];

    protected function analyze(): array {

        $domain = $this->getDomain();

        // ── 1. Run traceroute ─────────────────────────────────
        $hops = $this->runTraceroute($domain);

        if (empty($hops)) {
            throw new RuntimeException("Traceroute returned no hops for {$domain}");
        }

        // ── 2. Collect public IPs for geo-location ────────────
        $publicIps = array_filter(
            array_column($hops, 'ip'),
            fn($ip) => $ip && !$this->isPrivateIp($ip)
        );

        // ── 3. Geo-locate all public IPs in one batch request ─
        $geoData = !empty($publicIps)
            ? $this->geoLocateBatch(array_values($publicIps))
            : [];

        // ── 4. Enrich hops with geo data ──────────────────────
        $enrichedHops = $this->enrichHops($hops, $geoData);

        // ── 5. Analyse the route ──────────────────────────────
        $analysis = $this->analyseRoute($enrichedHops);

        // ── 6. Score ──────────────────────────────────────────
        $score = $this->calculateScore($enrichedHops, $analysis);

        return [
            'domain'          => $domain,
            'hop_count'       => count($enrichedHops),
            'hops'            => $enrichedHops,
            'countries'       => $analysis['countries'],
            'isps'            => $analysis['isps'],
            'avg_rtt_ms'      => $analysis['avg_rtt'],
            'max_rtt_ms'      => $analysis['max_rtt'],
            'unresponsive'    => $analysis['unresponsive'],
            'suspicious_routing' => $analysis['suspicious'],
            'score'           => $score,
        ];
    }

    // ── Run traceroute and parse output ───────────────────────
    private function runTraceroute(string $domain): array {

        // -n  → don't resolve IPs to hostnames (faster)
        // -m 20 → max 20 hops
        // -w 2  → wait 2 seconds per probe
        // -q 1  → send only 1 probe per hop (faster, less noisy)
        $command = escapeshellcmd(
            "traceroute -n -m 20 -w 2 -q 1 " . escapeshellarg($domain)
        );

        // proc_open gives us more control than shell_exec
        // we can capture stdout and stderr separately
        $descriptors = [
            0 => ['pipe', 'r'],  // stdin
            1 => ['pipe', 'w'],  // stdout
            2 => ['pipe', 'w'],  // stderr
        ];

        $process = proc_open($command, $descriptors, $pipes);

        if (!is_resource($process)) {
            throw new RuntimeException('Failed to start traceroute process');
        }

        // Close stdin — we don't send any input
        fclose($pipes[0]);

        // Read stdout with a timeout
        $output = '';
        $start  = time();
        while (!feof($pipes[1])) {
            if (time() - $start > 45) break; // 45 second hard timeout
            $output .= fread($pipes[1], 4096);
        }

        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        return $this->parseTraceroute($output);
    }

    // ── Parse traceroute output into structured hops ──────────
    private function parseTraceroute(string $output): array {

        $hops  = [];
        $lines = explode("\n", trim($output));

        foreach ($lines as $line) {

            $line = trim($line);

            // Skip the first line ("traceroute to github.com...")
            if (str_starts_with($line, 'traceroute')) continue;
            if (empty($line)) continue;

            // Traceroute line format:
            //  1  192.168.29.1  0.338 ms  0.463 ms  0.591 ms
            //  8  * * *
            // The hop number is always first
            if (!preg_match('/^\s*(\d+)\s+(.+)$/', $line, $matches)) {
                continue;
            }

            $hopNumber = (int) $matches[1];
            $rest      = trim($matches[2]);

            // Unresponsive hop — all probes timed out
            if (preg_match('/^\*[\s\*]*$/', $rest)) {
                $hops[] = [
                    'hop'          => $hopNumber,
                    'ip'           => null,
                    'rtt_ms'       => null,
                    'unresponsive' => true,
                ];
                continue;
            }

            // Extract IP address — first thing that looks like an IP
            $ip  = null;
            $rtt = null;

            if (preg_match('/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/', $rest, $ipMatch)) {
                $ip = $ipMatch[1];
            }

            // Extract first RTT value in milliseconds
            if (preg_match('/(\d+\.?\d*)\s+ms/', $rest, $rttMatch)) {
                $rtt = (float) $rttMatch[1];
            }

            $hops[] = [
                'hop'          => $hopNumber,
                'ip'           => $ip,
                'rtt_ms'       => $rtt,
                'unresponsive' => false,
            ];
        }

        return $hops;
    }

    // ── Geo-locate multiple IPs in one HTTP request ───────────
    private function geoLocateBatch(array $ips): array {

        // ip-api batch endpoint accepts a JSON array of queries
        $payload = json_encode(
            array_map(fn($ip) => [
                'query'  => $ip,
                'fields' => self::GEOIP_FIELDS,
            ], $ips)
        );

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => self::GEOIP_BATCH_URL,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_USERAGENT      => 'URLForensics/1.0',
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($response === false || $httpCode !== 200) {
            return []; // non-fatal — hops just won't have geo data
        }

        $data = json_decode($response, true);
        if (!is_array($data)) return [];

        // Key results by IP for easy lookup
        $byIp = [];
        foreach ($data as $result) {
            if (($result['status'] ?? '') === 'success') {
                $byIp[$result['query']] = $result;
            }
        }

        return $byIp;
    }

    // ── Merge geo data into hop records ──────────────────────
    private function enrichHops(array $hops, array $geoData): array {

        return array_map(function($hop) use ($geoData) {

            $ip = $hop['ip'];

            if (!$ip || $hop['unresponsive']) {
                return array_merge($hop, [
                    'country'      => null,
                    'country_code' => null,
                    'city'         => null,
                    'isp'          => null,
                    'asn'          => null,
                    'lat'          => null,
                    'lon'          => null,
                    'private'      => $hop['unresponsive'] ? false
                                    : $this->isPrivateIp($ip ?? ''),
                ]);
            }

            if ($this->isPrivateIp($ip)) {
                return array_merge($hop, [
                    'country'      => null,
                    'country_code' => null,
                    'city'         => 'Private Network',
                    'isp'          => null,
                    'asn'          => null,
                    'lat'          => null,
                    'lon'          => null,
                    'private'      => true,
                ]);
            }

            $geo = $geoData[$ip] ?? null;

            return array_merge($hop, [
                'country'      => $geo['country']      ?? null,
                'country_code' => $geo['countryCode']  ?? null,
                'city'         => $geo['city']         ?? null,
                'isp'          => $geo['isp']          ?? null,
                'asn'          => $geo['as']           ?? null,
                'lat'          => $geo['lat']          ?? null,
                'lon'          => $geo['lon']          ?? null,
                'private'      => false,
            ]);

        }, $hops);
    }

    // ── Analyse the full route ────────────────────────────────
    private function analyseRoute(array $hops): array {

        $countries    = [];
        $isps         = [];
        $rtts         = [];
        $unresponsive = 0;

        foreach ($hops as $hop) {
            if ($hop['unresponsive']) {
                $unresponsive++;
                continue;
            }
            if ($hop['rtt_ms'] !== null) {
                $rtts[] = $hop['rtt_ms'];
            }
            if ($hop['country'] && !in_array($hop['country'], $countries)) {
                $countries[] = $hop['country'];
            }
            if ($hop['isp'] && !in_array($hop['isp'], $isps)) {
                $isps[] = $hop['isp'];
            }
        }

        $avgRtt = !empty($rtts)
            ? round(array_sum($rtts) / count($rtts), 2)
            : null;

        $maxRtt = !empty($rtts) ? max($rtts) : null;

        // Suspicious routing: traffic leaving expected region
        // unnecessarily (e.g. Kolkata→London→Mumbai for an Indian site)
        $suspicious = $this->detectSuspiciousRouting($hops);

        return [
            'countries'   => $countries,
            'isps'        => $isps,
            'avg_rtt'     => $avgRtt,
            'max_rtt'     => $maxRtt,
            'unresponsive'=> $unresponsive,
            'suspicious'  => $suspicious,
        ];
    }

    // ── Detect suspicious routing patterns ───────────────────
    private function detectSuspiciousRouting(array $hops): array {

        $suspicious = [];
        $countries  = array_filter(array_column($hops, 'country_code'));

        // Flag if traffic exits and re-enters the same country
        // e.g. IN → SG → IN is inefficient and potentially suspicious
        $countrySequence = array_values(array_unique($countries));

        for ($i = 0; $i < count($countrySequence) - 2; $i++) {
            if ($countrySequence[$i] === $countrySequence[$i + 2]
                && $countrySequence[$i] !== $countrySequence[$i + 1]) {
                $suspicious[] = [
                    'type'   => 'traffic_hairpin',
                    'detail' => "Traffic left {$countrySequence[$i]} "
                              . "via {$countrySequence[$i+1]} "
                              . "then returned — inefficient routing",
                ];
            }
        }

        return $suspicious;
    }

    // ── Check if IP is in private/reserved range ──────────────
    private function isPrivateIp(string $ip): bool {
        foreach (self::PRIVATE_RANGES as $pattern) {
            if (preg_match($pattern, $ip)) return true;
        }
        return false;
    }

    // ── Score calculation ─────────────────────────────────────
    private function calculateScore(array $hops, array $analysis): int {

        $score = 100;

        // Too many hops — inefficient routing
        $hopCount = count($hops);
        if ($hopCount > 20)     $score -= 20;
        elseif ($hopCount > 15) $score -= 10;
        elseif ($hopCount > 10) $score -= 5;

        // High latency
        if ($analysis['avg_rtt'] !== null) {
            if ($analysis['avg_rtt'] > 300)     $score -= 25;
            elseif ($analysis['avg_rtt'] > 150) $score -= 15;
            elseif ($analysis['avg_rtt'] > 100) $score -= 5;
        }

        // Many unresponsive hops — harder to audit the path
        $unresponsiveRatio = $hopCount > 0
            ? $analysis['unresponsive'] / $hopCount
            : 0;
        if ($unresponsiveRatio > 0.5) $score -= 15;
        elseif ($unresponsiveRatio > 0.3) $score -= 5;

        // Suspicious routing
        $score -= count($analysis['suspicious']) * 10;

        return max(0, $score);
    }
}