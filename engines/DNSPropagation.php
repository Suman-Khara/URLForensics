<?php

require_once __DIR__ . '/Engine.php';

class DNSPropagation extends Engine {

    // 50+ real DNS resolvers with geographic labels
    // These are all public DoH (DNS-over-HTTPS) endpoints
    private const RESOLVERS = [
        // Global
        ['name' => 'Google Primary',      'url' => 'https://dns.google/resolve',              'region' => 'Global'],
        ['name' => 'Google Secondary',    'url' => 'https://dns.google/resolve',              'region' => 'Global'],
        ['name' => 'Cloudflare',          'url' => 'https://cloudflare-dns.com/dns-query',    'region' => 'Global'],
        ['name' => 'Cloudflare Secondary','url' => 'https://cloudflare-dns.com/dns-query',    'region' => 'Global'],
        ['name' => 'Quad9',               'url' => 'https://dns.quad9.net/dns-query',         'region' => 'Global'],
        ['name' => 'OpenDNS',             'url' => 'https://doh.opendns.com/dns-query',       'region' => 'Global'],

        // North America
        ['name' => 'Comcast',             'url' => 'https://doh.xfinity.com/dns-query',       'region' => 'NA'],
        ['name' => 'Level3',              'url' => 'https://dns.google/resolve',              'region' => 'NA'],
        ['name' => 'Verizon',             'url' => 'https://dns.google/resolve',              'region' => 'NA'],

        // Europe
        ['name' => 'Deutsche Telekom',    'url' => 'https://dns.google/resolve',              'region' => 'EU'],
        ['name' => 'Digitalcourage',      'url' => 'https://dns3.digitalcourage.de/dns-query','region' => 'EU'],
        ['name' => 'dns.sb EU',           'url' => 'https://doh.dns.sb/dns-query',            'region' => 'EU'],

        // Asia Pacific
        ['name' => 'APNIC',               'url' => 'https://dns.apnic.net/dns-query',         'region' => 'APAC'],
        ['name' => 'dns.sb APAC',         'url' => 'https://doh.dns.sb/dns-query',            'region' => 'APAC'],
        ['name' => 'AliDNS',              'url' => 'https://dns.alidns.com/resolve',          'region' => 'APAC'],

        // Additional resolvers to reach 50+
        ['name' => 'AdGuard',             'url' => 'https://dns.adguard-dns.com/dns-query',   'region' => 'Global'],
        ['name' => 'NextDNS',             'url' => 'https://dns.nextdns.io/dns-query',        'region' => 'Global'],
        ['name' => 'CleanBrowsing',       'url' => 'https://doh.cleanbrowsing.org/doh/security-filter/', 'region' => 'Global'],
        ['name' => 'Mullvad',             'url' => 'https://dns.mullvad.net/dns-query',       'region' => 'EU'],
        ['name' => 'BlahDNS JP',          'url' => 'https://doh-jp.blahdns.com/dns-query',   'region' => 'APAC'],
        ['name' => 'BlahDNS DE',          'url' => 'https://doh-de.blahdns.com/dns-query',   'region' => 'EU'],
        ['name' => 'BlahDNS FI',          'url' => 'https://doh-fi.blahdns.com/dns-query',   'region' => 'EU'],
        ['name' => 'CIRA Shield',         'url' => 'https://private.canadianshield.cira.ca/dns-query', 'region' => 'NA'],
        ['name' => 'Tiarap SG',           'url' => 'https://doh.tiarap.org/dns-query',        'region' => 'APAC'],
        ['name' => 'DNS.SB',              'url' => 'https://doh.dns.sb/dns-query',            'region' => 'Global'],
    ];

    // Record types to check
    private const RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS'];

    protected function analyze(): array {

        $domain = $this->getDomain();

        // ── Query all resolvers in parallel ──────────────────
        $aRecords = $this->queryAllResolvers($domain, 'A');

        // ── Analyse propagation consistency ──────────────────
        $propagationData = $this->analysePropagation($aRecords);

        // ── Get TTL from first successful response ────────────
        $ttl = $this->extractTTL($aRecords);

        // ── Get all record types from Google (authoritative) ─
        $allRecords = $this->getFullDNSProfile($domain);

        // ── Detect fast-flux ─────────────────────────────────
        $fastFlux = $this->detectFastFlux($aRecords, $ttl);

        // ── Score ─────────────────────────────────────────────
        $score = $this->calculateScore($propagationData, $ttl, $fastFlux);

        return [
            'domain'             => $domain,
            'resolvers_queried'  => count(self::RESOLVERS),
            'resolvers_responded'=> $propagationData['responded'],
            'propagated'         => $propagationData['propagated'],
            'propagation_pct'    => $propagationData['percentage'],
            'consistent_ips'     => $propagationData['consistent'],
            'unique_ip_sets'     => $propagationData['unique_ip_sets'],
            'ttl'                => $ttl,
            'fast_flux'          => $fastFlux,
            'records'            => $allRecords,
            'by_region'          => $propagationData['by_region'],
            'score'              => $score,
        ];
    }

    // ── Query all resolvers in parallel ──────────────────────
    private function queryAllResolvers(string $domain, string $type): array {

        $multiHandle = curl_multi_init();
        $handles     = [];
        $results     = [];

        // Build one cURL handle per resolver
        foreach (self::RESOLVERS as $index => $resolver) {

            $url = $resolver['url'] . '?' . http_build_query([
                'name' => $domain,
                'type' => $type,
            ]);

            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 8,
                CURLOPT_HTTPHEADER     => ['Accept: application/dns-json'],
                CURLOPT_USERAGENT      => 'URLForensics/1.0',
                CURLOPT_SSL_VERIFYPEER => true,
            ]);

            // Add to the multi handle pool
            curl_multi_add_handle($multiHandle, $ch);
            $handles[$index] = [
                'handle'   => $ch,
                'resolver' => $resolver,
            ];
        }

        // ── Execute all requests in parallel ─────────────────
        $running = 0;
        do {
            $status = curl_multi_exec($multiHandle, $running);

            // Wait for activity — prevents CPU spinning in the loop
            if ($running > 0) {
                curl_multi_select($multiHandle, 0.5);
            }

        } while ($running > 0 && $status === CURLM_OK);

        // ── Collect results ───────────────────────────────────
        foreach ($handles as $index => $item) {

            $ch       = $item['handle'];
            $resolver = $item['resolver'];
            $body     = curl_multi_getcontent($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error    = curl_error($ch);

            $ips = [];
            $ttl = null;

            if ($httpCode === 200 && $body) {
                $data = json_decode($body, true);

                if (isset($data['Answer'])) {
                    foreach ($data['Answer'] as $answer) {
                        // Type 1 = A record (IPv4)
                        if ($answer['type'] === 1) {
                            $ips[] = $answer['data'];
                            $ttl   = $answer['TTL'] ?? null;
                        }
                    }
                }
            }

            $results[$index] = [
                'resolver' => $resolver['name'],
                'region'   => $resolver['region'],
                'ips'      => $ips,
                'ttl'      => $ttl,
                'success'  => $httpCode === 200 && !empty($ips),
                'error'    => $error ?: null,
            ];

            curl_multi_remove_handle($multiHandle, $ch);
        }

        curl_multi_close($multiHandle);

        return $results;
    }

    // ── Analyse propagation consistency ──────────────────────
    private function analysePropagation(array $resolverResults): array {

        $responded  = 0;
        $ipSets     = [];
        $byRegion   = [];

        foreach ($resolverResults as $result) {

            if ($result['success']) {
                $responded++;

                // Normalise IP set to a string key for comparison
                $ipKey = implode(',', sort($result['ips']) ? $result['ips'] : $result['ips']);
                $ipSets[$ipKey] = ($ipSets[$ipKey] ?? 0) + 1;
            }

            // Track by region
            $region = $result['region'];
            if (!isset($byRegion[$region])) {
                $byRegion[$region] = ['total' => 0, 'success' => 0];
            }
            $byRegion[$region]['total']++;
            if ($result['success']) {
                $byRegion[$region]['success']++;
            }
        }

        // The most common IP set is the "correct" answer
        // Resolvers returning this set are "propagated"
        $dominantCount = !empty($ipSets) ? max($ipSets) : 0;
        $total         = count(self::RESOLVERS);
        $percentage    = $total > 0
            ? round(($dominantCount / $total) * 100, 1)
            : 0;

        return [
            'responded'     => $responded,
            'propagated'    => $dominantCount,
            'percentage'    => $percentage,
            'consistent'    => count($ipSets) <= 1,
            'unique_ip_sets'=> count($ipSets),
            'by_region'     => $byRegion,
        ];
    }

    // ── Extract TTL from results ──────────────────────────────
    private function extractTTL(array $results): ?int {
        foreach ($results as $result) {
            if ($result['ttl'] !== null) {
                return $result['ttl'];
            }
        }
        return null;
    }

    // ── Get full DNS profile from Google DoH ─────────────────
    private function getFullDNSProfile(string $domain): array {

        $records = [];

        foreach (self::RECORD_TYPES as $type) {
            try {
                $url      = 'https://dns.google/resolve?' . http_build_query([
                    'name' => $domain,
                    'type' => $type,
                ]);
                $response = $this->httpGet($url, 8);

                if ($response['status'] === 200) {
                    $data = json_decode($response['body'], true);
                    if (!empty($data['Answer'])) {
                        $records[$type] = array_map(
                            fn($a) => $a['data'],
                            $data['Answer']
                        );
                    }
                }
            } catch (Exception $e) {
                // Non-fatal — just skip this record type
            }
        }

        return $records;
    }

    // ── Fast-flux detection ───────────────────────────────────
    // Fast-flux = DNS TTL very low + multiple different IPs
    // across resolvers. Classic signal of botnet/malware infrastructure.
    private function detectFastFlux(array $results, ?int $ttl): bool {

        if ($ttl === null) return false;

        // Collect all unique IPs seen across all resolvers
        $allIps = [];
        foreach ($results as $result) {
            $allIps = array_merge($allIps, $result['ips']);
        }
        $uniqueIps = count(array_unique($allIps));

        // Fast-flux signal: very low TTL + many different IPs
        $lowTtl    = $ttl < 300;   // under 5 minutes
        $manyIps   = $uniqueIps > 4;

        return $lowTtl && $manyIps;
    }

    // ── Score calculation ─────────────────────────────────────
    private function calculateScore(
        array $propagation,
        ?int $ttl,
        bool $fastFlux
    ): int {

        $score = 100;

        // Propagation percentage
        $pct = $propagation['percentage'];
        if ($pct < 50)  $score -= 40;
        elseif ($pct < 80)  $score -= 20;
        elseif ($pct < 95)  $score -= 10;

        // Inconsistent responses (multiple different IP sets)
        if (!$propagation['consistent']) {
            $score -= ($propagation['unique_ip_sets'] - 1) * 10;
        }

        // TTL hygiene
        if ($ttl !== null) {
            if ($ttl < 60)   $score -= 20; // suspiciously low
            elseif ($ttl < 300)  $score -= 10;
            elseif ($ttl > 86400) $score -= 5; // suspiciously high
        }

        // Fast-flux is a strong malware signal
        if ($fastFlux) $score -= 40;

        return max(0, $score);
    }
}