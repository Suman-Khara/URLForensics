<?php

require_once __DIR__ . '/Engine.php';

class DNSResolutionTree extends Engine {

    private const DOH_URL = 'https://dns.google/resolve';

    // DNS record type numbers → human readable names
    private const RECORD_TYPES = [
        1  => 'A',
        2  => 'NS',
        5  => 'CNAME',
        6  => 'SOA',
        15 => 'MX',
        16 => 'TXT',
        28 => 'AAAA',
    ];

    protected function analyze(): array {

        $domain = $this->getDomain();

        // ── Walk the DNS tree level by level ─────────────────
        $tree  = [];
        $steps = 0;
        $anomalies = [];

        // ── Step 1: Root level ───────────────────────────────
        $rootStep = $this->queryLevel(
            name:        '.',
            type:        'NS',
            description: 'Root nameservers — the starting point of all DNS',
            level:       'root'
        );
        $tree[]  = $rootStep;
        $steps++;

        if (empty($rootStep['records'])) {
            $anomalies[] = [
                'type'     => 'root_query_failed',
                'severity' => 'high',
                'detail'   => 'Could not retrieve root nameservers'
            ];
        }

        // ── Step 2: TLD level ────────────────────────────────
        // Extract TLD from domain: github.com → com
        $tld     = $this->extractTLD($domain);
        $tldStep = $this->queryLevel(
            name:        $tld,
            type:        'NS',
            description: "TLD nameservers — who manages .{$tld} domains",
            level:       'tld'
        );
        $tree[]  = $tldStep;
        $steps++;

        if (empty($tldStep['records'])) {
            $anomalies[] = [
                'type'     => 'tld_query_failed',
                'severity' => 'high',
                'detail'   => "Could not retrieve .{$tld} TLD nameservers"
            ];
        }

        // ── Step 3: Second level domain (SLD) ────────────────
        // For sub.github.com this would be github.com
        // For github.com this is the same as the domain
        $sld     = $this->extractSLD($domain);
        $sldStep = null;

        if ($sld !== $domain) {
            $sldStep = $this->queryLevel(
                name:        $sld,
                type:        'NS',
                description: "Authoritative nameservers for {$sld}",
                level:       'sld'
            );
            $tree[]  = $sldStep;
            $steps++;
        }

        // ── Step 4: Authoritative nameservers ────────────────
        $authStep = $this->queryLevel(
            name:        $domain,
            type:        'NS',
            description: "Authoritative nameservers for {$domain}",
            level:       'authoritative'
        );
        $tree[]  = $authStep;
        $steps++;

        // Extract the authoritative nameservers for next step
        // Only extract actual NS records — ignore SOA responses
        // SOA is returned when no dedicated NS exists for a subdomain
        $authNameservers = array_column(
            array_filter(
                $authStep['records'],
                fn($r) => $r['type'] === 'NS'
            ),
            'data'
        );

        // ── Step 5: Final A record resolution ────────────────
        $aStep = $this->queryLevel(
            name:        $domain,
            type:        'A',
            description: "Final IP address resolution for {$domain}",
            level:       'resolution'
        );
        $tree[]  = $aStep;
        $steps++;

        // ── Step 6: Check for CNAME chain ────────────────────
        // Some domains resolve via CNAME before reaching A record
        $cnameStep = $this->queryLevel(
            name:        $domain,
            type:        'CNAME',
            description: "CNAME aliases for {$domain}",
            level:       'cname'
        );

        // Only include CNAME step if actual CNAME records exist
        // DNS returns SOA when CNAME doesn't exist — filter those out
        $actualCnames = array_filter(
            $cnameStep['records'],
            fn($r) => $r['type'] === 'CNAME'
        );

        if (!empty($actualCnames)) {
            $cnameStep['records'] = array_values($actualCnames);
            $tree[]  = $cnameStep;
            $steps++;
        }

        // ── Detect anomalies ──────────────────────────────────
        $anomalies = array_merge(
            $anomalies,
            $this->detectAnomalies($tree, $domain, $authNameservers)
        );

        // ── Score ─────────────────────────────────────────────
        $score = $this->calculateScore($tree, $anomalies, $steps);

        // ── Build summary ─────────────────────────────────────
        $finalIps = array_column($aStep['records'], 'data');

        return [
            'domain'          => $domain,
            'tld'             => $tld,
            'authoritative_ns'=> $authNameservers,
            'final_ips'       => $finalIps,
            'steps'           => $steps,
            'tree'            => $tree,
            'anomalies'       => $anomalies,
            'dnssec_indicated'=> $this->checkDNSSEC($authStep),
            'score'           => $score,
        ];
    }

    // ── Query one level of the DNS tree ───────────────────────
    private function queryLevel(
        string $name,
        string $type,
        string $description,
        string $level
    ): array {

        $start = microtime(true);

        $url = self::DOH_URL . '?' . http_build_query([
            'name' => $name,
            'type' => $type,
        ]);

        try {
            $response = $this->httpGet($url, 8);
        } catch (RuntimeException $e) {
            return [
                'level'       => $level,
                'name'        => $name,
                'type'        => $type,
                'description' => $description,
                'records'     => [],
                'ttl'         => null,
                'duration_ms' => $this->elapsed($start),
                'error'       => $e->getMessage(),
                'raw_comment' => null,
            ];
        }

        $records    = [];
        $ttl        = null;
        $rawComment = null;

        if ($response['status'] === 200 && !empty($response['body'])) {

            $data = json_decode($response['body'], true);

            // Google DoH sometimes includes a Comment field
            // telling us which authoritative server answered
            $rawComment = $data['Comment'] ?? null;

            if (!empty($data['Answer'])) {
                foreach ($data['Answer'] as $answer) {

                    $ttl       = $answer['TTL'] ?? null;
                    $typeNum   = $answer['type'] ?? 0;
                    $typeName  = self::RECORD_TYPES[$typeNum] ?? "TYPE{$typeNum}";

                    $records[] = [
                        'name' => rtrim($answer['name'] ?? '', '.'),
                        'type' => $typeName,
                        'ttl'  => $answer['TTL'] ?? null,
                        'data' => rtrim($answer['data'] ?? '', '.'),
                    ];
                }
            }

            // Authority section — present when answer is empty
            // but delegation exists
            if (empty($records) && !empty($data['Authority'])) {
                foreach ($data['Authority'] as $auth) {
                    $typeNum  = $auth['type'] ?? 0;
                    $typeName = self::RECORD_TYPES[$typeNum] ?? "TYPE{$typeNum}";

                    $records[] = [
                        'name' => rtrim($auth['name'] ?? '', '.'),
                        'type' => $typeName,
                        'ttl'  => $auth['TTL'] ?? null,
                        'data' => rtrim($auth['data'] ?? '', '.'),
                    ];
                }
            }
        }

        return [
            'level'       => $level,
            'name'        => $name,
            'type'        => $type,
            'description' => $description,
            'records'     => $records,
            'ttl'         => $ttl,
            'duration_ms' => $this->elapsed($start),
            'error'       => null,
            'raw_comment' => $rawComment,
        ];
    }

    // ── Extract TLD from domain ───────────────────────────────
    // github.com      → com
    // api.github.com  → com
    // github.co.uk    → co.uk (two-part TLD)
    private function extractTLD(string $domain): string {

        $parts = explode('.', $domain);

        // Known two-part TLDs
        $twoPartTLDs = ['co.uk', 'co.in', 'com.au', 'co.nz',
                        'org.uk', 'net.uk', 'ac.uk', 'gov.uk'];

        if (count($parts) >= 3) {
            $possibleTwopart = $parts[count($parts)-2]
                             . '.'
                             . $parts[count($parts)-1];

            if (in_array($possibleTwopart, $twoPartTLDs)) {
                return $possibleTwopart;
            }
        }

        return $parts[count($parts) - 1];
    }

    // ── Extract second level domain ───────────────────────────
    // api.github.com → github.com
    // github.com     → github.com (unchanged)
    private function extractSLD(string $domain): string {

        $tld   = $this->extractTLD($domain);
        $parts = explode('.', $domain);
        $tldPartCount = count(explode('.', $tld));

        if (count($parts) > $tldPartCount + 1) {
            // Has subdomain — return domain without subdomain
            return implode('.', array_slice($parts, -($tldPartCount + 1)));
        }

        return $domain;
    }

    // ── Detect anomalies in the resolution tree ───────────────
    private function detectAnomalies(
        array $tree,
        string $domain,
        array $authNameservers
    ): array {

        $anomalies = [];

        // ── Check 1: Empty authoritative NS ──────────────────────────
        // Subdomains inherit parent NS — only flag for apex domains
        $isSubdomain = $this->extractSLD($domain) !== $domain;

        if (empty($authNameservers) && !$isSubdomain) {
            $anomalies[] = [
                'type'     => 'no_authoritative_ns',
                'severity' => 'critical',
                'detail'   => 'No authoritative nameservers found for domain'
            ];
        }

        // ── Check 2: No A record ──────────────────────────────
        $aStep = $this->findStep($tree, 'resolution');
        if ($aStep && empty($aStep['records'])) {
            $anomalies[] = [
                'type'     => 'no_a_record',
                'severity' => 'high',
                'detail'   => 'Domain has no A record — not reachable via IPv4'
            ];
        }

        // ── Check 3: TTL inconsistency ────────────────────────
        // Authoritative NS TTL much lower than TLD TTL is unusual
        $tldStep  = $this->findStep($tree, 'tld');
        $authStep = $this->findStep($tree, 'authoritative');

        if ($tldStep && $authStep) {
            $tldTTL  = $tldStep['ttl']  ?? null;
            $authTTL = $authStep['ttl'] ?? null;

            if ($tldTTL && $authTTL && $authTTL < ($tldTTL * 0.1)) {
                $anomalies[] = [
                    'type'     => 'ttl_inconsistency',
                    'severity' => 'low',
                    'detail'   => "Auth NS TTL ({$authTTL}s) much lower than TLD TTL ({$tldTTL}s)"
                ];
            }
        }

        // ── Check 4: Single point of failure ─────────────────
        // Only one authoritative nameserver = no redundancy
        if (count($authNameservers) === 1) {
            $anomalies[] = [
                'type'     => 'single_nameserver',
                'severity' => 'medium',
                'detail'   => 'Only one authoritative nameserver — no redundancy'
            ];
        }

        // ── Check 5: Mixed DNS providers ─────────────────────
        // Having NS from different providers can indicate
        // a transition or misconfiguration
        if (count($authNameservers) > 1) {
            $providers = array_unique(array_map(
                fn($ns) => $this->extractNSProvider($ns),
                $authNameservers
            ));

            if (count($providers) > 1) {
                $anomalies[] = [
                    'type'     => 'mixed_dns_providers',
                    'severity' => 'low',
                    'detail'   => 'Nameservers from multiple providers: '
                                . implode(', ', $providers)
                ];
            }
        }

        return $anomalies;
    }

    // ── Extract DNS provider name from nameserver hostname ────
    // ns1.github.com         → github
    // dns1.p08.nsone.net     → nsone
    // ns-1283.awsdns-32.org  → awsdns (AWS Route53)
    private function extractNSProvider(string $ns): string {

        $parts = explode('.', $ns);

        // Known provider patterns
        if (str_contains($ns, 'awsdns'))    return 'AWS Route53';
        if (str_contains($ns, 'nsone'))     return 'NS1';
        if (str_contains($ns, 'cloudflare'))return 'Cloudflare';
        if (str_contains($ns, 'googledom')) return 'Google';
        if (str_contains($ns, 'akam'))      return 'Akamai';
        if (str_contains($ns, 'ultradns'))  return 'UltraDNS';
        if (str_contains($ns, 'dynect'))    return 'Dyn';

        // Fall back to second-to-last part of hostname
        // ns1.github.com → github
        return $parts[max(0, count($parts) - 2)] ?? $ns;
    }

    // ── Check for DNSSEC indicators ───────────────────────────
    // DNSSEC signs DNS responses cryptographically
    // AD=true in the response means the resolver validated DNSSEC
    private function checkDNSSEC(array $authStep): bool {
        // We infer DNSSEC from the AD (Authenticated Data) flag
        // This is set by the resolver when DNSSEC validation passed
        // We can't check it directly from DoH response structure
        // but presence of DNSKEY records would confirm it
        return false; // enhancement: query for DNSKEY record
    }

    // ── Find a step in the tree by level name ─────────────────
    private function findStep(array $tree, string $level): ?array {
        foreach ($tree as $step) {
            if ($step['level'] === $level) return $step;
        }
        return null;
    }

    // ── Score calculation ─────────────────────────────────────
    private function calculateScore(
        array $tree,
        array $anomalies,
        int $steps
    ): int {

        $score = 100;

        // Penalise by anomaly severity
        foreach ($anomalies as $anomaly) {
            $score -= match($anomaly['severity']) {
                'critical' => 40,
                'high'     => 20,
                'medium'   => 10,
                'low'      => 5,
                default    => 0,
            };
        }

        // Penalise failed steps
        foreach ($tree as $step) {
            if (!empty($step['error'])) {
                $score -= 15;
            }
        }

        return max(0, $score);
    }
}