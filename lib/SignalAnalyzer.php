<?php

class SignalAnalyzer {

    // Signal severity levels
    private const CRITICAL = 'critical'; // strong malicious indicator
    private const HIGH     = 'high';     // serious concern
    private const MEDIUM   = 'medium';   // worth investigating
    private const LOW      = 'low';      // minor issue
    private const GOOD     = 'good';     // positive signal

    // Engine results keyed by engine name
    private array $engines;

    public function __construct(array $engines) {
        $this->engines = $engines;
    }

    // ── Main analysis method ──────────────────────────────────
    public function analyze(): array {

        $signals = [];

        // Run each engine's signal checks
        $signals = array_merge($signals, $this->analyzeRedirectTrail());
        $signals = array_merge($signals, $this->analyzeDNSPropagation());
        $signals = array_merge($signals, $this->analyzeTLSTimeline());
        $signals = array_merge($signals, $this->analyzeCookieAudit());
        $signals = array_merge($signals, $this->analyzePacketJourney());
        $signals = array_merge($signals, $this->analyzeDNSResolution());

        // Compute overall verdict from signals
        $verdict = $this->computeVerdict($signals);

        return [
            'signals' => $signals,
            'verdict' => $verdict,
        ];
    }

    // ── Redirect Trail signals ────────────────────────────────
    private function analyzeRedirectTrail(): array {

        $signals = [];
        $data    = $this->engines['redirect_trail']['data'] ?? null;

        if (!$data) return $signals;

        // Long redirect chains are suspicious
        $hopCount = $data['hop_count'] ?? 0;
        if ($hopCount >= 6) {
            $signals[] = $this->signal(
                self::HIGH,
                'redirect_trail',
                'long_redirect_chain',
                "Unusually long redirect chain ({$hopCount} hops) — possible cloaking or traffic laundering"
            );
        } elseif ($hopCount >= 3) {
            $signals[] = $this->signal(
                self::MEDIUM,
                'redirect_trail',
                'moderate_redirect_chain',
                "{$hopCount} redirect hops — verify each destination is expected"
            );
        } else {
            $signals[] = $this->signal(
                self::GOOD,
                'redirect_trail',
                'clean_redirect_chain',
                'Clean redirect chain — ' . ($hopCount === 1 ? 'no redirects' : "{$hopCount} hops, all expected")
            );
        }

        // Tracking parameters
        $trackers = $data['trackers'] ?? [];
        if (count($trackers) >= 3) {
            $signals[] = $this->signal(
                self::MEDIUM,
                'redirect_trail',
                'heavy_tracking',
                count($trackers) . ' tracking parameters detected: ' . implode(', ', array_slice($trackers, 0, 3))
            );
        } elseif (count($trackers) > 0) {
            $signals[] = $this->signal(
                self::LOW,
                'redirect_trail',
                'tracking_params',
                'Tracking parameters present: ' . implode(', ', $trackers)
            );
        }

        // Mixed HTTP/HTTPS
        $risk = $data['privacy_risk'] ?? 'none';
        if ($risk === 'high' || $risk === 'medium') {
            $signals[] = $this->signal(
                self::MEDIUM,
                'redirect_trail',
                'mixed_protocols',
                'Redirect chain mixes HTTP and HTTPS — data exposed in transit'
            );
        }

        // Final status not 200
        $finalStatus = $data['final_status'] ?? 0;
        if ($finalStatus !== 200) {
            $signals[] = $this->signal(
                self::LOW,
                'redirect_trail',
                'non_200_final',
                "Final destination returned HTTP {$finalStatus} — URL may be broken or redirecting incorrectly"
            );
        }

        return $signals;
    }

    // ── DNS Propagation signals ───────────────────────────────
    private function analyzeDNSPropagation(): array {

        $signals = [];
        $data    = $this->engines['dns_propagation']['data'] ?? null;

        if (!$data) return $signals;

        // Fast-flux is a strong malware signal
        if ($data['fast_flux'] ?? false) {
            $signals[] = $this->signal(
                self::CRITICAL,
                'dns_propagation',
                'fast_flux',
                'Fast-flux DNS detected — IP addresses change rapidly, consistent with botnet or malware infrastructure'
            );
        }

        // Propagation percentage
        $pct = $data['propagation_pct'] ?? 0;
        if ($pct < 50) {
            $signals[] = $this->signal(
                self::LOW,
                'dns_propagation',
                'low_propagation',
                "Only {$pct}% of resolvers return consistent answers — may indicate Anycast routing, recent DNS changes, or a newly registered domain"
            );
        } elseif ($pct >= 90) {
            $signals[] = $this->signal(
                self::GOOD,
                'dns_propagation',
                'high_propagation',
                "DNS fully propagated ({$pct}% of resolvers consistent)"
            );
        }

        // Very low TTL without fast-flux (could indicate instability)
        $ttl = $data['ttl'] ?? null;
        if ($ttl !== null && $ttl < 60 && !($data['fast_flux'] ?? false)) {
            $signals[] = $this->signal(
                self::LOW,
                'dns_propagation',
                'very_low_ttl',
                "Unusually low DNS TTL ({$ttl}s) — domain infrastructure may be unstable or in transition"
            );
        }

        return $signals;
    }

    // ── TLS Timeline signals ──────────────────────────────────
    private function analyzeTLSTimeline(): array {

        $signals = [];
        $data    = $this->engines['tls_timeline']['data'] ?? null;

        if (!$data) return $signals;

        $liveCert = $data['live_cert'] ?? [];

        // No valid certificate
        if (!($liveCert['valid'] ?? false)) {
            $signals[] = $this->signal(
                self::CRITICAL,
                'tls_timeline',
                'no_valid_cert',
                'No valid TLS certificate — connection is not secure'
            );
            return $signals;
        }

        // Expired certificate
        if ($liveCert['expired'] ?? false) {
            $signals[] = $this->signal(
                self::CRITICAL,
                'tls_timeline',
                'expired_cert',
                'TLS certificate has expired — site owner is negligent or domain is abandoned'
            );
        }

        // Expiring soon
        if ($liveCert['expiring_soon'] ?? false) {
            $days = $liveCert['days_remaining'] ?? 0;
            $signals[] = $this->signal(
                self::MEDIUM,
                'tls_timeline',
                'expiring_soon',
                "Certificate expires in {$days} days — site may become inaccessible soon"
            );
        }

        // Very young certificate on established-looking domain
        $historyCount = $data['history_count'] ?? 0;
        $validFrom    = $liveCert['valid_from'] ?? null;

        if ($validFrom) {
            $certAgeDays = (int) round(
                (time() - strtotime($validFrom)) / 86400
            );

        // Only flag young cert if we actually have CT log data
        // history_count = 0 could mean crt.sh was unavailable
        // Only flag if cert is young AND we have confirmed no history
        // (i.e. crt.sh responded but returned nothing)
        $crtshAvailable = isset($data['history_count']) && $data['history_count'] !== null;

        if ($certAgeDays < 30 && $historyCount === 0 && $crtshAvailable) {
            // Check if this looks like a crt.sh failure vs genuine no history
            // If the live cert itself is valid and well-configured, 
            // reduce severity
            $certWellConfigured = ($liveCert['san_count'] ?? 0) > 0
                            && ($liveCert['secure'] ?? true);

            if ($certWellConfigured) {
                $signals[] = $this->signal(
                    self::LOW,
                    'tls_timeline',
                    'young_cert_no_history',
                    "Certificate issued {$certAgeDays} days ago — no CT log history found (may indicate CT log service was unavailable)"
                );
            } else {
                $signals[] = $this->signal(
                    self::HIGH,
                    'tls_timeline',
                    'very_young_cert',
                    "Certificate issued only {$certAgeDays} days ago with no verifiable history"
                );
            }
        } elseif ($certAgeDays < 30 && $historyCount >= 1) {
            $signals[] = $this->signal(
                self::LOW,
                'tls_timeline',
                'young_cert',
                "Certificate recently renewed ({$certAgeDays} days ago)"
            );
        } elseif ($certAgeDays < 30) {
                $signals[] = $this->signal(
                    self::LOW,
                    'tls_timeline',
                    'young_cert',
                    "Certificate recently renewed ({$certAgeDays} days ago)"
                );
            }
        }

        // Good cert history
        if ($historyCount >= 3) {
            $signals[] = $this->signal(
                self::GOOD,
                'tls_timeline',
                'established_cert_history',
                "Established certificate history ({$historyCount} certs) — domain has been active for some time"
            );
        }

        // Anomalies from the engine
        $anomalies = $data['anomalies'] ?? [];
        foreach ($anomalies as $anomaly) {
            if (in_array($anomaly['type'], ['expired', 'expiring_soon'])) {
                continue; // already handled above
            }
            $severity = match($anomaly['severity']) {
                'critical' => self::CRITICAL,
                'high'     => self::HIGH,
                'medium'   => self::MEDIUM,
                default    => self::LOW,
            };
            $signals[] = $this->signal(
                $severity,
                'tls_timeline',
                $anomaly['type'],
                $anomaly['detail']
            );
        }

        return $signals;
    }

    // ── Cookie Audit signals ──────────────────────────────────
    private function analyzeCookieAudit(): array {

        $signals = [];
        $data    = $this->engines['cookie_audit']['data'] ?? null;

        if (!$data) return $signals;

        $trackingCount = $data['tracking_cookies'] ?? 0;
        $totalCookies  = $data['total_cookies']    ?? 0;
        $grade         = $data['privacy_grade']    ?? 'A';
        $trackers      = $data['trackers_found']   ?? [];

        // Many tracking cookies
        if ($trackingCount >= 5) {
            $signals[] = $this->signal(
                self::HIGH,
                'cookie_audit',
                'heavy_tracking_cookies',
                "{$trackingCount} tracking cookies detected — extensive user profiling in place"
            );
        } elseif ($trackingCount >= 2) {
            $signals[] = $this->signal(
                self::MEDIUM,
                'cookie_audit',
                'tracking_cookies',
                "{$trackingCount} tracking cookies: " . implode(', ', $trackers)
            );
        } elseif ($trackingCount === 0 && $totalCookies > 0) {
            $signals[] = $this->signal(
                self::GOOD,
                'cookie_audit',
                'no_tracking_cookies',
                'No tracking cookies detected'
            );
        }

        // Poor cookie security
        if ($grade === 'F') {
            $signals[] = $this->signal(
                self::HIGH,
                'cookie_audit',
                'poor_cookie_security',
                'Cookie security grade F — majority of cookies are tracking and poorly secured'
            );
        } elseif ($grade === 'D') {
            $signals[] = $this->signal(
                self::MEDIUM,
                'cookie_audit',
                'weak_cookie_security',
                'Cookie security grade D — significant tracking and security issues'
            );
        }

        return $signals;
    }

    // ── Packet Journey signals ────────────────────────────────
    private function analyzePacketJourney(): array {

        $signals = [];
        $data    = $this->engines['packet_journey']['data'] ?? null;

        if (!$data) return $signals;

        $countries = $data['countries'] ?? [];
        $avgRtt    = $data['avg_rtt_ms'] ?? null;
        $suspicious = $data['suspicious_routing'] ?? [];

        // Suspicious routing patterns
        if (!empty($suspicious)) {
            $signals[] = $this->signal(
                self::MEDIUM,
                'packet_journey',
                'suspicious_routing',
                'Suspicious network routing detected: ' . $suspicious[0]['detail']
            );
        }

        // High latency can indicate routing through unexpected regions
        if ($avgRtt !== null && $avgRtt > 300) {
            $signals[] = $this->signal(
                self::LOW,
                'packet_journey',
                'high_latency',
                "High average latency ({$avgRtt}ms) — server may be geographically distant or routing is inefficient"
            );
        }

        // Traffic routing through high-risk jurisdictions
        $highRiskCountries = ['CN', 'RU', 'KP', 'IR'];
        $hopCountries = array_column($data['hops'] ?? [], 'country_code');
        $riskCountries = array_intersect($hopCountries, $highRiskCountries);

        if (!empty($riskCountries)) {
            $signals[] = $this->signal(
                self::HIGH,
                'packet_journey',
                'high_risk_routing',
                'Traffic routes through jurisdictions with known surveillance laws: ' .
                implode(', ', array_unique($riskCountries))
            );
        }

        return $signals;
    }

    // ── DNS Resolution signals ────────────────────────────────
    private function analyzeDNSResolution(): array {

        $signals = [];
        $data    = $this->engines['dns_resolution_tree']['data'] ?? null;

        if (!$data) return $signals;

        $anomalies = $data['anomalies'] ?? [];
        $authNS    = $data['authoritative_ns'] ?? [];
        $finalIPs  = $data['final_ips'] ?? [];

        // No authoritative nameservers — very suspicious
        if (empty($authNS) && !empty($data['domain'])) {
            $isSubdomain = substr_count($data['domain'], '.') > 1;
            if (!$isSubdomain) {
                $signals[] = $this->signal(
                    self::CRITICAL,
                    'dns_resolution_tree',
                    'no_nameservers',
                    'No authoritative nameservers found — domain may be in the process of being seized or abandoned'
                );
            }
        }

        // No IP resolution
        if (empty($finalIPs)) {
            $signals[] = $this->signal(
                self::HIGH,
                'dns_resolution_tree',
                'no_ip_resolution',
                'Domain does not resolve to any IP address — not reachable'
            );
        }

        // DNS anomalies from the engine
        foreach ($anomalies as $anomaly) {
            if ($anomaly['type'] === 'mixed_dns_providers') {
                // Multiple providers is common for large sites (resilience)
                // Only flag if the detail mentions more than 2 providers
                $providerCount = substr_count($anomaly['detail'], ',') + 1;
                if ($providerCount > 2) {
                    $signals[] = $this->signal(
                        self::LOW,
                        'dns_resolution_tree',
                        'mixed_dns_providers',
                        $anomaly['detail']
                    );
                }
                // If 2 providers: skip — common resilience pattern, not suspicious
            } elseif ($anomaly['type'] === 'ttl_inconsistency') {
                $signals[] = $this->signal(
                    self::LOW,
                    'dns_resolution_tree',
                    'ttl_inconsistency',
                    $anomaly['detail']
                );
            } else {
                $severity = match($anomaly['severity']) {
                    'critical' => self::CRITICAL,
                    'high'     => self::HIGH,
                    'medium'   => self::MEDIUM,
                    default    => self::LOW,
                };
                $signals[] = $this->signal(
                    $severity,
                    'dns_resolution_tree',
                    $anomaly['type'],
                    $anomaly['detail']
                );
            }
        }

        return $signals;
    }

    // ── Compute overall verdict ───────────────────────────────
    private function computeVerdict(array $signals): array {

        $criticalCount = 0;
        $highCount     = 0;
        $mediumCount   = 0;
        $goodCount     = 0;

        foreach ($signals as $signal) {
            match($signal['severity']) {
                self::CRITICAL => $criticalCount++,
                self::HIGH     => $highCount++,
                self::MEDIUM   => $mediumCount++,
                self::GOOD     => $goodCount++,
                default        => null,
            };
        }

        if ($criticalCount > 0) {
            return [
                'level'   => 'critical',
                'label'   => 'High Risk',
                'message' => 'Strong indicators of malicious or compromised infrastructure detected. Do not proceed.',
                'color'   => 'danger',
            ];
        }

        if ($highCount >= 2) {
            return [
                'level'   => 'high',
                'label'   => 'Suspicious',
                'message' => 'Multiple concerning signals detected. Investigate before trusting this URL.',
                'color'   => 'danger',
            ];
        }

        if ($highCount === 1 || $mediumCount >= 3) {
            return [
                'level'   => 'medium',
                'label'   => 'Caution Advised',
                'message' => 'Some suspicious signals detected. Proceed with caution.',
                'color'   => 'warning',
            ];
        }

        if ($mediumCount >= 1) {
            return [
                'level'   => 'low',
                'label'   => 'Mostly Safe',
                'message' => 'Minor concerns noted. Generally safe but worth reviewing the details.',
                'color'   => 'warning',
            ];
        }

        return [
            'level'   => 'safe',
            'label'   => 'Low Risk',
            'message' => 'No significant malicious signals detected.',
            'color'   => 'success',
        ];
    }

    // ── Signal factory ────────────────────────────────────────
    private function signal(
        string $severity,
        string $engine,
        string $type,
        string $detail
    ): array {
        return [
            'severity' => $severity,
            'engine'   => $engine,
            'type'     => $type,
            'detail'   => $detail,
        ];
    }
}