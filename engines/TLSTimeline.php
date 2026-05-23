<?php

require_once __DIR__ . '/Engine.php';

class TLSTimeline extends Engine {

    // crt.sh API — public certificate transparency log
    private const CRTSH_API = 'https://crt.sh/?q=%s&output=json';

    // How many days before expiry we consider a cert "expiring soon"
    private const EXPIRY_WARNING_DAYS = 30;

    // A cert valid for less than this many days is suspicious
    private const MIN_NORMAL_VALIDITY_DAYS = 30;

    protected function analyze(): array {

        $domain = $this->getDomain();

        // ── 1. Fetch the live certificate ────────────────────
        $liveCert = $this->fetchLiveCertificate($domain);

        // ── 2. Fetch certificate history from crt.sh ────────
        $history  = $this->fetchCertHistory($domain);

        // ── 3. Analyse the history for anomalies ────────────
        $anomalies = $this->detectAnomalies($history, $liveCert);

        // ── 4. Compute hygiene score ─────────────────────────
        $score = $this->calculateScore($liveCert, $history, $anomalies);

        return [
            'domain'        => $domain,
            'live_cert'     => $liveCert,
            'history_count' => count($history),
            'history'       => array_slice($history, 0, 10), // last 10 certs
            'anomalies'     => $anomalies,
            'score'         => $score,
        ];
    }

    // ── Fetch live certificate from the server ───────────────
    private function fetchLiveCertificate(string $domain): array {

        // stream_context lets PHP open a TLS connection and
        // capture the certificate the server presents
        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,   // grab the cert
                'verify_peer'       => true,   // verify it's valid
                'verify_peer_name'  => true,
                'cafile'            => '/etc/ssl/certs/ca-certificates.crt',
            ]
        ]);

        // Suppress warnings — we handle errors manually
        $socket = @stream_socket_client(
            "ssl://{$domain}:443",
            $errno,
            $errstr,
            10,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!$socket) {
            // Try without peer verification as fallback
            // (captures cert data even if chain is broken)
            $fallbackContext = stream_context_create([
                'ssl' => [
                    'capture_peer_cert' => true,
                    'verify_peer'       => false,
                    'verify_peer_name'  => false,
                ]
            ]);

            $socket = @stream_socket_client(
                "ssl://{$domain}:443",
                $errno,
                $errstr,
                10,
                STREAM_CLIENT_CONNECT,
                $fallbackContext
            );

            if (!$socket) {
                return [
                    'error'   => "Could not connect (errno {$errno}): {$errstr}",
                    'valid'   => false,
                ];
            }
        }

        // Extract the certificate from the stream context
        $params = stream_context_get_params($socket);
        $cert   = $params['options']['ssl']['peer_certificate'] ?? null;
        fclose($socket);

        if (!$cert) {
            return ['error' => 'No certificate returned', 'valid' => false];
        }

        // Parse the certificate into a readable array
        $certInfo = openssl_x509_parse($cert);

        if (!$certInfo) {
            return ['error' => 'Could not parse certificate', 'valid' => false];
        }

        // Extract the fields we care about
        $validFrom  = date('Y-m-d', $certInfo['validFrom_time_t']);
        $validTo    = date('Y-m-d', $certInfo['validTo_time_t']);
        $now        = time();
        $daysLeft   = (int) round(
            ($certInfo['validTo_time_t'] - $now) / 86400
        );
        $totalDays  = (int) round(
            ($certInfo['validTo_time_t'] - $certInfo['validFrom_time_t']) / 86400
        );

        // Extract Subject Alternative Names (the domains this cert covers)
        $sans = [];
        if (isset($certInfo['extensions']['subjectAltName'])) {
            preg_match_all('/DNS:([^\s,]+)/', $certInfo['extensions']['subjectAltName'], $matches);
            $sans = $matches[1] ?? [];
        }

        // Extract issuer organisation name
        $issuer = $certInfo['issuer']['O']
               ?? $certInfo['issuer']['CN']
               ?? 'Unknown';

        return [
            'valid'        => true,
            'subject'      => $certInfo['subject']['CN'] ?? $domain,
            'issuer'       => $issuer,
            'issuer_cn'    => $certInfo['issuer']['CN'] ?? 'Unknown',
            'valid_from'   => $validFrom,
            'valid_to'     => $validTo,
            'days_remaining' => $daysLeft,
            'total_validity_days' => $totalDays,
            'expired'      => $daysLeft < 0,
            'expiring_soon'=> $daysLeft >= 0 && $daysLeft <= self::EXPIRY_WARNING_DAYS,
            'sans'         => $sans,
            'san_count'    => count($sans),
            'serial'       => $certInfo['serialNumberHex'] ?? null,
        ];
    }

    // ── Fetch certificate history from crt.sh ────────────────
    private function fetchCertHistory(string $domain): array {

        $url = sprintf(self::CRTSH_API, urlencode($domain));

        try {
            $response = $this->httpGet($url, 15);
        } catch (RuntimeException $e) {
            return []; // non-fatal — live cert data is still useful
        }

        if ($response['status'] !== 200 || empty($response['body'])) {
            return [];
        }

        $raw = json_decode($response['body'], true);
        if (!is_array($raw)) {
            return [];
        }

        // Normalise and deduplicate by serial number
        $certs = [];
        $seen  = [];

        foreach ($raw as $entry) {

            $serial = $entry['serial_number'] ?? null;

            // Skip duplicates
            if ($serial && in_array($serial, $seen)) {
                continue;
            }
            if ($serial) {
                $seen[] = $serial;
            }

            $notBefore = $entry['not_before'] ?? null;
            $notAfter  = $entry['not_after']  ?? null;

            // Calculate validity duration in days
            $validityDays = null;
            if ($notBefore && $notAfter) {
                $validityDays = (int) round(
                    (strtotime($notAfter) - strtotime($notBefore)) / 86400
                );
            }

            $certs[] = [
                'id'            => $entry['id']           ?? null,
                'serial'        => $serial,
                'issuer'        => $entry['issuer_name']  ?? 'Unknown',
                'not_before'    => $notBefore,
                'not_after'     => $notAfter,
                'validity_days' => $validityDays,
                'name_value'    => $entry['name_value']   ?? null,
            ];
        }

        // Sort by issue date descending (newest first)
        usort($certs, function($a, $b) {
            return strtotime($b['not_before'] ?? '0')
                 - strtotime($a['not_before'] ?? '0');
        });

        return $certs;
    }

    // ── Detect anomalies in certificate history ───────────────
    private function detectAnomalies(array $history, array $liveCert): array {

        $anomalies = [];

        if (empty($history)) {
            return $anomalies;
        }

        // ── Check 1: Very short-lived certificates ────────────
        foreach ($history as $cert) {
            if (
                $cert['validity_days'] !== null &&
                $cert['validity_days'] < self::MIN_NORMAL_VALIDITY_DAYS
            ) {
                $anomalies[] = [
                    'type'    => 'short_lived_cert',
                    'detail'  => "Certificate valid for only {$cert['validity_days']} days",
                    'serial'  => $cert['serial'],
                    'severity'=> 'medium',
                ];
            }
        }

        // ── Check 2: Sudden issuer change ─────────────────────
        // Compare consecutive certs — if issuer changes abruptly, flag it
        for ($i = 0; $i < count($history) - 1; $i++) {

            $current  = $history[$i];
            $previous = $history[$i + 1];

            $currentIssuer  = $this->normaliseIssuer($current['issuer']);
            $previousIssuer = $this->normaliseIssuer($previous['issuer']);

            if (
                $currentIssuer &&
                $previousIssuer &&
                $currentIssuer !== $previousIssuer
            ) {
                $anomalies[] = [
                    'type'    => 'issuer_change',
                    'detail'  => "Issuer changed from {$previousIssuer} to {$currentIssuer}",
                    'severity'=> 'low', // common when renewing with a different CA
                ];
                break; // report once, not for every change
            }
        }

        // ── Check 3: Many certs issued in a short time ────────
        // More than 5 certs in 30 days is unusual
        $thirtyDaysAgo = time() - (30 * 86400);
        $recentCerts   = array_filter($history, function($cert) use ($thirtyDaysAgo) {
            return strtotime($cert['not_before'] ?? '0') > $thirtyDaysAgo;
        });

        if (count($recentCerts) > 5) {
            $anomalies[] = [
                'type'    => 'cert_flood',
                'detail'  => count($recentCerts) . ' certificates issued in the last 30 days',
                'severity'=> 'high',
            ];
        }

        // ── Check 4: Live cert not found in CT logs ───────────
        // Every legitimate cert should be in the CT logs
        if (
            !empty($liveCert['serial']) &&
            !empty($history)
        ) {
            $liveSerial = strtolower($liveCert['serial']);
            $found = false;

            foreach ($history as $cert) {
                if (strtolower($cert['serial'] ?? '') === $liveSerial) {
                    $found = true;
                    break;
                }
            }

            if (!$found) {
                $anomalies[] = [
                    'type'    => 'not_in_ct_logs',
                    'detail'  => 'Live certificate serial not found in CT logs',
                    'severity'=> 'high',
                ];
            }
        }

        // ── Check 5: Certificate expiring soon ───────────────
        if (!empty($liveCert['expiring_soon'])) {
            $anomalies[] = [
                'type'    => 'expiring_soon',
                'detail'  => "Certificate expires in {$liveCert['days_remaining']} days",
                'severity'=> 'medium',
            ];
        }

        // ── Check 6: Certificate already expired ─────────────
        if (!empty($liveCert['expired'])) {
            $anomalies[] = [
                'type'    => 'expired',
                'detail'  => 'Certificate has expired',
                'severity'=> 'critical',
            ];
        }

        return $anomalies;
    }

    // ── Normalise issuer name for comparison ──────────────────
    // "Let's Encrypt Authority X3" and "Let's Encrypt R3"
    // are the same CA — normalise to just "Let's Encrypt"
    private function normaliseIssuer(string $issuer): string {

        $issuer = strtolower($issuer);

        if (str_contains($issuer, "let's encrypt") ||
            str_contains($issuer, 'lets encrypt')) {
            return "let's encrypt";
        }
        if (str_contains($issuer, 'digicert'))    return 'digicert';
        if (str_contains($issuer, 'comodo') ||
            str_contains($issuer, 'sectigo'))     return 'sectigo';
        if (str_contains($issuer, 'globalsign'))  return 'globalsign';
        if (str_contains($issuer, 'google'))      return 'google';
        if (str_contains($issuer, 'amazon'))      return 'amazon';
        if (str_contains($issuer, 'microsoft'))   return 'microsoft';
        if (str_contains($issuer, 'cloudflare'))  return 'cloudflare';

        // Return first meaningful word as fallback
        return explode(' ', trim($issuer))[0];
    }

    // ── Score calculation ─────────────────────────────────────
    private function calculateScore(
        array $liveCert,
        array $history,
        array $anomalies
    ): int {

        $score = 100;

        // Can't connect or parse cert
        if (!empty($liveCert['error'])) {
            return 0;
        }

        // Expired certificate is critical
        if (!empty($liveCert['expired'])) {
            return 0;
        }

        // Expiring soon
        if (!empty($liveCert['expiring_soon'])) {
            $score -= 20;
        }

        // No CT log history at all (very suspicious for established domain)
        if (empty($history)) {
            $score -= 20;
        }

        // Penalise by anomaly severity
        foreach ($anomalies as $anomaly) {
            $score -= match($anomaly['severity']) {
                'critical' => 50,
                'high'     => 25,
                'medium'   => 10,
                'low'      => 5,
                default    => 0,
            };
        }

        return max(0, $score);
    }
}