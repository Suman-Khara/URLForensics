<template>
  <div v-if="loading" class="loading">Loading...</div>
  <div v-else-if="error" class="error">{{ error }}</div>

  <DetailLayout
    v-else-if="data"
    :slug="slug"
    :domain="audit.domain"
    icon="🔒"
    title="TLS Certificate"
    description="Inspects the live TLS certificate and queries the Certificate Transparency logs for the full certificate history, detecting anomalies that may indicate compromise or phishing."
    :score="engineData?.score"
  >

    <template #visualization>
      <div class="tls-visual">

        <div v-if="data.live_cert?.valid" class="tls-cert-card">

          <div class="tls-cert-header">
            <div class="tls-cert-issuer">{{ data.live_cert.issuer }}</div>
            <div
              class="tls-cert-status"
              :style="{ color: expiryColor }"
            >
              {{ data.live_cert.expired ? 'EXPIRED' :
                 data.live_cert.expiring_soon ? 'EXPIRING SOON' : 'VALID' }}
            </div>
          </div>

          <div class="tls-validity">
            <div class="tls-validity-dates">
              <span>{{ data.live_cert.valid_from }}</span>
              <span class="tls-validity-arrow">→</span>
              <span>{{ data.live_cert.valid_to }}</span>
            </div>
            <div class="tls-validity-bar-wrap">
              <div
                class="tls-validity-bar"
                :style="{
                  width: expiryPct + '%',
                  background: expiryColor
                }"
              ></div>
            </div>
            <div
              class="tls-validity-remaining"
              :style="{ color: expiryColor }"
            >
              {{ data.live_cert.days_remaining }} days remaining
              of {{ data.live_cert.total_validity_days }} day certificate
            </div>
          </div>

          <div class="tls-sans">
            <span class="tls-sans-label">Covers:</span>
            <span
              v-for="san in data.live_cert.sans"
              :key="san"
              class="tls-san"
            >{{ san }}</span>
          </div>

        </div>

        <div v-else class="alert alert--danger">
          {{ data.live_cert?.error ?? 'Could not retrieve certificate' }}
        </div>

        <div v-if="data.anomalies?.length" class="tls-anomalies">
          <div
            v-for="anomaly in data.anomalies"
            :key="anomaly.type"
            class="tls-anomaly"
            :class="`tls-anomaly--${anomaly.severity}`"
          >
            <span class="tls-anomaly-severity">{{ anomaly.severity }}</span>
            {{ anomaly.detail }}
          </div>
        </div>

        <div v-if="data.history?.length" class="tls-history">
          <div class="tls-history-label">Certificate history ({{ data.history_count }} total)</div>
          <div
            v-for="cert in data.history.slice(0, 8)"
            :key="cert.serial"
            class="tls-history-row"
          >
            <span class="tls-history-issuer">
              {{ extractIssuerName(cert.issuer) }}
            </span>
            <span class="tls-history-dates">
              {{ formatDate(cert.not_before) }} →
              {{ formatDate(cert.not_after) }}
            </span>
            <span class="tls-history-days">
              {{ cert.validity_days }}d
            </span>
          </div>
          <a
            :href="`https://crt.sh/?q=${audit.domain}`"
            target="_blank"
            rel="noopener"
            class="tls-crtsh-link"
          >
            View full history on crt.sh →
          </a>
        </div>

        <div v-else class="tls-history-empty">
          No certificate history available
          (Certificate Transparency log may have been unavailable)
        </div>

      </div>
    </template>

    <template #data>
      <div class="detail-grid">

        <div class="detail-row">
          <span class="detail-label">Subject</span>
          <span class="detail-value detail-value--mono">
            {{ data.live_cert?.subject }}
          </span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Issuer</span>
          <span class="detail-value">{{ data.live_cert?.issuer }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Issuer CN</span>
          <span class="detail-value detail-value--mono">
            {{ data.live_cert?.issuer_cn }}
          </span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Valid from</span>
          <span class="detail-value detail-value--mono">
            {{ data.live_cert?.valid_from }}
          </span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Valid to</span>
          <span class="detail-value detail-value--mono">
            {{ data.live_cert?.valid_to }}
          </span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Days remaining</span>
          <span
            class="detail-value"
            :style="{ color: expiryColor }"
          >{{ data.live_cert?.days_remaining }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Serial number</span>
          <span class="detail-value detail-value--mono detail-value--small">
            {{ data.live_cert?.serial }}
          </span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Domains covered</span>
          <span class="detail-value">{{ data.live_cert?.san_count }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Certs in CT logs</span>
          <span class="detail-value">{{ data.history_count }}</span>
        </div>

      </div>
    </template>

    <template #explanation>
      <div class="explanation">

        <div class="explanation__item">
          <h3>What is a TLS certificate?</h3>
          <p>When you connect to a website over HTTPS, the server presents a certificate — a digital identity document proving it is who it claims to be. The certificate is signed by a trusted Certificate Authority (CA) who verified the domain ownership. Your browser checks this signature before establishing a secure connection.</p>
        </div>

        <div class="explanation__item">
          <h3>Certificate validity — {{ data.live_cert?.days_remaining }} days remaining</h3>
          <p v-if="data.live_cert?.expired">
            <strong>Critical.</strong> The certificate has expired. The connection is not secure and browsers will show a warning. This indicates negligence or an abandoned domain.
          </p>
          <p v-else-if="data.live_cert?.expiring_soon">
            <strong>Warning.</strong> The certificate expires soon. The site owner needs to renew it or the site will become inaccessible with a security warning.
          </p>
          <p v-else>
            <strong>Good.</strong> The certificate is valid and not expiring soon.
          </p>
        </div>

        <div class="explanation__item">
          <h3>Certificate Transparency logs</h3>
          <p>Every certificate issued must be logged in public Certificate Transparency (CT) logs. This creates an auditable record of every certificate ever issued for a domain. URLForensics queries crt.sh — a public CT log aggregator — to retrieve this history.</p>
          <p>A domain with a long certificate history is established. A domain with no history (especially with a young certificate) may be newly created infrastructure — which is a common pattern in phishing attacks.</p>
        </div>

        <div class="explanation__item">
          <h3>Subject Alternative Names (SANs)</h3>
          <p>Modern certificates cover multiple domains using SANs. A certificate for <code>github.com</code> with SANs for <code>www.github.com</code> is normal. Wildcard SANs like <code>*.example.com</code> cover all subdomains.</p>
        </div>

        <div class="explanation__item">
          <h3>Certificate issuers</h3>
          <p><strong>Let's Encrypt</strong> — free, automated, used by millions of legitimate sites. Also used by phishing sites because it's instant and free.</p>
          <p><strong>DigiCert, Sectigo, GlobalSign</strong> — commercial CAs, typically paid. More common for established businesses.</p>
          <p><strong>Google Trust Services</strong> — used by Google's own properties.</p>
          <p>The issuer alone is not a reliable signal — Let's Encrypt serves both legitimate and malicious sites equally.</p>
        </div>

      </div>
    </template>

  </DetailLayout>
</template>

<script setup>
import { computed } from 'vue'
import DetailLayout from './DetailLayout.vue'
import { useReport } from '@/composables/useReport.js'

const props = defineProps({
  slug: { type: String, required: true }
})

const { loading, error, audit, engines } = useReport(props.slug)

const engineData = computed(() => engines.value?.tls_timeline)
const data       = computed(() => engineData.value?.data)

const expiryPct = computed(() => {
  const cert = data.value?.live_cert
  if (!cert?.valid) return 0
  return Math.max(0, Math.min(100,
    Math.round((cert.days_remaining / cert.total_validity_days) * 100)
  ))
})

const expiryColor = computed(() => {
  const days = data.value?.live_cert?.days_remaining ?? 0
  if (days <= 0)  return '#ef4444'
  if (days <= 30) return '#f59e0b'
  return '#22c55e'
})

function extractIssuerName(issuerStr) {
  if (!issuerStr) return 'Unknown'
  const match = issuerStr.match(/O=([^,]+)/)
  return match ? match[1].trim() : issuerStr.slice(0, 40)
}

function formatDate(dateStr) {
  if (!dateStr) return '—'
  return dateStr.slice(0, 10)
}
</script>

<style scoped>
.loading, .error {
  text-align: center;
  padding: 4rem;
  color: var(--color-text-secondary);
}

.tls-visual { display: flex; flex-direction: column; gap: 1.5rem; }

.tls-cert-card {
  background: var(--color-background-primary);
  border: 0.5px solid var(--color-border-tertiary);
  border-radius: var(--border-radius-lg);
  padding: 1.25rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.tls-cert-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.tls-cert-issuer {
  font-size: 1rem;
  font-weight: 500;
  color: var(--color-text-primary);
}

.tls-cert-status {
  font-size: 0.75rem;
  font-weight: 500;
  letter-spacing: 0.05em;
}

.tls-validity { display: flex; flex-direction: column; gap: 6px; }

.tls-validity-dates {
  display: flex;
  gap: 8px;
  align-items: center;
  font-family: var(--font-mono);
  font-size: 0.82rem;
  color: var(--color-text-secondary);
}

.tls-validity-arrow { color: var(--color-text-tertiary); }

.tls-validity-bar-wrap {
  height: 8px;
  background: var(--color-border-tertiary);
  border-radius: 4px;
  overflow: hidden;
}

.tls-validity-bar {
  height: 100%;
  border-radius: 4px;
  transition: width 0.8s ease;
}

.tls-validity-remaining {
  font-size: 0.82rem;
  font-weight: 500;
}

.tls-sans {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}

.tls-sans-label {
  font-size: 0.75rem;
  color: var(--color-text-secondary);
}

.tls-san {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  padding: 2px 8px;
  background: var(--color-background-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-secondary);
}

.tls-anomalies { display: flex; flex-direction: column; gap: 4px; }

.tls-anomaly {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-radius: 0;
  border-left: 3px solid;
  font-size: 0.82rem;
}

.tls-anomaly--critical,
.tls-anomaly--high {
  background: var(--color-background-danger);
  color: var(--color-text-danger);
  border-color: var(--color-border-danger);
}

.tls-anomaly--medium {
  background: var(--color-background-warning);
  color: var(--color-text-warning);
  border-color: var(--color-border-warning);
}

.tls-anomaly--low {
  background: var(--color-background-secondary);
  color: var(--color-text-secondary);
  border-color: var(--color-border-secondary);
}

.tls-anomaly-severity {
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  opacity: 0.7;
  flex-shrink: 0;
}

.tls-history { display: flex; flex-direction: column; gap: 4px; }

.tls-history-label {
  font-size: 0.78rem;
  color: var(--color-text-secondary);
  margin-bottom: 4px;
}

.tls-history-row {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 6px 0;
  border-bottom: 0.5px solid var(--color-border-tertiary);
  font-size: 0.8rem;
}

.tls-history-row:last-of-type { border-bottom: none; }

.tls-history-issuer {
  flex: 1;
  color: var(--color-text-primary);
}

.tls-history-dates {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  color: var(--color-text-secondary);
}

.tls-history-days {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  color: var(--color-text-tertiary);
  min-width: 35px;
  text-align: right;
}

.tls-crtsh-link {
  display: inline-block;
  margin-top: 8px;
  font-size: 0.8rem;
  color: var(--color-text-info);
  text-decoration: none;
}

.tls-crtsh-link:hover { text-decoration: underline; }

.tls-history-empty {
  font-size: 0.82rem;
  color: var(--color-text-tertiary);
  font-style: italic;
}

.alert {
  padding: 0.875rem 1.25rem;
  font-size: 0.85rem;
  border-left: 3px solid;
  border-radius: 0;
}

.alert--danger {
  background: var(--color-background-danger);
  color: var(--color-text-danger);
  border-color: var(--color-border-danger);
}

.detail-grid {
  display: flex;
  flex-direction: column;
  border: 0.5px solid var(--color-border-tertiary);
  border-radius: var(--border-radius-lg);
  overflow: hidden;
}

.detail-row {
  display: flex;
  align-items: flex-start;
  gap: 1rem;
  padding: 0.625rem 1rem;
  border-bottom: 0.5px solid var(--color-border-tertiary);
}

.detail-row:last-child { border-bottom: none; }

.detail-label {
  font-size: 0.8rem;
  color: var(--color-text-secondary);
  min-width: 150px;
  flex-shrink: 0;
  padding-top: 2px;
}

.detail-value {
  font-size: 0.85rem;
  color: var(--color-text-primary);
}

.detail-value--mono { font-family: var(--font-mono); font-size: 0.8rem; }
.detail-value--small { font-size: 0.72rem; }

.explanation { display: flex; flex-direction: column; gap: 1.5rem; }

.explanation__item h3 {
  font-size: 0.9rem;
  font-weight: 500;
  color: var(--color-text-primary);
  margin: 0 0 6px;
}

.explanation__item p {
  font-size: 0.85rem;
  color: var(--color-text-secondary);
  line-height: 1.6;
  margin: 0 0 6px;
}

.explanation__item p:last-child { margin-bottom: 0; }

.explanation__item code {
  font-family: var(--font-mono);
  font-size: 0.8rem;
  padding: 1px 5px;
  background: var(--color-background-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
}
</style>