<template>
  <div v-if="loading" class="loading">Loading...</div>
  <div v-else-if="error" class="error">{{ error }}</div>

  <DetailLayout
    v-else-if="data"
    :slug="slug"
    :domain="audit.domain"
    icon="🌲"
    title="DNS Resolution Tree"
    description="Manually walks the DNS hierarchy from root nameservers down to the authoritative answer, exposing every delegation step and detecting misconfiguration."
    :score="engineData?.score"
  >

    <template #visualization>
      <div class="dr-visual">

        <!-- Tree visualization -->
        <div class="dr-tree">
          <div
            v-for="(step, i) in data.tree"
            :key="step.level"
            class="dr-step"
            :style="{ paddingLeft: (i * 24) + 'px' }"
          >
            <div class="dr-step-connector" v-if="i > 0">
              <div class="dr-step-line"></div>
              <div class="dr-step-arrow">└─</div>
            </div>

            <div class="dr-step-node" :class="`dr-step-node--${step.level}`">
              <div class="dr-step-node-header">
                <span class="dr-step-level">{{ levelLabel(step.level) }}</span>
                <span class="dr-step-name">{{ step.name }}</span>
                <span class="dr-step-count">
                  {{ step.records?.length ?? 0 }}
                  {{ step.records?.length === 1 ? 'record' : 'records' }}
                </span>
                <span class="dr-step-ms">{{ step.duration_ms }}ms</span>
              </div>

              <div v-if="step.raw_comment" class="dr-step-source">
                {{ step.raw_comment }}
              </div>

              <div
                v-if="step.level === 'resolution'"
                class="dr-step-ips"
              >
                <span
                  v-for="ip in data.final_ips"
                  :key="ip"
                  class="dr-ip"
                >{{ ip }}</span>
              </div>

              <div
                v-else-if="step.records?.length"
                class="dr-step-records"
              >
                <span
                  v-for="(rec, ri) in step.records.slice(0, 4)"
                  :key="ri"
                  class="dr-record"
                >{{ rec.data }}</span>
                <span
                  v-if="step.records.length > 4"
                  class="dr-record-more"
                >+{{ step.records.length - 4 }} more</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Anomalies -->
        <div v-if="data.anomalies?.length" class="dr-anomalies">
          <div
            v-for="anomaly in data.anomalies"
            :key="anomaly.type"
            class="dr-anomaly"
            :class="`dr-anomaly--${anomaly.severity}`"
          >
            <span class="dr-anomaly-severity">{{ anomaly.severity }}</span>
            {{ anomaly.detail }}
          </div>
        </div>

        <!-- Authoritative nameservers -->
        <div v-if="data.authoritative_ns?.length" class="dr-auth">
          <div class="dr-auth-label">Authoritative nameservers</div>
          <div class="dr-ns-grid">
            <div
              v-for="ns in data.authoritative_ns"
              :key="ns"
              class="dr-ns"
            >
              <span class="dr-ns-name">{{ ns }}</span>
              <span class="dr-ns-provider">{{ extractProvider(ns) }}</span>
            </div>
          </div>
        </div>

      </div>
    </template>

    <template #data>
      <div class="detail-grid">
        <div class="detail-row">
          <span class="detail-label">Domain</span>
          <span class="detail-value detail-value--mono">{{ data.domain }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">TLD</span>
          <span class="detail-value detail-value--mono">.{{ data.tld }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Resolution steps</span>
          <span class="detail-value">{{ data.steps }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Final IPs</span>
          <div class="detail-value detail-value--stack">
            <span
              v-for="ip in data.final_ips"
              :key="ip"
              class="detail-value--mono"
            >{{ ip }}</span>
          </div>
        </div>
        <div class="detail-row">
          <span class="detail-label">Nameservers</span>
          <span class="detail-value">{{ data.authoritative_ns?.length ?? 0 }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">DNSSEC</span>
          <span class="detail-value">
            {{ data.dnssec_indicated ? 'Indicated' : 'Not detected' }}
          </span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Anomalies</span>
          <span class="detail-value">{{ data.anomalies?.length ?? 0 }}</span>
        </div>
      </div>
    </template>

    <template #explanation>
      <div class="explanation">

        <div class="explanation__item">
          <h3>How DNS resolution works</h3>
          <p>When you type a domain, your computer doesn't magically know its IP. It follows a chain of delegation:</p>
          <p><strong>1. Root servers</strong> — 13 clusters of servers that know which servers handle each TLD (.com, .org, .in).</p>
          <p><strong>2. TLD servers</strong> — servers run by Verisign (for .com), ICANN, and others that know which nameservers handle each domain.</p>
          <p><strong>3. Authoritative nameservers</strong> — the domain owner's servers that have the actual IP address.</p>
          <p>This entire process normally takes milliseconds because resolvers cache each step.</p>
        </div>

        <div class="explanation__item">
          <h3>What the "Response from" field means</h3>
          <p>Each step shows which specific server answered the query. This is from Google's DoH (DNS-over-HTTPS) service, which performs the resolution on our behalf. On a network without ISP DNS restrictions, URLForensics would query these servers directly.</p>
        </div>

        <div class="explanation__item">
          <h3>Authoritative nameservers</h3>
          <p>These are the servers with the definitive answer for this domain. Changes to DNS records must be made here. The nameserver provider is significant — AWS Route53, Cloudflare, NS1, and Google are reliable enterprise DNS providers. Unknown or suspicious nameservers can indicate a compromised domain.</p>
        </div>

        <div class="explanation__item">
          <h3>TTL inconsistencies</h3>
          <p>TTL (Time to Live) at each level controls caching. A very low authoritative NS TTL (like GitHub's 900s) means the domain owner wants flexibility to change nameservers quickly. This is a deliberate choice, not a problem — but worth noting as it differs from typical DNS configuration.</p>
        </div>

        <div class="explanation__item">
          <h3>DNSSEC</h3>
          <p>DNSSEC cryptographically signs DNS responses, preventing attackers from intercepting DNS queries and returning false IP addresses (DNS spoofing). Not all domains implement DNSSEC — its absence is not an immediate risk but represents a hardening gap.</p>
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

const engineData = computed(() => engines.value?.dns_resolution_tree)
const data       = computed(() => engineData.value?.data)

function levelLabel(level) {
  return {
    root:          'Root .',
    tld:           'TLD',
    sld:           'SLD',
    authoritative: 'Auth NS',
    resolution:    'A record',
    cname:         'CNAME',
  }[level] ?? level
}

function extractProvider(ns) {
  if (ns.includes('awsdns'))     return 'AWS Route53'
  if (ns.includes('nsone'))      return 'NS1'
  if (ns.includes('cloudflare')) return 'Cloudflare'
  if (ns.includes('google'))     return 'Google'
  if (ns.includes('akam'))       return 'Akamai'
  const parts = ns.split('.')
  return parts[parts.length - 2] ?? ''
}
</script>

<style scoped>
.loading, .error {
  text-align: center;
  padding: 4rem;
  color: var(--color-text-secondary);
}

.dr-visual { display: flex; flex-direction: column; gap: 1.5rem; }

.dr-tree { display: flex; flex-direction: column; gap: 4px; }

.dr-step { position: relative; }

.dr-step-connector {
  display: flex;
  align-items: center;
  gap: 0;
  margin-bottom: 2px;
  color: var(--color-text-tertiary);
  font-family: var(--font-mono);
  font-size: 0.75rem;
}

.dr-step-line {
  width: 1px;
  height: 8px;
  background: var(--color-border-secondary);
  margin-left: 8px;
}

.dr-step-arrow { color: var(--color-text-tertiary); }

.dr-step-node {
  background: var(--color-background-primary);
  border: 0.5px solid var(--color-border-tertiary);
  border-radius: var(--border-radius-md);
  padding: 0.75rem 1rem;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.dr-step-node--root       { border-left: 3px solid var(--color-border-tertiary); }
.dr-step-node--tld        { border-left: 3px solid var(--color-border-info); }
.dr-step-node--sld        { border-left: 3px solid var(--color-border-warning); }
.dr-step-node--authoritative { border-left: 3px solid var(--color-border-success); }
.dr-step-node--resolution { border-left: 3px solid #22c55e; }

.dr-step-node-header {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.dr-step-level {
  font-size: 0.7rem;
  font-family: var(--font-mono);
  padding: 1px 6px;
  background: var(--color-background-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-secondary);
  white-space: nowrap;
}

.dr-step-name {
  font-family: var(--font-mono);
  font-size: 0.85rem;
  color: var(--color-text-primary);
  flex: 1;
}

.dr-step-count {
  font-size: 0.7rem;
  color: var(--color-text-tertiary);
}

.dr-step-ms {
  font-family: var(--font-mono);
  font-size: 0.7rem;
  color: var(--color-text-tertiary);
}

.dr-step-source {
  font-size: 0.72rem;
  color: var(--color-text-tertiary);
  font-family: var(--font-mono);
}

.dr-step-ips { display: flex; flex-wrap: wrap; gap: 6px; }

.dr-ip {
  font-family: var(--font-mono);
  font-size: 0.82rem;
  padding: 3px 10px;
  background: var(--color-background-success);
  color: var(--color-text-success);
  border-radius: var(--border-radius-md);
}

.dr-step-records { display: flex; flex-wrap: wrap; gap: 4px; }

.dr-record {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  padding: 2px 8px;
  background: var(--color-background-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-secondary);
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.dr-record-more {
  font-size: 0.72rem;
  color: var(--color-text-tertiary);
  padding: 2px 4px;
}

.dr-anomalies { display: flex; flex-direction: column; gap: 4px; }

.dr-anomaly {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-left: 3px solid;
  border-radius: 0;
  font-size: 0.82rem;
}

.dr-anomaly--critical,
.dr-anomaly--high {
  background: var(--color-background-danger);
  color: var(--color-text-danger);
  border-color: var(--color-border-danger);
}

.dr-anomaly--medium {
  background: var(--color-background-warning);
  color: var(--color-text-warning);
  border-color: var(--color-border-warning);
}

.dr-anomaly--low {
  background: var(--color-background-secondary);
  color: var(--color-text-secondary);
  border-color: var(--color-border-secondary);
}

.dr-anomaly-severity {
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  opacity: 0.7;
  flex-shrink: 0;
}

.dr-auth { display: flex; flex-direction: column; gap: 8px; }

.dr-auth-label {
  font-size: 0.78rem;
  color: var(--color-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.dr-ns-grid { display: flex; flex-direction: column; gap: 4px; }

.dr-ns {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 6px 0;
  border-bottom: 0.5px solid var(--color-border-tertiary);
}

.dr-ns:last-child { border-bottom: none; }

.dr-ns-name {
  font-family: var(--font-mono);
  font-size: 0.8rem;
  color: var(--color-text-primary);
  flex: 1;
}

.dr-ns-provider {
  font-size: 0.72rem;
  padding: 2px 8px;
  background: var(--color-background-secondary);
  color: var(--color-text-secondary);
  border-radius: var(--border-radius-md);
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
  min-width: 160px;
  flex-shrink: 0;
  padding-top: 2px;
}

.detail-value {
  font-size: 0.85rem;
  color: var(--color-text-primary);
}

.detail-value--mono { font-family: var(--font-mono); font-size: 0.8rem; }
.detail-value--stack { display: flex; flex-direction: column; gap: 2px; }

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
</style>