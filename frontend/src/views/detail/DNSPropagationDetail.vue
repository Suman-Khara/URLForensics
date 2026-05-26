<template>
  <div v-if="loading" class="loading">Loading...</div>
  <div v-else-if="error" class="error">{{ error }}</div>

  <DetailLayout
    v-else-if="data"
    :slug="slug"
    :domain="audit.domain"
    icon="🌍"
    title="DNS Propagation"
    description="Queries 25+ global DNS resolvers simultaneously to measure how consistently your domain resolves worldwide, detecting fast-flux patterns and propagation issues."
    :score="engineData?.score"
  >

    <template #visualization>
      <div class="prop-visual">

        <div class="prop-headline">
          <div class="prop-pct" :style="{ color: propagationColor }">
            {{ data.propagation_pct }}%
          </div>
          <div class="prop-pct-label">of resolvers return consistent answers</div>
          <div class="prop-bar-wrap">
            <div
              class="prop-bar"
              :style="{
                width: data.propagation_pct + '%',
                background: propagationColor
              }"
            ></div>
          </div>
        </div>

        <div v-if="data.fast_flux" class="alert alert--danger">
          Fast-flux DNS detected — IP addresses rotate rapidly,
          consistent with botnet or malware infrastructure
        </div>

        <div class="prop-regions">
          <div
            v-for="(stats, region) in data.by_region"
            :key="region"
            class="prop-region"
          >
            <span class="prop-region-name">{{ region }}</span>
            <div class="prop-region-bar-wrap">
              <div
                class="prop-region-bar"
                :style="{
                  width: regionPct(stats) + '%',
                  background: '#3b82f6'
                }"
              ></div>
            </div>
            <span class="prop-region-nums">
              {{ stats.success }}/{{ stats.total }}
            </span>
            <span class="prop-region-pct">
              {{ regionPct(stats) }}%
            </span>
          </div>
        </div>

      </div>
    </template>

    <template #data>
      <div class="detail-grid">

        <div class="detail-row">
          <span class="detail-label">Resolvers queried</span>
          <span class="detail-value">{{ data.resolvers_queried }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Resolvers responded</span>
          <span class="detail-value">{{ data.resolvers_responded }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Consistent responses</span>
          <span class="detail-value">{{ data.propagated }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Propagation</span>
          <span
            class="detail-value"
            :style="{ color: propagationColor }"
          >{{ data.propagation_pct }}%</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Unique IP sets</span>
          <span class="detail-value">{{ data.unique_ip_sets }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">TTL</span>
          <span class="detail-value">
            {{ data.ttl }}s
            <span class="detail-value--muted">({{ ttlHuman }})</span>
          </span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Fast-flux</span>
          <span
            class="detail-value"
            :style="{ color: data.fast_flux ? '#ef4444' : '#22c55e' }"
          >{{ data.fast_flux ? 'Detected' : 'Not detected' }}</span>
        </div>

        <div
          v-for="(values, type) in data.records"
          :key="type"
          class="detail-row"
        >
          <span class="detail-label">{{ type }} records</span>
          <div class="detail-value detail-value--stack">
            <span
              v-for="(val, i) in values"
              :key="i"
              class="detail-value--mono"
            >{{ val }}</span>
          </div>
        </div>

      </div>
    </template>

    <template #explanation>
      <div class="explanation">

        <div class="explanation__item">
          <h3>What is DNS propagation?</h3>
          <p>When you type a domain into your browser, your computer asks a DNS resolver to translate it into an IP address. There are thousands of DNS resolvers worldwide — each caches answers for a period defined by the TTL. When DNS records change, it takes time for all resolvers to get the updated answer. This process is called propagation.</p>
        </div>

        <div class="explanation__item">
          <h3>Propagation — {{ data.propagation_pct }}%</h3>
          <p v-if="data.propagation_pct >= 90">
            <strong>Excellent.</strong> Nearly all resolvers worldwide return consistent answers. DNS is stable and fully propagated.
          </p>
          <p v-else-if="data.propagation_pct >= 70">
            <strong>Good.</strong> Most resolvers are consistent. Minor propagation lag in some regions is normal.
          </p>
          <p v-else>
            <strong>Investigate.</strong> Low propagation can mean the domain was recently registered, DNS records recently changed, or the domain uses Anycast routing (where different IPs are intentionally served to different regions for performance).
          </p>
        </div>

        <div class="explanation__item">
          <h3>TTL — {{ data.ttl }} seconds ({{ ttlHuman }})</h3>
          <p>TTL (Time to Live) controls how long resolvers cache DNS answers before re-checking. A TTL of {{ data.ttl }}s means resolvers refresh their cache every {{ ttlHuman }}.</p>
          <p v-if="data.ttl < 300">Very low TTL — resolvers refresh frequently. This gives the domain owner flexibility to change IPs quickly but increases DNS query load.</p>
          <p v-else-if="data.ttl > 86400">High TTL — resolvers cache for a long time. DNS changes take longer to propagate worldwide.</p>
          <p v-else>Normal TTL range — good balance between propagation speed and DNS query efficiency.</p>
        </div>

        <div class="explanation__item">
          <h3>Fast-flux DNS</h3>
          <p>Fast-flux is a technique where a domain's IP addresses change very rapidly (low TTL + many different IPs). Legitimate high-traffic sites like Google use similar techniques for load balancing, but fast-flux is also a hallmark of malware command-and-control infrastructure and botnet hosting — it makes takedowns difficult by constantly cycling through different IP addresses.</p>
        </div>

        <div class="explanation__item">
          <h3>DNS record types</h3>
          <p><strong>A records</strong> — map the domain to IPv4 addresses (where to connect).</p>
          <p><strong>AAAA records</strong> — map to IPv6 addresses.</p>
          <p><strong>MX records</strong> — where to send email for this domain.</p>
          <p><strong>NS records</strong> — which servers are authoritative for this domain's DNS.</p>
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

const engineData = computed(() => engines.value?.dns_propagation)
const data       = computed(() => engineData.value?.data)

const propagationColor = computed(() => {
  const pct = data.value?.propagation_pct ?? 0
  if (pct >= 90) return '#22c55e'
  if (pct >= 70) return '#f59e0b'
  return '#ef4444'
})

const ttlHuman = computed(() => {
  const ttl = data.value?.ttl ?? 0
  if (ttl < 60)   return `${ttl}s`
  if (ttl < 3600) return `${Math.round(ttl/60)}min`
  if (ttl < 86400)return `${Math.round(ttl/3600)}hr`
  return `${Math.round(ttl/86400)}d`
})

function regionPct(stats) {
  return stats.total > 0
    ? Math.round((stats.success / stats.total) * 100)
    : 0
}
</script>

<style scoped>
.loading, .error {
  text-align: center;
  padding: 4rem;
  color: var(--color-text-secondary);
}

.prop-visual { display: flex; flex-direction: column; gap: 1.5rem; }

.prop-headline { display: flex; flex-direction: column; gap: 6px; }

.prop-pct {
  font-size: 3rem;
  font-weight: 500;
  line-height: 1;
}

.prop-pct-label {
  font-size: 0.85rem;
  color: var(--color-text-secondary);
}

.prop-bar-wrap {
  height: 8px;
  background: var(--color-border-tertiary);
  border-radius: 4px;
  overflow: hidden;
}

.prop-bar {
  height: 100%;
  border-radius: 4px;
  transition: width 0.8s ease;
}

.alert {
  padding: 0.875rem 1.25rem;
  border-radius: var(--border-radius-lg);
  font-size: 0.85rem;
  border-left: 3px solid;
  border-radius: 0;
}

.alert--danger {
  background: var(--color-background-danger);
  color: var(--color-text-danger);
  border-color: var(--color-border-danger);
}

.prop-regions { display: flex; flex-direction: column; gap: 8px; }

.prop-region {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 0.82rem;
}

.prop-region-name {
  min-width: 60px;
  color: var(--color-text-secondary);
  font-weight: 500;
}

.prop-region-bar-wrap {
  flex: 1;
  height: 6px;
  background: var(--color-border-tertiary);
  border-radius: 3px;
  overflow: hidden;
}

.prop-region-bar {
  height: 100%;
  border-radius: 3px;
  transition: width 0.6s ease;
}

.prop-region-nums {
  min-width: 35px;
  color: var(--color-text-tertiary);
  font-family: var(--font-mono);
  font-size: 0.78rem;
}

.prop-region-pct {
  min-width: 40px;
  text-align: right;
  font-family: var(--font-mono);
  font-size: 0.78rem;
  color: var(--color-text-secondary);
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

.detail-value--mono {
  font-family: var(--font-mono);
  font-size: 0.8rem;
  display: block;
}

.detail-value--muted { color: var(--color-text-tertiary); }

.detail-value--stack {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

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