<template>
  <div v-if="loading" class="loading">Loading...</div>
  <div v-else-if="error" class="error">{{ error }}</div>

  <DetailLayout
    v-else-if="data"
    :slug="slug"
    :domain="audit.domain"
    icon="📡"
    title="Packet Journey"
    description="Runs a traceroute to map every network hop between your server and the destination, geo-locating each router to show whose infrastructure your data passes through."
    :score="engineData?.score"
  >

    <template #visualization>
      <div class="pj-visual">

        <div class="pj-summary">
          <div class="pj-metric">
            <span class="pj-metric-value">{{ data.hop_count }}</span>
            <span class="pj-metric-label">Total hops</span>
          </div>
          <div class="pj-metric">
            <span class="pj-metric-value">{{ data.avg_rtt_ms }}ms</span>
            <span class="pj-metric-label">Avg RTT</span>
          </div>
          <div class="pj-metric">
            <span class="pj-metric-value">{{ data.max_rtt_ms }}ms</span>
            <span class="pj-metric-label">Max RTT</span>
          </div>
          <div class="pj-metric">
            <span class="pj-metric-value">{{ data.unresponsive }}</span>
            <span class="pj-metric-label">Silent hops</span>
          </div>
        </div>

        <div class="pj-countries">
          <span class="pj-countries-label">Countries traversed:</span>
          <span
            v-for="country in data.countries"
            :key="country"
            class="pj-country"
          >{{ country }}</span>
        </div>

        <div v-if="data.suspicious_routing?.length" class="alert alert--warning">
          <div
            v-for="s in data.suspicious_routing"
            :key="s.type"
          >⚠ {{ s.detail }}</div>
        </div>

        <!-- Full hop table -->
        <div class="pj-hops">
          <div class="pj-hops-header">
            <span>Hop</span>
            <span>IP Address</span>
            <span>Location</span>
            <span>Organization</span>
            <span>RTT</span>
          </div>
          <div
            v-for="hop in data.hops"
            :key="hop.hop"
            class="pj-hop"
            :class="{ 'pj-hop--silent': hop.unresponsive }"
          >
            <span class="pj-hop-num">{{ hop.hop }}</span>
            <span class="pj-hop-ip">
              {{ hop.unresponsive ? '* * *' : (hop.ip ?? '—') }}
            </span>
            <span class="pj-hop-loc">
              <template v-if="hop.private">
                <span class="pj-hop-private">Private network</span>
              </template>
              <template v-else-if="hop.city">
                {{ hop.city }}, {{ hop.country }}
              </template>
              <template v-else-if="!hop.unresponsive">—</template>
            </span>
            <span class="pj-hop-org">{{ hop.isp ?? '—' }}</span>
            <span class="pj-hop-rtt">
              <template v-if="hop.rtt_ms !== null">
                <div class="pj-rtt-bar-wrap">
                  <div
                    class="pj-rtt-bar"
                    :style="{ width: rttBarWidth(hop.rtt_ms) + '%' }"
                  ></div>
                </div>
                {{ hop.rtt_ms }}ms
              </template>
              <template v-else>—</template>
            </span>
          </div>
        </div>

        <!-- ISP breakdown -->
        <div v-if="data.isps?.length" class="pj-isps">
          <div class="pj-isps-label">Infrastructure owners:</div>
          <div
            v-for="isp in data.isps"
            :key="isp"
            class="pj-isp"
          >{{ isp }}</div>
        </div>

      </div>
    </template>

    <template #data>
      <div class="detail-grid">
        <div class="detail-row">
          <span class="detail-label">Total hops</span>
          <span class="detail-value">{{ data.hop_count }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Unresponsive hops</span>
          <span class="detail-value">{{ data.unresponsive }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Average RTT</span>
          <span class="detail-value">{{ data.avg_rtt_ms }}ms</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Maximum RTT</span>
          <span class="detail-value">{{ data.max_rtt_ms }}ms</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Countries</span>
          <span class="detail-value">{{ data.countries?.join(', ') }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">ISPs / Orgs</span>
          <div class="detail-value detail-value--stack">
            <span v-for="isp in data.isps" :key="isp">{{ isp }}</span>
          </div>
        </div>
        <div class="detail-row">
          <span class="detail-label">Suspicious routing</span>
          <span class="detail-value">
            {{ data.suspicious_routing?.length ? 'Detected' : 'None' }}
          </span>
        </div>
      </div>
    </template>

    <template #explanation>
      <div class="explanation">

        <div class="explanation__item">
          <h3>What is a traceroute?</h3>
          <p>Every piece of data you send to a server travels through dozens of intermediate routers. Traceroute exploits the IP protocol's TTL (Time to Live) field to reveal each router in the path. By sending packets with incrementally increasing TTLs, each router is forced to identify itself — mapping the complete network path.</p>
        </div>

        <div class="explanation__item">
          <h3>Silent hops ({{ data.unresponsive }} found)</h3>
          <p>Routers showing <code>* * *</code> are configured to not respond to traceroute probes — they silently forward packets without announcing themselves. This is common for ISP core routers and is generally not suspicious. The data still passed through these routers.</p>
        </div>

        <div class="explanation__item">
          <h3>RTT — Round Trip Time</h3>
          <p>RTT measures how long it takes for data to travel to a hop and back. Higher RTT generally means greater geographic distance. A sudden RTT spike between hops indicates a long geographic jump — often a transoceanic cable or satellite link.</p>
        </div>

        <div class="explanation__item">
          <h3>Why does traffic route through unexpected countries?</h3>
          <p>Internet routing follows BGP (Border Gateway Protocol) paths optimized for various factors — not always geographic proximity. Traffic from India to an Indian server may briefly pass through routers in Singapore or the US due to peering agreements between ISPs. This is usually normal but worth noting.</p>
          <p>Routing through countries with known mass surveillance laws (China, Russia, Iran, North Korea) is a stronger concern — state actors in those jurisdictions may be able to intercept the traffic.</p>
        </div>

        <div class="explanation__item">
          <h3>Infrastructure ownership</h3>
          <p>The ISP/organization field shows who owns each router. This reveals which companies' infrastructure your data passes through. For this audit, your data traversed: {{ data.isps?.join(', ') ?? 'unknown' }}.</p>
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

const engineData = computed(() => engines.value?.packet_journey)
const data       = computed(() => engineData.value?.data)

const maxRtt = computed(() => {
  const hops = data.value?.hops ?? []
  return Math.max(...hops.map(h => h.rtt_ms ?? 0), 1)
})

function rttBarWidth(rtt) {
  return Math.round((rtt / maxRtt.value) * 100)
}
</script>

<style scoped>
.loading, .error {
  text-align: center;
  padding: 4rem;
  color: var(--color-text-secondary);
}

.pj-visual { display: flex; flex-direction: column; gap: 1.5rem; }

.pj-summary {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
}

.pj-metric {
  background: var(--color-background-secondary);
  border-radius: var(--border-radius-md);
  padding: 0.875rem;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.pj-metric-value {
  font-size: 1.25rem;
  font-weight: 500;
  color: var(--color-text-primary);
}

.pj-metric-label {
  font-size: 0.7rem;
  color: var(--color-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.pj-countries {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.pj-countries-label {
  font-size: 0.78rem;
  color: var(--color-text-secondary);
}

.pj-country {
  font-size: 0.78rem;
  padding: 3px 10px;
  background: var(--color-background-info);
  color: var(--color-text-info);
  border-radius: var(--border-radius-md);
}

.alert {
  padding: 0.875rem 1.25rem;
  font-size: 0.85rem;
  border-left: 3px solid;
  border-radius: 0;
}

.alert--warning {
  background: var(--color-background-warning);
  color: var(--color-text-warning);
  border-color: var(--color-border-warning);
}

.pj-hops {
  border: 0.5px solid var(--color-border-tertiary);
  border-radius: var(--border-radius-lg);
  overflow: hidden;
}

.pj-hops-header {
  display: grid;
  grid-template-columns: 40px 130px 1fr 1fr 120px;
  gap: 8px;
  padding: 8px 12px;
  background: var(--color-background-secondary);
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--color-text-tertiary);
  border-bottom: 0.5px solid var(--color-border-tertiary);
}

.pj-hop {
  display: grid;
  grid-template-columns: 40px 130px 1fr 1fr 120px;
  gap: 8px;
  padding: 8px 12px;
  border-bottom: 0.5px solid var(--color-border-tertiary);
  align-items: center;
  font-size: 0.8rem;
}

.pj-hop:last-child { border-bottom: none; }

.pj-hop--silent { opacity: 0.5; }

.pj-hop-num { color: var(--color-text-tertiary); }

.pj-hop-ip {
  font-family: var(--font-mono);
  font-size: 0.75rem;
  color: var(--color-text-primary);
}

.pj-hop-loc { color: var(--color-text-secondary); font-size: 0.78rem; }
.pj-hop-private { color: var(--color-text-tertiary); font-style: italic; }
.pj-hop-org { color: var(--color-text-secondary); font-size: 0.75rem; }

.pj-hop-rtt {
  display: flex;
  align-items: center;
  gap: 6px;
  font-family: var(--font-mono);
  font-size: 0.75rem;
  color: var(--color-text-secondary);
}

.pj-rtt-bar-wrap {
  flex: 1;
  height: 3px;
  background: var(--color-border-tertiary);
  border-radius: 2px;
  overflow: hidden;
}

.pj-rtt-bar {
  height: 100%;
  background: var(--color-text-info);
  border-radius: 2px;
}

.pj-isps { display: flex; flex-direction: column; gap: 4px; }

.pj-isps-label {
  font-size: 0.78rem;
  color: var(--color-text-secondary);
  margin-bottom: 4px;
}

.pj-isp {
  font-size: 0.82rem;
  color: var(--color-text-primary);
  padding: 4px 0;
  border-bottom: 0.5px solid var(--color-border-tertiary);
}

.pj-isp:last-child { border-bottom: none; }

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

.explanation__item code {
  font-family: var(--font-mono);
  font-size: 0.8rem;
  padding: 1px 5px;
  background: var(--color-background-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
}
</style>