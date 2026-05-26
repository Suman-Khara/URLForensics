<template>
  <div v-if="loading" class="loading">Loading...</div>
  <div v-else-if="error" class="error">{{ error }}</div>

  <DetailLayout
    v-else-if="data"
    :slug="slug"
    :domain="audit.domain"
    icon="🔀"
    title="Redirect Trail"
    description="Follows every redirect hop from the original URL to the final destination, fingerprinting CDNs and detecting tracking parameters along the way."
    :score="engineData?.score"
  >

    <template #visualization>
      <div class="rt-chain">
        <div
          v-for="(hop, i) in data.hops"
          :key="i"
          class="rt-chain__hop"
        >
          <div
            class="rt-chain__node"
            :class="{
              'rt-chain__node--ok':       hop.status >= 200 && hop.status < 300,
              'rt-chain__node--redirect': hop.status >= 300 && hop.status < 400,
              'rt-chain__node--error':    hop.status >= 400,
            }"
          >
            <div class="rt-chain__node-top">
              <span
                class="rt-chain__node-status"
                :class="{
                  'status--ok':       hop.status >= 200 && hop.status < 300,
                  'status--redirect': hop.status >= 300 && hop.status < 400,
                  'status--error':    hop.status >= 400,
                }"
              >{{ hop.status }}</span>
              <span class="rt-chain__node-url">{{ hop.url }}</span>
            </div>
            <div class="rt-chain__node-bottom" v-if="hop.cdn || hop.trackers?.length">
              <span v-if="hop.cdn" class="rt-chain__node-cdn">
                {{ hop.cdn }}
              </span>
              <span
                v-for="tracker in hop.trackers"
                :key="tracker"
                class="rt-chain__node-tracker"
              >{{ tracker }}</span>
            </div>
          </div>

          <div v-if="i < data.hops.length - 1" class="rt-chain__connector">
            <div class="rt-chain__connector-line"></div>
            <span class="rt-chain__connector-label">
              {{ data.hops[i + 1].status >= 300 && data.hops[i + 1].status < 400
                ? `HTTP ${data.hops[i + 1].status}`
                : '→' }}
            </span>
            <div class="rt-chain__connector-arrow">↓</div>
          </div>

        </div>
      </div>
    </template>

    <template #data>
      <div class="detail-grid">

        <div class="detail-row">
          <span class="detail-label">Final URL</span>
          <span class="detail-value detail-value--mono">{{ data.final_url }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Final status</span>
          <span class="detail-value">
            <span :class="statusBadgeClass(data.final_status)">
              {{ data.final_status }}
            </span>
          </span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Total hops</span>
          <span class="detail-value">{{ data.hop_count }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">CDNs detected</span>
          <span class="detail-value">
            <span v-if="data.cdns?.length" class="tags">
              <span v-for="cdn in data.cdns" :key="cdn" class="tag tag--info">
                {{ cdn }}
              </span>
            </span>
            <span v-else class="detail-value--muted">None detected</span>
          </span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Trackers</span>
          <span class="detail-value">
            <span v-if="data.trackers?.length" class="tags">
              <span v-for="t in data.trackers" :key="t" class="tag tag--warning">
                {{ t }}
              </span>
            </span>
            <span v-else class="detail-value--muted">None detected</span>
          </span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Privacy risk</span>
          <span class="detail-value" :class="`risk--${data.privacy_risk}`">
            {{ data.privacy_risk }}
          </span>
        </div>

        <!-- Per-hop details -->
        <div class="detail-row detail-row--full">
          <span class="detail-label">Hop details</span>
        </div>
        <div
          v-for="(hop, i) in data.hops"
          :key="i"
          class="detail-row detail-row--full detail-row--hop"
        >
          <div class="hop-detail">
            <span class="hop-detail__num">Hop {{ i + 1 }}</span>
            <span class="hop-detail__url">{{ hop.url }}</span>
            <span :class="statusBadgeClass(hop.status)">{{ hop.status }}</span>
            <span v-if="hop.cdn" class="tag tag--info">{{ hop.cdn }}</span>
            <span
              v-for="t in hop.trackers"
              :key="t"
              class="tag tag--warning"
            >{{ t }}</span>
          </div>
        </div>

      </div>
    </template>

    <template #explanation>
      <div class="explanation">

        <div class="explanation__item">
          <h3>What is a redirect chain?</h3>
          <p>When you visit a URL, the server may instruct your browser to go somewhere else — this is a redirect. Each step in this journey is a "hop". URLForensics follows every hop manually, recording what happens at each step.</p>
        </div>

        <div class="explanation__item">
          <h3>Hop count — {{ data.hop_count }} {{ data.hop_count === 1 ? 'hop' : 'hops' }}</h3>
          <p v-if="data.hop_count === 1">
            <strong>Clean.</strong> The URL resolves directly — no redirects. This is ideal.
          </p>
          <p v-else-if="data.hop_count <= 3">
            <strong>Normal.</strong> Short redirect chains are common and expected — HTTP to HTTPS upgrades, www to non-www normalization, and short link expansion all create legitimate hops.
          </p>
          <p v-else>
            <strong>Investigate.</strong> Long redirect chains ({{ data.hop_count }} hops) can indicate traffic laundering through ad networks, affiliate tracking systems, or cloaking — where the initial URL hides the true destination.
          </p>
        </div>

        <div class="explanation__item">
          <h3>CDN detection</h3>
          <p>Content Delivery Networks (CDNs) like Cloudflare, Fastly, and Akamai are identified by distinctive HTTP response headers they inject. A CDN presence means the site uses distributed infrastructure for performance and/or security — generally a positive signal for established sites.</p>
        </div>

        <div class="explanation__item">
          <h3>Tracking parameters</h3>
          <p>Parameters like <code>utm_source</code>, <code>fbclid</code>, and <code>gclid</code> in URLs are tracking identifiers. They don't affect the page you see, but they report back to analytics and advertising systems — tracking where you came from and attributing the visit to a specific campaign or ad click.</p>
        </div>

        <div class="explanation__item">
          <h3>Privacy risk — {{ data.privacy_risk }}</h3>
          <p v-if="data.privacy_risk === 'none'">No privacy signals detected in the redirect chain.</p>
          <p v-else-if="data.privacy_risk === 'low'">Minor privacy signals — possibly HTTP in the chain or a small number of trackers.</p>
          <p v-else-if="data.privacy_risk === 'medium'">Moderate privacy concerns — mix of HTTP and HTTPS, or multiple tracking parameters.</p>
          <p v-else>Significant privacy concerns — heavy tracking, mixed protocols, or unusually long chain suggesting traffic laundering.</p>
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

const engineData = computed(() => engines.value?.redirect_trail)
const data       = computed(() => engineData.value?.data)

function formatUrl(url) {
  try {
    const u = new URL(url)
    return u.host + (u.pathname.length > 30
      ? u.pathname.slice(0, 30) + '…'
      : u.pathname)
  } catch { return url }
}

function nodeClass(status) {
  if (status >= 200 && status < 300) return 'rt-chain__node--ok'
  if (status >= 300 && status < 400) return 'rt-chain__node--redirect'
  return 'rt-chain__node--error'
}

function hopArrowLabel(nextStatus) {
  if (nextStatus >= 300 && nextStatus < 400) return '301/302'
  return '→'
}

function statusBadgeClass(code) {
  if (code >= 200 && code < 300) return 'badge badge--success'
  if (code >= 300 && code < 400) return 'badge badge--info'
  return 'badge badge--danger'
}
</script>

<style scoped>
.loading, .error {
  text-align: center;
  padding: 4rem;
  color: var(--color-text-secondary);
}

/* ── Hop chain ─────────────────────────────────────────── */
.rt-chain {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: 0;
  max-width: 680px;
}

.rt-chain__hop {
  display: flex;
  flex-direction: column;
  align-items: stretch;
}

.rt-chain__node {
  padding: 0.875rem 1.25rem;
  border-radius: var(--border-radius-lg);
  border: 0.5px solid var(--color-border-tertiary);
  background: var(--color-background-primary);
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.rt-chain__node--ok {
  border-color: #22c55e;
  border-left-width: 3px;
}

.rt-chain__node--redirect {
  border-color: #3b82f6;
  border-left-width: 3px;
}

.rt-chain__node--error {
  border-color: #ef4444;
  border-left-width: 3px;
}

.rt-chain__node-top {
  display: flex;
  align-items: center;
  gap: 10px;
}

.rt-chain__node-status {
  font-size: 0.78rem;
  font-weight: 500;
  padding: 2px 10px;
  border-radius: var(--border-radius-md);
  flex-shrink: 0;
}

.status--ok {
  background: #dcfce7;
  color: #166534;
}

.status--redirect {
  background: #dbeafe;
  color: #1e40af;
}

.status--error {
  background: #fee2e2;
  color: #991b1b;
}

.rt-chain__node-url {
  font-family: var(--font-mono);
  font-size: 0.85rem;
  color: var(--color-text-primary);
  word-break: break-all;
}

.rt-chain__node-bottom {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.rt-chain__node-cdn {
  font-size: 0.72rem;
  padding: 2px 8px;
  background: #dbeafe;
  color: #1e40af;
  border-radius: var(--border-radius-md);
}

.rt-chain__node-tracker {
  font-size: 0.72rem;
  padding: 2px 8px;
  background: #fef3c7;
  color: #92400e;
  border-radius: var(--border-radius-md);
}

.rt-chain__connector {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 4px 0;
  gap: 1px;
}

.rt-chain__connector-line {
  width: 1px;
  height: 8px;
  background: var(--color-border-secondary);
}

.rt-chain__connector-label {
  font-size: 0.68rem;
  color: var(--color-text-tertiary);
  font-family: var(--font-mono);
}

.rt-chain__connector-arrow {
  font-size: 0.75rem;
  color: var(--color-text-tertiary);
}

/* ── Data grid ─────────────────────────────────────────── */
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
.detail-row--full { flex-direction: column; align-items: flex-start; }
.detail-row--hop  { background: var(--color-background-secondary); padding: 0.5rem 1rem; }

.detail-label {
  font-size: 0.8rem;
  color: var(--color-text-secondary);
  min-width: 130px;
  flex-shrink: 0;
}

.detail-value {
  font-size: 0.85rem;
  color: var(--color-text-primary);
}

.detail-value--mono  { font-family: var(--font-mono); font-size: 0.8rem; }
.detail-value--muted { color: var(--color-text-tertiary); }

.hop-detail {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  width: 100%;
}

.hop-detail__num {
  font-size: 0.72rem;
  color: var(--color-text-tertiary);
  min-width: 40px;
}

.hop-detail__url {
  font-family: var(--font-mono);
  font-size: 0.78rem;
  color: var(--color-text-primary);
  flex: 1;
  word-break: break-all;
}

/* ── Tags and badges ───────────────────────────────────── */
.tags { display: flex; flex-wrap: wrap; gap: 4px; }

.tag {
  font-size: 0.72rem;
  padding: 2px 8px;
  border-radius: var(--border-radius-md);
}

.tag--info    { background: #dbeafe; color: #1e40af; }
.tag--warning { background: #fef3c7; color: #92400e; }

.badge {
  font-size: 0.72rem;
  padding: 2px 8px;
  border-radius: var(--border-radius-md);
  font-weight: 500;
}

.badge--success { background: #dcfce7; color: #166534; }
.badge--info    { background: #dbeafe; color: #1e40af; }
.badge--danger  { background: #fee2e2; color: #991b1b; }

.risk--none, .risk--low   { color: var(--color-text-success); }
.risk--medium             { color: var(--color-text-warning); }
.risk--high               { color: var(--color-text-danger); }

/* ── Explanation ───────────────────────────────────────── */
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