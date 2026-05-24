<template>
  <div class="rt">

    <div class="rt__metrics">
      <div class="metric">
        <span class="metric__value">{{ data.hop_count }}</span>
        <span class="metric__label">hops</span>
      </div>
      <div class="metric">
        <span
          class="metric__value"
          :style="{ color: riskColor }"
        >{{ data.privacy_risk }}</span>
        <span class="metric__label">privacy risk</span>
      </div>
      <div class="metric">
        <span class="metric__value">{{ data.final_status }}</span>
        <span class="metric__label">final status</span>
      </div>
    </div>

    <div v-if="data.hops?.length" class="rt__hops">
      <div
        v-for="(hop, i) in data.hops"
        :key="i"
        class="rt__hop"
      >
        <span class="rt__hop-num">{{ i + 1 }}</span>
        <div class="rt__hop-info">
          <span class="rt__hop-url">{{ truncateUrl(hop.url) }}</span>
          <div class="rt__hop-meta">
            <span class="rt__status" :class="statusClass(hop.status)">
              {{ hop.status }}
            </span>
            <span v-if="hop.cdn" class="rt__cdn">{{ hop.cdn }}</span>
            <span
              v-for="tracker in hop.trackers"
              :key="tracker"
              class="rt__tracker"
            >{{ tracker }}</span>
          </div>
        </div>
        <span v-if="i < data.hops.length - 1" class="rt__arrow">↓</span>
      </div>
    </div>

    <div v-if="data.cdns?.length" class="rt__section">
      <span class="rt__section-label">CDN</span>
      <div class="rt__tags">
        <span v-for="cdn in data.cdns" :key="cdn" class="rt__tag rt__tag--cdn">
          {{ cdn }}
        </span>
      </div>
    </div>

    <div v-if="data.trackers?.length" class="rt__section">
      <span class="rt__section-label">trackers</span>
      <div class="rt__tags">
        <span
          v-for="t in data.trackers"
          :key="t"
          class="rt__tag rt__tag--tracker"
        >{{ t }}</span>
      </div>
    </div>

  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({ data: { type: Object, required: true } })

const riskColor = computed(() => ({
  none:   'var(--color-text-success)',
  low:    'var(--color-text-success)',
  medium: 'var(--color-text-warning)',
  high:   'var(--color-text-danger)',
}[props.data.privacy_risk] ?? 'var(--color-text-secondary)'))

function statusClass(code) {
  if (code >= 200 && code < 300) return 'status--ok'
  if (code >= 300 && code < 400) return 'status--redirect'
  return 'status--error'
}

function truncateUrl(url) {
  try {
    const u = new URL(url)
    const path = u.pathname.length > 20
      ? u.pathname.slice(0, 20) + '…'
      : u.pathname
    return u.host + path
  } catch {
    return url.slice(0, 40)
  }
}
</script>

<style scoped>
.rt { display: flex; flex-direction: column; gap: 12px; }

.rt__metrics {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 8px;
}

.metric {
  background: var(--color-background-secondary);
  border-radius: var(--border-radius-md);
  padding: 8px 10px;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.metric__value {
  font-size: 1.1rem;
  font-weight: 500;
  color: var(--color-text-primary);
}

.metric__label {
  font-size: 0.7rem;
  color: var(--color-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.rt__hops { display: flex; flex-direction: column; gap: 2px; }

.rt__hop {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 6px 0;
  border-bottom: 0.5px solid var(--color-border-tertiary);
  position: relative;
}

.rt__hop:last-child { border-bottom: none; }

.rt__hop-num {
  font-size: 0.7rem;
  color: var(--color-text-tertiary);
  min-width: 16px;
  padding-top: 2px;
}

.rt__hop-info { flex: 1; display: flex; flex-direction: column; gap: 4px; }

.rt__hop-url {
  font-size: 0.82rem;
  font-family: var(--font-mono);
  color: var(--color-text-primary);
  word-break: break-all;
}

.rt__hop-meta { display: flex; flex-wrap: wrap; gap: 4px; }

.rt__status {
  font-size: 0.72rem;
  padding: 1px 6px;
  border-radius: var(--border-radius-md);
  font-weight: 500;
}

.status--ok       { background: var(--color-background-success); color: var(--color-text-success); }
.status--redirect { background: var(--color-background-info);    color: var(--color-text-info); }
.status--error    { background: var(--color-background-danger);  color: var(--color-text-danger); }

.rt__cdn {
  font-size: 0.72rem;
  padding: 1px 6px;
  border-radius: var(--border-radius-md);
  background: var(--color-background-secondary);
  color: var(--color-text-secondary);
}

.rt__tracker {
  font-size: 0.72rem;
  padding: 1px 6px;
  border-radius: var(--border-radius-md);
  background: var(--color-background-warning);
  color: var(--color-text-warning);
}

.rt__arrow {
  font-size: 0.75rem;
  color: var(--color-text-tertiary);
  position: absolute;
  bottom: -10px;
  left: 6px;
}

.rt__section {
  display: flex;
  align-items: center;
  gap: 8px;
}

.rt__section-label {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--color-text-secondary);
  min-width: 50px;
}

.rt__tags { display: flex; flex-wrap: wrap; gap: 4px; }

.rt__tag {
  font-size: 0.75rem;
  padding: 2px 8px;
  border-radius: var(--border-radius-md);
}

.rt__tag--cdn     { background: var(--color-background-info);    color: var(--color-text-info); }
.rt__tag--tracker { background: var(--color-background-warning); color: var(--color-text-warning); }
</style>