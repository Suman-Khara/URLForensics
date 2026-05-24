<template>
  <div class="dns">

    <div class="dns__headline">
      <div class="dns__pct" :style="{ color: propagationColor }">
        {{ data.propagation_pct }}%
      </div>
      <div class="dns__pct-label">propagated</div>
      <div class="dns__bar-wrap">
        <div
          class="dns__bar"
          :style="{
            width: data.propagation_pct + '%',
            background: propagationBarColor,
            height: '4px',
            borderRadius: '2px',
            transition: 'width 0.6s ease'
          }"
        ></div>
      </div>
    </div>

    <div v-if="data.fast_flux" class="dns__alert">
      Fast-flux DNS detected — possible malicious infrastructure
    </div>

    <div class="dns__metrics">
      <div class="metric">
        <span class="metric__value">{{ data.resolvers_queried }}</span>
        <span class="metric__label">queried</span>
      </div>
      <div class="metric">
        <span class="metric__value">{{ data.resolvers_responded }}</span>
        <span class="metric__label">responded</span>
      </div>
      <div class="metric">
        <span class="metric__value">{{ data.ttl }}s</span>
        <span class="metric__label">TTL</span>
      </div>
      <div class="metric">
        <span class="metric__value">{{ data.unique_ip_sets }}</span>
        <span class="metric__label">IP sets</span>
      </div>
    </div>

    <div v-if="data.by_region" class="dns__regions">
      <div
        v-for="(stats, region) in data.by_region"
        :key="region"
        class="dns__region"
      >
        <span class="dns__region-name">{{ region }}</span>
        <div class="dns__region-bar-wrap">
          <div
            class="dns__region-bar"
            :style="{
              width: regionPct(stats) + '%',
              background: '#3b82f6',
              height: '4px',
              borderRadius: '2px',
              transition: 'width 0.6s ease'
            }"
          ></div>
        </div>
        <span class="dns__region-pct">
          {{ stats.success }}/{{ stats.total }}
        </span>
      </div>
    </div>

    <div v-if="data.records" class="dns__records">
      <div
        v-for="(values, type) in data.records"
        :key="type"
        class="dns__record"
      >
        <span class="dns__record-type">{{ type }}</span>
        <span class="dns__record-values">
          {{ values.slice(0, 2).join(', ') }}
          <span v-if="values.length > 2" class="dns__record-more">
            +{{ values.length - 2 }} more
          </span>
        </span>
      </div>
    </div>

  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({ data: { type: Object, required: true } })

const propagationBarColor = computed(() => {
  const pct = props.data.propagation_pct
  if (pct >= 90) return '#22c55e'
  if (pct >= 70) return '#f59e0b'
  return '#ef4444'
})

const propagationColor = computed(() => propagationBarColor.value)

function regionPct(stats) {
  return stats.total > 0
    ? Math.round((stats.success / stats.total) * 100)
    : 0
}
</script>

<style scoped>
.dns { display: flex; flex-direction: column; gap: 12px; }

.dns__headline { display: flex; flex-direction: column; gap: 4px; }

.dns__pct {
  font-size: 2rem;
  font-weight: 500;
  line-height: 1;
}

.dns__pct-label {
  font-size: 0.75rem;
  color: var(--color-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.dns__bar-wrap {
  height: 4px;
  background: var(--color-border-tertiary);
  border-radius: 2px;
  overflow: hidden;
}

.dns__alert {
  font-size: 0.8rem;
  padding: 6px 10px;
  border-radius: var(--border-radius-md);
  background: var(--color-background-danger);
  color: var(--color-text-danger);
  border-left: 3px solid var(--color-border-danger);
  border-radius: 0;
}

.dns__metrics {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 6px;
}

.metric {
  background: var(--color-background-secondary);
  border-radius: var(--border-radius-md);
  padding: 6px 8px;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.metric__value {
  font-size: 0.95rem;
  font-weight: 500;
  color: var(--color-text-primary);
}

.metric__label {
  font-size: 0.65rem;
  color: var(--color-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.dns__regions { display: flex; flex-direction: column; gap: 6px; }

.dns__region {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.8rem;
}

.dns__region-name {
  min-width: 55px;
  color: var(--color-text-secondary);
}

.dns__region-bar-wrap {
  flex: 1;
  height: 4px;
  background: var(--color-border-tertiary);
  border-radius: 2px;
  overflow: hidden;
}

.dns__region-pct {
  min-width: 35px;
  text-align: right;
  color: var(--color-text-tertiary);
}

.dns__records { display: flex; flex-direction: column; gap: 4px; }

.dns__record {
  display: flex;
  gap: 8px;
  font-size: 0.8rem;
  padding: 4px 0;
  border-top: 0.5px solid var(--color-border-tertiary);
}

.dns__record-type {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  min-width: 32px;
  padding: 1px 6px;
  background: var(--color-background-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-secondary);
  height: fit-content;
}

.dns__record-values {
  color: var(--color-text-primary);
  font-family: var(--font-mono);
  font-size: 0.75rem;
  word-break: break-all;
}

.dns__record-more {
  color: var(--color-text-tertiary);
  font-family: var(--font-sans);
}
</style>