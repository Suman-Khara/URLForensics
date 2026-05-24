<template>
  <div class="pj">

    <div class="pj__metrics">
      <div class="metric">
        <span class="metric__value">{{ data.hop_count }}</span>
        <span class="metric__label">hops</span>
      </div>
      <div class="metric">
        <span class="metric__value">{{ data.avg_rtt_ms }}ms</span>
        <span class="metric__label">avg RTT</span>
      </div>
      <div class="metric">
        <span class="metric__value">{{ data.max_rtt_ms }}ms</span>
        <span class="metric__label">max RTT</span>
      </div>
      <div class="metric">
        <span class="metric__value">{{ data.unresponsive }}</span>
        <span class="metric__label">silent</span>
      </div>
    </div>

    <div v-if="data.countries?.length" class="pj__countries">
      <span
        v-for="country in data.countries"
        :key="country"
        class="pj__country"
      >{{ country }}</span>
    </div>

    <div v-if="data.suspicious_routing?.length" class="pj__alert">
      <div
        v-for="s in data.suspicious_routing"
        :key="s.type"
      >{{ s.detail }}</div>
    </div>

    <div class="pj__hops">
      <div
        v-for="hop in publicHops"
        :key="hop.hop"
        class="pj__hop"
      >
        <span class="pj__hop-num">{{ hop.hop }}</span>
        <div class="pj__hop-info">
          <span class="pj__hop-ip">{{ hop.ip }}</span>
          <span v-if="hop.city" class="pj__hop-loc">
            {{ hop.city }}{{ hop.country ? ', ' + hop.country : '' }}
          </span>
          <span v-if="hop.isp" class="pj__hop-isp">{{ hop.isp }}</span>
        </div>
        <div v-if="hop.rtt_ms !== null" class="pj__hop-rtt">
          <div
            class="pj__rtt-bar"
            :style="{ width: rttBarWidth(hop.rtt_ms) + '%' }"
          ></div>
          <span class="pj__rtt-val">{{ hop.rtt_ms }}ms</span>
        </div>
      </div>
    </div>

  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({ data: { type: Object, required: true } })

const publicHops = computed(() =>
  (props.data.hops ?? []).filter(h => !h.unresponsive && h.ip)
)

const maxRtt = computed(() =>
  Math.max(...publicHops.value.map(h => h.rtt_ms ?? 0), 1)
)

function rttBarWidth(rtt) {
  return Math.round((rtt / maxRtt.value) * 100)
}
</script>

<style scoped>
.pj { display: flex; flex-direction: column; gap: 12px; }

.pj__metrics {
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

.pj__countries { display: flex; flex-wrap: wrap; gap: 4px; }

.pj__country {
  font-size: 0.75rem;
  padding: 2px 8px;
  border-radius: var(--border-radius-md);
  background: var(--color-background-info);
  color: var(--color-text-info);
}

.pj__alert {
  font-size: 0.78rem;
  padding: 6px 10px;
  background: var(--color-background-warning);
  color: var(--color-text-warning);
  border-left: 3px solid var(--color-border-warning);
  border-radius: 0;
}

.pj__hops { display: flex; flex-direction: column; gap: 4px; }

.pj__hop {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 0;
  border-bottom: 0.5px solid var(--color-border-tertiary);
}

.pj__hop:last-child { border-bottom: none; }

.pj__hop-num {
  font-size: 0.7rem;
  color: var(--color-text-tertiary);
  min-width: 20px;
}

.pj__hop-info {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 1px;
}

.pj__hop-ip {
  font-size: 0.78rem;
  font-family: var(--font-mono);
  color: var(--color-text-primary);
}

.pj__hop-loc {
  font-size: 0.72rem;
  color: var(--color-text-secondary);
}

.pj__hop-isp {
  font-size: 0.68rem;
  color: var(--color-text-tertiary);
}

.pj__hop-rtt {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 80px;
}

.pj__rtt-bar {
  height: 3px;
  background: var(--color-text-info);
  border-radius: 2px;
  min-width: 2px;
}

.pj__rtt-val {
  font-size: 0.72rem;
  font-family: var(--font-mono);
  color: var(--color-text-tertiary);
  min-width: 45px;
  text-align: right;
}
</style>