<template>
  <div class="tls">

    <template v-if="data.live_cert?.valid">

      <div class="tls__cert">
        <div class="tls__issuer">{{ data.live_cert.issuer }}</div>
        <div class="tls__dates">
          {{ data.live_cert.valid_from }} → {{ data.live_cert.valid_to }}
        </div>
      </div>

      <div class="tls__expiry">
        <div class="tls__expiry-bar-wrap">
          <div
            class="tls__expiry-bar"
            :style="{
              width: expiryPct + '%',
              background: expiryBarColor,
              height: '6px',
              borderRadius: '3px',
              transition: 'width 0.6s ease'
            }"
          ></div>
        </div>
        <div class="tls__expiry-label" :style="{ color: expiryColor }">
          {{ data.live_cert.days_remaining }} days remaining
        </div>
      </div>

      <div class="tls__metrics">
        <div class="metric">
          <span class="metric__value">{{ data.live_cert.san_count }}</span>
          <span class="metric__label">domains covered</span>
        </div>
        <div class="metric">
          <span class="metric__value">{{ data.live_cert.total_validity_days }}d</span>
          <span class="metric__label">validity period</span>
        </div>
        <div class="metric">
          <span class="metric__value">{{ data.history_count }}</span>
          <span class="metric__label">certs in history</span>
        </div>
      </div>

      <div v-if="data.live_cert.sans?.length" class="tls__sans">
        <span
          v-for="san in data.live_cert.sans"
          :key="san"
          class="tls__san"
        >{{ san }}</span>
      </div>

    </template>

    <div v-else-if="data.live_cert?.error" class="tls__error">
      {{ data.live_cert.error }}
    </div>

    <div v-if="data.anomalies?.length" class="tls__anomalies">
      <div
        v-for="anomaly in data.anomalies"
        :key="anomaly.type"
        class="tls__anomaly"
        :class="`tls__anomaly--${anomaly.severity}`"
      >
        {{ anomaly.detail }}
      </div>
    </div>

  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({ data: { type: Object, required: true } })

const expiryPct = computed(() => {
  const cert = props.data.live_cert
  if (!cert?.valid) return 0
  return Math.max(0, Math.min(100,
    Math.round((cert.days_remaining / cert.total_validity_days) * 100)
  ))
})

const expiryBarColor = computed(() => {
  const days = props.data.live_cert?.days_remaining ?? 0
  if (days <= 0)  return '#ef4444'
  if (days <= 30) return '#f59e0b'
  return '#22c55e'
})

const expiryColor = computed(() => expiryBarColor.value)

const expiryBarClass = computed(() => {
  const days = props.data.live_cert?.days_remaining ?? 0
  if (days <= 0)  return 'bar--danger'
  if (days <= 30) return 'bar--warning'
  return 'bar--success'
})
</script>

<style scoped>
.tls { display: flex; flex-direction: column; gap: 12px; }

.tls__cert { display: flex; flex-direction: column; gap: 2px; }

.tls__issuer {
  font-weight: 500;
  font-size: 0.9rem;
  color: var(--color-text-primary);
}

.tls__dates {
  font-size: 0.78rem;
  font-family: var(--font-mono);
  color: var(--color-text-secondary);
}

.tls__expiry { display: flex; flex-direction: column; gap: 4px; }

.tls__expiry-bar-wrap {
  height: 6px;
  background: var(--color-background-tertiary);
  border-radius: 3px;
  overflow: hidden;
}

.tls__expiry-label {
  font-size: 0.8rem;
  font-weight: 500;
}

.tls__metrics {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
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

.tls__sans { display: flex; flex-wrap: wrap; gap: 4px; }

.tls__san {
  font-size: 0.75rem;
  font-family: var(--font-mono);
  padding: 2px 8px;
  background: var(--color-background-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-secondary);
}

.tls__error {
  font-size: 0.82rem;
  color: var(--color-text-danger);
  padding: 6px 10px;
  background: var(--color-background-danger);
  border-radius: var(--border-radius-md);
}

.tls__anomalies { display: flex; flex-direction: column; gap: 4px; }

.tls__anomaly {
  font-size: 0.78rem;
  padding: 4px 8px;
  border-radius: 0;
  border-left: 3px solid;
}

.tls__anomaly--critical {
  background: var(--color-background-danger);
  color: var(--color-text-danger);
  border-color: var(--color-border-danger);
}

.tls__anomaly--high {
  background: var(--color-background-danger);
  color: var(--color-text-danger);
  border-color: var(--color-border-danger);
}

.tls__anomaly--medium {
  background: var(--color-background-warning);
  color: var(--color-text-warning);
  border-color: var(--color-border-warning);
}

.tls__anomaly--low {
  background: var(--color-background-secondary);
  color: var(--color-text-secondary);
  border-color: var(--color-border-secondary);
}
</style>