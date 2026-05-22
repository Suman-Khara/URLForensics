<template>
  <div class="panel" :class="[`panel--${engine.status}`]">

    <div class="panel__header">
      <span class="panel__icon">{{ engine.icon }}</span>
      <span class="panel__label">{{ engine.label }}</span>
      <span class="panel__status-badge">{{ statusLabel }}</span>
    </div>

    <!-- Loading state -->
    <div v-if="engine.status === 'running'" class="panel__loading">
      <div class="pulse-bar"></div>
    </div>

    <!-- Result state -->
    <div v-else-if="engine.status === 'complete'" class="panel__result">
      <div
        v-for="(value, key) in displayData"
        :key="key"
        class="panel__row"
      >
        <span class="panel__key">{{ formatKey(key) }}</span>
        <span class="panel__value">{{ formatValue(value) }}</span>
      </div>
      <div class="panel__duration">{{ engine.duration_ms }}ms</div>
    </div>

    <!-- Failed state -->
    <div v-else-if="engine.status === 'failed'" class="panel__error">
      Engine failed — check logs
    </div>

    <!-- Pending state -->
    <div v-else-if="engine.status === 'pending'" class="panel__pending">
      Queued
    </div>

  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  engine: {
    type: Object,
    required: true
  }
})

const statusLabel = computed(() => ({
  idle:     '',
  pending:  'queued',
  running:  'analyzing...',
  complete: 'complete',
  failed:   'failed',
}[props.engine.status] ?? ''))

// Don't display the raw score in the panel — it's used for trust score only
const displayData = computed(() => {
  if (!props.engine.data) return {}
  const { score, ...rest } = props.engine.data
  return rest
})

// "privacy_risk" → "Privacy Risk"
function formatKey(key) {
  return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
}

function formatValue(value) {
  if (Array.isArray(value)) return value.length ? value.join(', ') : 'none'
  if (value === null || value === undefined) return '—'
  return String(value)
}
</script>

<style scoped>
.panel {
  background: #12121a;
  border: 1px solid #1e1e2e;
  border-radius: 12px;
  padding: 1.25rem;
  transition: border-color 0.3s ease;
}

.panel--running  { border-color: #3b82f6; }
.panel--complete { border-color: #22c55e; }
.panel--failed   { border-color: #ef4444; }

.panel__header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1rem;
}

.panel__icon  { font-size: 1.2rem; }

.panel__label {
  font-weight: 600;
  font-size: 0.95rem;
  flex: 1;
}

.panel__status-badge {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: #64748b;
}

.panel--running  .panel__status-badge { color: #3b82f6; }
.panel--complete .panel__status-badge { color: #22c55e; }
.panel--failed   .panel__status-badge { color: #ef4444; }

.panel__row {
  display: flex;
  justify-content: space-between;
  padding: 0.3rem 0;
  border-bottom: 1px solid #1e1e2e;
  font-size: 0.85rem;
}

.panel__row:last-child { border-bottom: none; }

.panel__key   { color: #94a3b8; }
.panel__value { color: #e2e8f0; font-family: monospace; }

.panel__duration {
  margin-top: 0.75rem;
  font-size: 0.75rem;
  color: #475569;
  text-align: right;
}

.panel__pending,
.panel__error {
  font-size: 0.85rem;
  color: #475569;
  padding: 0.5rem 0;
}

.panel__error { color: #ef4444; }

/* Animated loading bar */
.pulse-bar {
  height: 3px;
  background: linear-gradient(90deg, #1e1e2e, #3b82f6, #1e1e2e);
  background-size: 200% 100%;
  border-radius: 2px;
  animation: pulse 1.5s ease-in-out infinite;
}

@keyframes pulse {
  0%   { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}
</style>