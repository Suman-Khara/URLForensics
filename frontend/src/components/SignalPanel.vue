<template>
  <div class="sp" :class="`sp--${verdict.color}`">

    <div class="sp__verdict">
      <div class="sp__verdict-left">
        <span class="sp__verdict-label">{{ verdict.label }}</span>
        <span class="sp__verdict-message">{{ verdict.message }}</span>
      </div>
      <button
        class="sp__toggle"
        @click="expanded = !expanded"
      >
        {{ expanded ? 'Hide signals' : `Show ${signals.length} signals` }}
      </button>
    </div>

    <div v-if="expanded" class="sp__signals">
      <div
        v-for="signal in sortedSignals"
        :key="signal.type"
        class="sp__signal"
        :class="`sp__signal--${signal.severity}`"
      >
        <span class="sp__signal-icon" aria-hidden="true">
          {{ severityIcon(signal.severity) }}
        </span>
        <span class="sp__signal-detail">{{ signal.detail }}</span>
        <span class="sp__signal-engine">{{ engineLabel(signal.engine) }}</span>
      </div>
    </div>

  </div>
</template>

<script setup>
import { ref, computed } from 'vue'

const props = defineProps({
  signals: { type: Array,  required: true },
  verdict: { type: Object, required: true },
})

const expanded = ref(false)

// Sort: critical first, good last
const severityOrder = {
  critical: 0,
  high:     1,
  medium:   2,
  low:      3,
  good:     4,
}

const sortedSignals = computed(() =>
  [...props.signals].sort((a, b) =>
    (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
  )
)

function severityIcon(severity) {
  return {
    critical: '✗',
    high:     '✗',
    medium:   '⚠',
    low:      '↗',
    good:     '✓',
  }[severity] ?? '·'
}

function engineLabel(engine) {
  return {
    redirect_trail:      'Redirect',
    dns_propagation:     'DNS',
    tls_timeline:        'TLS',
    cookie_audit:        'Cookies',
    packet_journey:      'Network',
    dns_resolution_tree: 'DNS Tree',
  }[engine] ?? engine
}
</script>

<style scoped>
.sp {
  border-radius: var(--border-radius-lg);
  border: 0.5px solid var(--color-border-tertiary);
  background: var(--color-background-primary);
  overflow: hidden;
  margin-bottom: 1.5rem;
}

.sp--success { border-color: var(--color-border-success); }
.sp--warning { border-color: var(--color-border-warning); }
.sp--danger  { border-color: var(--color-border-danger); }

.sp__verdict {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 1rem 1.25rem;
}

.sp--success .sp__verdict { background: var(--color-background-success); }
.sp--warning .sp__verdict { background: var(--color-background-warning); }
.sp--danger  .sp__verdict { background: var(--color-background-danger); }

.sp__verdict-left {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.sp__verdict-label {
  font-weight: 500;
  font-size: 0.95rem;
}

.sp--success .sp__verdict-label { color: var(--color-text-success); }
.sp--warning .sp__verdict-label { color: var(--color-text-warning); }
.sp--danger  .sp__verdict-label { color: var(--color-text-danger); }

.sp__verdict-message {
  font-size: 0.82rem;
  color: var(--color-text-secondary);
}

.sp__toggle {
  padding: 5px 12px;
  border: 0.5px solid var(--color-border-secondary);
  border-radius: var(--border-radius-md);
  background: transparent;
  color: var(--color-text-secondary);
  font-size: 0.78rem;
  cursor: pointer;
  white-space: nowrap;
  flex-shrink: 0;
}

.sp__toggle:hover { background: var(--color-background-secondary); }

.sp__signals {
  padding: 0.5rem 0;
  border-top: 0.5px solid var(--color-border-tertiary);
}

.sp__signal {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 7px 1.25rem;
  border-bottom: 0.5px solid var(--color-border-tertiary);
  font-size: 0.82rem;
}

.sp__signal:last-child { border-bottom: none; }

.sp__signal-icon {
  font-size: 0.85rem;
  min-width: 16px;
  margin-top: 1px;
}

.sp__signal--critical .sp__signal-icon,
.sp__signal--high     .sp__signal-icon { color: var(--color-text-danger); }
.sp__signal--medium   .sp__signal-icon { color: var(--color-text-warning); }
.sp__signal--low      .sp__signal-icon { color: var(--color-text-secondary); }
.sp__signal--good     .sp__signal-icon { color: var(--color-text-success); }

.sp__signal-detail {
  flex: 1;
  color: var(--color-text-primary);
  line-height: 1.4;
}

.sp__signal--critical .sp__signal-detail,
.sp__signal--high     .sp__signal-detail { color: var(--color-text-danger); }
.sp__signal--good     .sp__signal-detail { color: var(--color-text-success); }

.sp__signal-engine {
  font-size: 0.7rem;
  color: var(--color-text-tertiary);
  padding: 1px 6px;
  background: var(--color-background-secondary);
  border-radius: var(--border-radius-md);
  white-space: nowrap;
  flex-shrink: 0;
}
</style>