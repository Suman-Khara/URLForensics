<template>
  <div class="dr">

    <div class="dr__metrics">
      <div class="metric">
        <span class="metric__value">{{ data.steps }}</span>
        <span class="metric__label">steps</span>
      </div>
      <div class="metric">
        <span class="metric__value">{{ data.tld }}</span>
        <span class="metric__label">TLD</span>
      </div>
      <div class="metric">
        <span class="metric__value">{{ data.final_ips?.length ?? 0 }}</span>
        <span class="metric__label">{{ data.final_ips?.length === 1 ? 'IP address' : 'IP addresses' }}</span>
      </div>
    </div>

    <div class="dr__tree">
      <div
        v-for="step in data.tree"
        :key="step.level"
        class="dr__step"
      >
        <div class="dr__step-header">
          <span class="dr__step-level">{{ levelLabel(step.level) }}</span>
          <span class="dr__step-name">{{ step.name }}</span>
          <span class="dr__step-count">
            {{ step.records?.length ?? 0 }} {{ step.records?.length === 1 ? 'record' : 'records' }}
          </span>
          <span class="dr__step-ms">{{ step.duration_ms }}ms</span>
        </div>

        <div v-if="step.level === 'resolution'" class="dr__ips">
          <span
            v-for="ip in data.final_ips"
            :key="ip"
            class="dr__ip"
          >{{ ip }}</span>
        </div>

        <div
          v-else-if="step.records?.length"
          class="dr__records"
        >
          <span
            v-for="(rec, i) in step.records.slice(0, 3)"
            :key="i"
            class="dr__record"
          >{{ rec.data }}</span>
          <span
            v-if="step.records.length > 3"
            class="dr__record-more"
          >+{{ step.records.length - 3 }} more</span>
        </div>

        <div v-if="step.raw_comment" class="dr__comment">
          {{ step.raw_comment }}
        </div>
      </div>
    </div>

    <div v-if="data.authoritative_ns?.length" class="dr__auth">
      <div class="dr__auth-label">authoritative nameservers</div>
      <div class="dr__ns-list">
        <span
          v-for="ns in data.authoritative_ns"
          :key="ns"
          class="dr__ns"
        >{{ ns }}</span>
      </div>
    </div>

    <div v-if="data.anomalies?.length" class="dr__anomalies">
      <div
        v-for="anomaly in data.anomalies"
        :key="anomaly.type"
        class="dr__anomaly"
        :class="`dr__anomaly--${anomaly.severity}`"
      >{{ anomaly.detail }}</div>
    </div>

  </div>
</template>

<script setup>
defineProps({ data: { type: Object, required: true } })

function levelLabel(level) {
  return {
    root:          '.',
    tld:           'TLD',
    sld:           'SLD',
    authoritative: 'AUTH',
    resolution:    'A',
    cname:         'CNAME',
  }[level] ?? level
}
</script>

<style scoped>
.dr { display: flex; flex-direction: column; gap: 12px; }

.dr__metrics {
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

.dr__tree { display: flex; flex-direction: column; gap: 2px; }

.dr__step {
  border-left: 2px solid var(--color-border-tertiary);
  padding: 6px 0 6px 10px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.dr__step-header {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.dr__step-level {
  font-size: 0.7rem;
  font-family: var(--font-mono);
  padding: 1px 6px;
  background: var(--color-background-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-secondary);
  min-width: 40px;
  text-align: center;
}

.dr__step-name {
  font-size: 0.82rem;
  font-family: var(--font-mono);
  color: var(--color-text-primary);
  flex: 1;
}

.dr__step-count {
  font-size: 0.7rem;
  color: var(--color-text-tertiary);
}

.dr__step-ms {
  font-size: 0.68rem;
  color: var(--color-text-tertiary);
  font-family: var(--font-mono);
}

.dr__ips { display: flex; flex-wrap: wrap; gap: 4px; }

.dr__ip {
  font-size: 0.78rem;
  font-family: var(--font-mono);
  padding: 2px 8px;
  background: var(--color-background-success);
  color: var(--color-text-success);
  border-radius: var(--border-radius-md);
}

.dr__records { display: flex; flex-wrap: wrap; gap: 4px; }

.dr__record {
  font-size: 0.72rem;
  font-family: var(--font-mono);
  color: var(--color-text-secondary);
  background: var(--color-background-secondary);
  padding: 1px 6px;
  border-radius: var(--border-radius-md);
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.dr__record-more {
  font-size: 0.72rem;
  color: var(--color-text-tertiary);
  padding: 1px 4px;
}

.dr__comment {
  font-size: 0.7rem;
  color: var(--color-text-tertiary);
  font-family: var(--font-mono);
}

.dr__auth { display: flex; flex-direction: column; gap: 6px; }

.dr__auth-label {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--color-text-secondary);
}

.dr__ns-list { display: flex; flex-direction: column; gap: 3px; }

.dr__ns {
  font-size: 0.75rem;
  font-family: var(--font-mono);
  color: var(--color-text-primary);
  padding: 2px 0;
  border-bottom: 0.5px solid var(--color-border-tertiary);
}

.dr__ns:last-child { border-bottom: none; }

.dr__anomalies { display: flex; flex-direction: column; gap: 4px; }

.dr__anomaly {
  font-size: 0.78rem;
  padding: 4px 8px;
  border-left: 3px solid;
  border-radius: 0;
}

.dr__anomaly--critical,
.dr__anomaly--high {
  background: var(--color-background-danger);
  color: var(--color-text-danger);
  border-color: var(--color-border-danger);
}

.dr__anomaly--medium {
  background: var(--color-background-warning);
  color: var(--color-text-warning);
  border-color: var(--color-border-warning);
}

.dr__anomaly--low {
  background: var(--color-background-secondary);
  color: var(--color-text-secondary);
  border-color: var(--color-border-secondary);
}
</style>