<template>
  <div class="ca">

    <div class="ca__top">
      <div class="ca__grade" :style="{ color: gradeColor }">
        {{ data.privacy_grade }}
      </div>
      <div class="ca__grade-label">privacy grade</div>
      <div class="ca__metrics">
        <div class="metric">
          <span class="metric__value">{{ data.total_cookies }}</span>
          <span class="metric__label">total</span>
        </div>
        <div class="metric">
          <span
            class="metric__value"
            :style="{ color: data.tracking_cookies > 0 ? 'var(--color-text-warning)' : 'inherit' }"
          >{{ data.tracking_cookies }}</span>
          <span class="metric__label">trackers</span>
        </div>
        <div class="metric">
          <span class="metric__value">{{ data.third_party }}</span>
          <span class="metric__label">3rd party</span>
        </div>
      </div>
    </div>

    <div v-if="data.trackers_found?.length" class="ca__trackers">
      <span
        v-for="t in data.trackers_found"
        :key="t"
        class="ca__tracker-tag"
      >{{ t }}</span>
    </div>

    <div v-if="data.cookies?.length" class="ca__table-wrap">
      <table class="ca__table">
        <thead>
          <tr>
            <th>name</th>
            <th>secure</th>
            <th>httponly</th>
            <th>samesite</th>
            <th>risk</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="cookie in data.cookies"
            :key="cookie.name"
            :class="{ 'ca__row--tracking': cookie.is_tracking }"
          >
            <td class="ca__cookie-name">{{ cookie.name }}</td>
            <td><span :class="boolClass(cookie.secure)">{{ boolIcon(cookie.secure) }}</span></td>
            <td><span :class="boolClass(cookie.httponly)">{{ boolIcon(cookie.httponly) }}</span></td>
            <td class="ca__samesite">{{ cookie.samesite ?? '—' }}</td>
            <td>
              <span class="ca__risk" :class="`ca__risk--${cookie.risk}`">
                {{ cookie.risk }}
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-else class="ca__empty">
      No cookies detected
    </div>

  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({ data: { type: Object, required: true } })

const gradeColor = computed(() => ({
  A: 'var(--color-text-success)',
  B: 'var(--color-text-success)',
  C: 'var(--color-text-warning)',
  D: 'var(--color-text-warning)',
  F: 'var(--color-text-danger)',
}[props.data.privacy_grade] ?? 'var(--color-text-secondary)'))

function boolClass(val) {
  return val ? 'ca__bool ca__bool--yes' : 'ca__bool ca__bool--no'
}

function boolIcon(val) {
  return val ? '✓' : '✗'
}
</script>

<style scoped>
.ca { display: flex; flex-direction: column; gap: 12px; }

.ca__top {
  display: flex;
  align-items: center;
  gap: 12px;
}

.ca__grade {
  font-size: 2.5rem;
  font-weight: 500;
  line-height: 1;
  min-width: 40px;
}

.ca__grade-label {
  font-size: 0.7rem;
  color: var(--color-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  min-width: 50px;
}

.ca__metrics {
  display: flex;
  gap: 6px;
  flex: 1;
}

.metric {
  background: var(--color-background-secondary);
  border-radius: var(--border-radius-md);
  padding: 6px 8px;
  display: flex;
  flex-direction: column;
  gap: 2px;
  flex: 1;
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

.ca__trackers { display: flex; flex-wrap: wrap; gap: 4px; }

.ca__tracker-tag {
  font-size: 0.75rem;
  padding: 2px 8px;
  border-radius: var(--border-radius-md);
  background: var(--color-background-warning);
  color: var(--color-text-warning);
}

.ca__table-wrap { overflow-x: auto; }

.ca__table {
  width: 100%;
  font-size: 0.78rem;
  border-collapse: collapse;
  table-layout: fixed;
}

.ca__table th {
  text-align: left;
  color: var(--color-text-tertiary);
  font-weight: 400;
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  padding: 4px 4px 6px;
  border-bottom: 0.5px solid var(--color-border-tertiary);
}

.ca__table td {
  padding: 5px 4px;
  border-bottom: 0.5px solid var(--color-border-tertiary);
  color: var(--color-text-primary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.ca__row--tracking td { background: var(--color-background-warning); }

.ca__cookie-name {
  font-family: var(--font-mono);
  font-size: 0.75rem !important;
}

.ca__bool { font-size: 0.8rem; }
.ca__bool--yes { color: var(--color-text-success); }
.ca__bool--no  { color: var(--color-text-danger); }

.ca__samesite {
  font-size: 0.72rem !important;
  color: var(--color-text-secondary) !important;
}

.ca__risk {
  font-size: 0.68rem;
  padding: 1px 5px;
  border-radius: var(--border-radius-md);
}

.ca__risk--none   { background: var(--color-background-success); color: var(--color-text-success); }
.ca__risk--low    { background: var(--color-background-success); color: var(--color-text-success); }
.ca__risk--medium { background: var(--color-background-warning); color: var(--color-text-warning); }
.ca__risk--high   { background: var(--color-background-danger);  color: var(--color-text-danger); }

.ca__empty {
  font-size: 0.82rem;
  color: var(--color-text-secondary);
}
</style>