<template>
  <div class="report">

    <!-- Loading state -->
    <div v-if="loading" class="report__loading">
      <div class="report__spinner"></div>
      <p>Loading report...</p>
    </div>

    <!-- Error state -->
    <div v-else-if="error" class="report__error">
      <h2>Report not found</h2>
      <p>{{ error }}</p>
      <RouterLink to="/" class="report__back">← Analyze a URL</RouterLink>
    </div>

    <!-- Report content -->
    <template v-else-if="audit">

      <header class="report__header">
        <RouterLink to="/" class="report__home">URLForensics</RouterLink>
        <div class="report__meta">
          <span class="report__domain">{{ audit.domain }}</span>
          <span class="report__date">
            audited {{ formatDate(audit.created_at) }}
          </span>
        </div>
        <div class="report__actions">
          <button class="report__btn" @click="copyLink">
            {{ copied ? 'Copied!' : 'Copy link' }}
          </button>
          <button class="report__btn" @click="exportJSON">
            Export JSON
          </button>
          <RouterLink
            :to="`/?url=${encodeURIComponent(audit.url)}`"
            class="report__btn report__btn--primary"
          >
            Re-audit
          </RouterLink>
        </div>
      </header>

      <!-- Trust score -->
      <div class="report__score-wrap">
        <div class="report__score">
          <div class="report__score-left">
            <div class="report__score-url">{{ audit.url }}</div>
            <div class="report__score-sub">computed from 6 engines</div>
          </div>
          <div
            class="report__score-value"
            :style="{ color: trustColor }"
          >
            {{ audit.trust_score }}
            <span class="report__score-denom">/100</span>
          </div>
          <div class="report__score-bar-wrap">
            <div
              class="report__score-bar"
              :style="{
                width: audit.trust_score + '%',
                background: trustColor
              }"
            ></div>
          </div>
        </div>
      </div>

      <!-- Engine panels -->
      <div class="report__panels">
        <EnginePanel
          v-for="(engineData, engineKey) in formattedEngines"
          :key="engineKey"
          :engine="engineData"
          :engine-key="engineKey"
        />
      </div>

    </template>

  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { RouterLink }  from 'vue-router'
import axios           from 'axios'
import EnginePanel     from '@/components/EnginePanel.vue'

const props = defineProps({
  slug: { type: String, required: true }
})

// ── State ──────────────────────────────────────────────────
const loading = ref(true)
const error   = ref(null)
const audit   = ref(null)
const engines = ref({})
const copied  = ref(false)

// Engine display metadata — same as useAudit.js
const ENGINE_META = {
  redirect_trail:      { label: 'Redirect Trail',       icon: '🔀' },
  dns_propagation:     { label: 'DNS Propagation',       icon: '🌍' },
  tls_timeline:        { label: 'TLS Certificate',       icon: '🔒' },
  cookie_audit:        { label: 'Cookie Audit',          icon: '🍪' },
  packet_journey:      { label: 'Packet Journey',        icon: '📡' },
  dns_resolution_tree: { label: 'DNS Resolution Tree',   icon: '🌲' },
}

// ── Fetch report on mount ──────────────────────────────────
onMounted(async () => {
  try {
    const response = await axios.get(
      `/api/report/get.php?slug=${props.slug}`
    )
    audit.value   = response.data.audit
    engines.value = response.data.engines
  } catch (err) {
    error.value = err.response?.status === 404
      ? 'This report does not exist or has been removed.'
      : 'Failed to load report. Please try again.'
  } finally {
    loading.value = false
  }
})

// ── Format engines for EnginePanel component ──────────────
// EnginePanel expects the same shape as useAudit.js provides
const formattedEngines = computed(() => {
  const result = {}
  for (const [key, meta] of Object.entries(ENGINE_META)) {
    const engineData = engines.value[key]
    result[key] = {
      ...meta,
      status:      engineData?.status      ?? 'pending',
      data:        engineData?.data        ?? null,
      duration_ms: engineData?.duration_ms ?? null,
      score:       engineData?.score       ?? null,
    }
  }
  return result
})

// ── Trust score color ──────────────────────────────────────
const trustColor = computed(() => {
  const score = audit.value?.trust_score ?? 0
  if (score >= 80) return '#22c55e'
  if (score >= 60) return '#f59e0b'
  return '#ef4444'
})

// ── Actions ────────────────────────────────────────────────
function copyLink() {
  navigator.clipboard.writeText(window.location.href)
  copied.value = true
  setTimeout(() => { copied.value = false }, 2000)
}

function exportJSON() {
  const data = {
    audit:   audit.value,
    engines: engines.value,
    exported_at: new Date().toISOString(),
  }
  const blob = new Blob(
    [JSON.stringify(data, null, 2)],
    { type: 'application/json' }
  )
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a')
  a.href     = url
  a.download = `urlforensics-${props.slug}.json`
  a.click()
  URL.revokeObjectURL(url)
}

function formatDate(dateStr) {
  return new Date(dateStr).toLocaleDateString('en-IN', {
    day:   'numeric',
    month: 'short',
    year:  'numeric',
    hour:  '2-digit',
    minute:'2-digit',
  })
}
</script>

<style scoped>
.report {
  max-width: 1200px;
  margin: 0 auto;
  padding: 1.5rem 1.5rem 4rem;
}

.report__loading {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 60vh;
  gap: 1rem;
  color: var(--color-text-secondary);
}

.report__spinner {
  width: 32px;
  height: 32px;
  border: 2px solid var(--color-border-tertiary);
  border-top-color: var(--color-text-info);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin { to { transform: rotate(360deg); } }

.report__error {
  text-align: center;
  padding: 4rem 2rem;
  color: var(--color-text-secondary);
}

.report__error h2 {
  font-size: 1.25rem;
  font-weight: 500;
  color: var(--color-text-primary);
  margin-bottom: 0.5rem;
}

.report__back {
  display: inline-block;
  margin-top: 1.5rem;
  color: var(--color-text-info);
  text-decoration: none;
  font-size: 0.9rem;
}

.report__header {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 1.5rem;
  padding-bottom: 1rem;
  border-bottom: 0.5px solid var(--color-border-tertiary);
  flex-wrap: wrap;
}

.report__home {
  font-size: 1.1rem;
  font-weight: 500;
  color: var(--color-text-primary);
  text-decoration: none;
  flex-shrink: 0;
}

.report__home:hover { color: var(--color-text-info); }

.report__meta {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.report__domain {
  font-family: var(--font-mono);
  font-size: 0.95rem;
  color: var(--color-text-primary);
}

.report__date {
  font-size: 0.75rem;
  color: var(--color-text-tertiary);
}

.report__actions {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.report__btn {
  padding: 6px 14px;
  border: 0.5px solid var(--color-border-secondary);
  border-radius: var(--border-radius-md);
  background: transparent;
  color: var(--color-text-secondary);
  font-size: 0.82rem;
  cursor: pointer;
  text-decoration: none;
  display: inline-flex;
  align-items: center;
}

.report__btn:hover { background: var(--color-background-secondary); }

.report__btn--primary {
  background: var(--color-background-info);
  color: var(--color-text-info);
  border-color: var(--color-border-info);
}

.report__score-wrap { margin-bottom: 1.5rem; }

.report__score {
  display: grid;
  grid-template-columns: 1fr auto;
  grid-template-rows: auto auto;
  gap: 0.5rem 1rem;
  align-items: center;
  padding: 1.25rem 1.5rem;
  background: var(--color-background-primary);
  border: 0.5px solid var(--color-border-tertiary);
  border-radius: var(--border-radius-lg);
}

.report__score-left { display: flex; flex-direction: column; gap: 4px; }

.report__score-url {
  font-family: var(--font-mono);
  font-size: 0.85rem;
  color: var(--color-text-primary);
}

.report__score-sub {
  font-size: 0.72rem;
  color: var(--color-text-tertiary);
}

.report__score-value {
  font-size: 2.5rem;
  font-weight: 500;
  font-variant-numeric: tabular-nums;
  line-height: 1;
}

.report__score-denom {
  font-size: 1rem;
  color: var(--color-text-tertiary);
  font-weight: 400;
}

.report__score-bar-wrap {
  grid-column: 1 / -1;
  height: 4px;
  background: var(--color-border-tertiary);
  border-radius: 2px;
  overflow: hidden;
}

.report__score-bar {
  height: 100%;
  border-radius: 2px;
  transition: width 0.8s ease;
}

.report__panels {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
  gap: 1rem;
}
</style>