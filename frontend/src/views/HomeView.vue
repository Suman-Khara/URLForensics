<template>
  <div class="app">

    <header class="header">
      <h1 class="header__title">URLForensics</h1>
      <p class="header__tagline">What's really behind any URL</p>
    </header>

    <main class="main">

      <div class="search">
        <input
          v-model="urlInput"
          type="text"
          class="search__input"
          placeholder="https://example.com"
          :disabled="isLoading"
          @keyup.enter="handleSubmit"
        />
        <button
          class="search__btn"
          :disabled="isLoading || !urlInput.trim()"
          @click="handleSubmit"
        >
          {{ isLoading ? 'Analyzing...' : 'Analyze' }}
        </button>
      </div>

      <div v-if="error" class="error">{{ error }}</div>

      <div v-if="isComplete" class="trust-score">
        <div class="trust-score__left">
          <span class="trust-score__label">Trust Score</span>
          <span class="trust-score__sub">computed from 6 engines</span>
        </div>
        <span class="trust-score__value" :class="trustScoreClass">
          {{ trustScore }}<span class="trust-score__denom">/100</span>
        </span>
        <div class="trust-score__bar-wrap">
          <div
            class="trust-score__bar"
            :style="{ width: trustScore + '%', background: trustBarColor }"
          ></div>
        </div>
      </div>

      <!-- Shareable report link -->
      <div v-if="isComplete && auditSlug" class="report-link">
        <span class="report-link__label">Permanent report:</span>
        <a :href="`/report/${auditSlug}`" class="report-link__url" target="_blank">
          /report/{{ auditSlug }}
        </a>
        <button class="report-link__copy" @click="copyReportLink">
          {{ copied ? 'Copied!' : 'Copy link' }}
        </button>
      </div>

      <div v-if="auditSlug" class="panels">
        <EnginePanel
          v-for="(engine, key) in engines"
          :key="key"
          :engine="engine"
          :engine-key="key"
        />
      </div>

    </main>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import EnginePanel from '@/components/EnginePanel.vue'
import { useAudit } from '@/composables/useAudit.js'

const route    = useRoute()
const urlInput = ref(route.query.url ?? '')
const copied   = ref(false)

const {
  isLoading,
  error,
  auditSlug,
  trustScore,
  isComplete,
  engines,
  startAudit,
} = useAudit()

function handleSubmit() {
  if (!urlInput.value.trim() || isLoading.value) return
  startAudit(urlInput.value.trim())
}

function copyReportLink() {
  navigator.clipboard.writeText(
    `${window.location.origin}/report/${auditSlug.value}`
  )
  copied.value = true
  setTimeout(() => { copied.value = false }, 2000)
}

const trustScoreClass = computed(() => {
  if (trustScore.value === null) return ''
  if (trustScore.value >= 80)   return 'trust-score__value--high'
  if (trustScore.value >= 60)   return 'trust-score__value--mid'
  return 'trust-score__value--low'
})

const trustBarColor = computed(() => {
  if (trustScore.value === null) return '#888'
  if (trustScore.value >= 80)   return '#22c55e'
  if (trustScore.value >= 60)   return '#f59e0b'
  return '#ef4444'
})
</script>

<style scoped>
.app {
  max-width: 1200px;
  margin: 0 auto;
  padding: 2rem 1.5rem 4rem;
}

.header {
  text-align: center;
  margin-bottom: 3rem;
}

.header__title {
  font-size: 2.5rem;
  font-weight: 800;
  letter-spacing: -0.03em;
  background: linear-gradient(135deg, #3b82f6, #8b5cf6);
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  color: transparent;
}

.header__tagline {
  color: #475569;
  margin-top: 0.5rem;
  font-size: 1rem;
}

.search {
  display: flex;
  gap: 0.75rem;
  margin-bottom: 2rem;
}

.search__input {
  flex: 1;
  padding: 0.875rem 1.25rem;
  background: #12121a;
  border: 1px solid #1e1e2e;
  border-radius: 10px;
  color: #e2e8f0;
  font-size: 1rem;
  outline: none;
  transition: border-color 0.2s;
}

.search__input:focus { border-color: #3b82f6; }

.search__input:disabled { opacity: 0.5; }

.search__btn {
  padding: 0.875rem 2rem;
  background: linear-gradient(135deg, #3b82f6, #8b5cf6);
  border: none;
  border-radius: 10px;
  color: white;
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.2s;
}

.search__btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.error {
  background: #1a0a0a;
  border: 1px solid #ef4444;
  color: #ef4444;
  padding: 0.875rem 1.25rem;
  border-radius: 10px;
  margin-bottom: 1.5rem;
  font-size: 0.9rem;
}

.trust-score {
  display: grid;
  grid-template-columns: 1fr auto;
  grid-template-rows: auto auto;
  gap: 0.5rem 1rem;
  align-items: center;
  margin-bottom: 1rem;
  padding: 1.25rem 1.5rem;
  background: var(--color-background-primary);
  border: 0.5px solid var(--color-border-tertiary);
  border-radius: var(--border-radius-lg);
}

.trust-score__left { display: flex; flex-direction: column; gap: 2px; }

.trust-score__label {
  font-size: 0.75rem;
  color: var(--color-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.trust-score__sub {
  font-size: 0.72rem;
  color: var(--color-text-tertiary);
}

.trust-score__value {
  font-size: 2.5rem;
  font-weight: 500;
  font-variant-numeric: tabular-nums;
  line-height: 1;
}

.trust-score__denom {
  font-size: 1rem;
  color: var(--color-text-tertiary);
  font-weight: 400;
}

.trust-score__value--high { color: #22c55e; }
.trust-score__value--mid  { color: #f59e0b; }
.trust-score__value--low  { color: #ef4444; }

.trust-score__bar-wrap {
  grid-column: 1 / -1;
  height: 4px;
  background: var(--color-border-tertiary);
  border-radius: 2px;
  overflow: hidden;
}

.trust-score__bar {
  height: 100%;
  border-radius: 2px;
  transition: width 0.8s ease;
}

.report-link {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 1.5rem;
  padding: 0.75rem 1.25rem;
  background: var(--color-background-primary);
  border: 0.5px solid var(--color-border-tertiary);
  border-radius: var(--border-radius-lg);
  font-size: 0.85rem;
}

.report-link__label {
  color: var(--color-text-secondary);
}

.report-link__url {
  color: var(--color-text-info);
  font-family: var(--font-mono);
  text-decoration: none;
  flex: 1;
}

.report-link__url:hover { text-decoration: underline; }

.report-link__copy {
  padding: 4px 12px;
  border: 0.5px solid var(--color-border-secondary);
  border-radius: var(--border-radius-md);
  background: transparent;
  color: var(--color-text-secondary);
  font-size: 0.78rem;
  cursor: pointer;
}

.report-link__copy:hover { background: var(--color-background-secondary); }

.panels {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
  gap: 1rem;
}
</style>