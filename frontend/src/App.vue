<template>
  <div class="app">

    <header class="header">
      <h1 class="header__title">URLForensics</h1>
      <p class="header__tagline">What's really behind any URL</p>
    </header>

    <main class="main">

      <!-- URL Input Form -->
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

      <!-- Error -->
      <div v-if="error" class="error">{{ error }}</div>

      <!-- Trust Score -->
      <div v-if="isComplete" class="trust-score">
        <span class="trust-score__label">Trust Score</span>
        <span
          class="trust-score__value"
          :class="trustScoreClass"
        >
          {{ trustScore }}
        </span>
      </div>

      <!-- Engine Panels — only show after audit starts -->
      <div v-if="auditSlug" class="panels">
        <EnginePanel
          v-for="(engine, key) in engines"
          :key="key"
          :engine="engine"
        />
      </div>

    </main>

  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import EnginePanel from '@/components/EnginePanel.vue'
import { useAudit } from '@/composables/useAudit.js'

const urlInput = ref('')

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

const trustScoreClass = computed(() => {
  if (trustScore.value === null) return ''
  if (trustScore.value >= 80)   return 'trust-score__value--high'
  if (trustScore.value >= 60)   return 'trust-score__value--mid'
  return 'trust-score__value--low'
})
</script>

<style scoped>
.app {
  max-width: 1100px;
  margin: 0 auto;
  padding: 2rem 1.5rem;
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
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 2rem;
  padding: 1.25rem 1.5rem;
  background: #12121a;
  border: 1px solid #1e1e2e;
  border-radius: 12px;
}

.trust-score__label {
  font-size: 0.85rem;
  color: #64748b;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.trust-score__value {
  font-size: 2.5rem;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
}

.trust-score__value--high { color: #22c55e; }
.trust-score__value--mid  { color: #f59e0b; }
.trust-score__value--low  { color: #ef4444; }

.panels {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 1rem;
}
</style>