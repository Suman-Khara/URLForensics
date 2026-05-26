<template>
  <div class="detail">

    <nav class="detail__nav">
      <RouterLink :to="`/report/${slug}`" class="detail__back">
        ← Back to report
      </RouterLink>
      <span class="detail__domain">{{ domain }}</span>
    </nav>

    <header class="detail__header">
      <div class="detail__header-left">
        <span class="detail__icon" aria-hidden="true">{{ icon }}</span>
        <div>
          <h1 class="detail__title">{{ title }}</h1>
          <p class="detail__description">{{ description }}</p>
        </div>
      </div>
      <div
        v-if="score !== null"
        class="detail__score"
        :style="{ color: scoreColor }"
      >
        {{ score }}<span class="detail__score-denom">/100</span>
      </div>
    </header>

    <!-- Visualization slot -->
    <section v-if="$slots.visualization" class="detail__section">
      <slot name="visualization" />
    </section>

    <!-- Data slot -->
    <section class="detail__section">
      <h2 class="detail__section-title">Detailed results</h2>
      <slot name="data" />
    </section>

    <!-- Explanation slot -->
    <section class="detail__section detail__section--explanation">
      <h2 class="detail__section-title">What this means</h2>
      <slot name="explanation" />
    </section>

  </div>
</template>

<script setup>
import { computed } from 'vue'
import { RouterLink } from 'vue-router'

const props = defineProps({
  slug:        { type: String, required: true },
  domain:      { type: String, required: true },
  icon:        { type: String, required: true },
  title:       { type: String, required: true },
  description: { type: String, required: true },
  score:       { type: Number, default: null },
})

const scoreColor = computed(() => {
  if (props.score === null) return 'var(--color-text-secondary)'
  if (props.score >= 80) return '#22c55e'
  if (props.score >= 60) return '#f59e0b'
  return '#ef4444'
})
</script>

<style scoped>
.detail {
  max-width: 1000px;
  margin: 0 auto;
  padding: 1.5rem 1.5rem 4rem;
}

.detail__nav {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 1.5rem;
  padding-bottom: 1rem;
  border-bottom: 0.5px solid var(--color-border-tertiary);
}

.detail__back {
  font-size: 0.85rem;
  color: var(--color-text-info);
  text-decoration: none;
}

.detail__back:hover { text-decoration: underline; }

.detail__domain {
  font-size: 0.85rem;
  font-family: var(--font-mono);
  color: var(--color-text-tertiary);
}

.detail__header {
  display: flex;
  align-items: flex-start;
  gap: 1rem;
  margin-bottom: 2rem;
}

.detail__header-left {
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
  flex: 1;
}

.detail__icon { font-size: 1.5rem; margin-top: 2px; }

.detail__title {
  font-size: 1.3rem;
  font-weight: 500;
  color: var(--color-text-primary);
  margin: 0 0 4px;
}

.detail__description {
  font-size: 0.85rem;
  color: var(--color-text-secondary);
  margin: 0;
  line-height: 1.5;
}

.detail__score {
  font-size: 2rem;
  font-weight: 500;
  font-variant-numeric: tabular-nums;
  line-height: 1;
  flex-shrink: 0;
}

.detail__score-denom {
  font-size: 0.9rem;
  color: var(--color-text-tertiary);
  font-weight: 400;
}

.detail__section {
  margin-bottom: 2.5rem;
}

.detail__section-title {
  font-size: 0.8rem;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--color-text-secondary);
  margin-bottom: 1rem;
  padding-bottom: 0.5rem;
  border-bottom: 0.5px solid var(--color-border-tertiary);
}

.detail__section--explanation {
  background: var(--color-background-secondary);
  border-radius: var(--border-radius-lg);
  padding: 1.5rem;
}

.detail__section--explanation .detail__section-title {
  border-color: var(--color-border-secondary);
}
</style>