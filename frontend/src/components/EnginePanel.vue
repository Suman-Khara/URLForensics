<template>
  <div class="panel" :class="[`panel--${engine.status}`]">

    <div class="panel__header">
      <span class="panel__icon" aria-hidden="true">{{ engine.icon }}</span>
      <span class="panel__label">{{ engine.label }}</span>
      <span class="panel__badge">{{ statusLabel }}</span>
      <RouterLink
        v-if="engine.status === 'complete' && detailPath"
        :to="detailPath"
        class="panel__detail-link"
      >
        Details →
      </RouterLink>
    </div>

    <div v-if="engine.status === 'running'" class="panel__loading">
      <div class="pulse-bar"></div>
    </div>

    <div v-else-if="engine.status === 'pending'" class="panel__pending">
      Queued
    </div>

    <div v-else-if="engine.status === 'failed'" class="panel__error">
      Engine failed
    </div>

    <template v-else-if="engine.status === 'complete' && engine.data">
      <RedirectTrailPanel
        v-if="engineKey === 'redirect_trail'"
        :data="engine.data"
      />
      <DNSPropagationPanel
        v-else-if="engineKey === 'dns_propagation'"
        :data="engine.data"
      />
      <TLSTimelinePanel
        v-else-if="engineKey === 'tls_timeline'"
        :data="engine.data"
      />
      <CookieAuditPanel
        v-else-if="engineKey === 'cookie_audit'"
        :data="engine.data"
      />
      <PacketJourneyPanel
        v-else-if="engineKey === 'packet_journey'"
        :data="engine.data"
      />
      <DNSResolutionPanel
        v-else-if="engineKey === 'dns_resolution_tree'"
        :data="engine.data"
      />
    </template>

    <div v-if="engine.duration_ms" class="panel__duration">
      {{ engine.duration_ms }}ms
    </div>

  </div>
</template>

<script setup>
import { computed } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import RedirectTrailPanel   from './panels/RedirectTrailPanel.vue'
import DNSPropagationPanel  from './panels/DNSPropagationPanel.vue'
import TLSTimelinePanel     from './panels/TLSTimelinePanel.vue'
import CookieAuditPanel     from './panels/CookieAuditPanel.vue'
import PacketJourneyPanel   from './panels/PacketJourneyPanel.vue'
import DNSResolutionPanel   from './panels/DNSResolutionPanel.vue'

const props = defineProps({
  engine:    { type: Object,  required: true },
  engineKey: { type: String,  required: true },
  auditSlug: { type: String,  default: null },
})


const statusLabel = computed(() => ({
  idle:     '',
  pending:  'queued',
  running:  'analyzing...',
  complete: 'complete',
  failed:   'failed',
}[props.engine.status] ?? ''))

const route = useRoute()

const ENGINE_PATHS = {
  redirect_trail:      'redirect-trail',
  dns_propagation:     'dns-propagation',
  tls_timeline:        'tls-timeline',
  cookie_audit:        'cookie-audit',
  packet_journey:      'packet-journey',
  dns_resolution_tree: 'dns-resolution',
}

const detailPath = computed(() => {
  // Use prop slug (homepage) or route param slug (report page)
  const slug = props.auditSlug || route.params.slug
  if (!slug) return null
  const path = ENGINE_PATHS[props.engineKey]
  if (!path) return null
  return `/report/${slug}/${path}`
})
</script>

<style scoped>
.panel {
  background: var(--color-background-primary);
  border: 0.5px solid var(--color-border-tertiary);
  border-radius: var(--border-radius-lg);
  padding: 1rem 1.25rem;
  transition: border-color 0.3s ease;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.panel--running  { border-color: var(--color-border-info); }
.panel--complete { border-color: var(--color-border-success); }
.panel--failed   { border-color: var(--color-border-danger); }

.panel__header {
  display: flex;
  align-items: center;
  gap: 8px;
}

.panel__icon  { font-size: 1.1rem; }

.panel__label {
  font-weight: 500;
  font-size: 0.95rem;
  flex: 1;
  color: var(--color-text-primary);
}

.panel__badge {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--color-text-secondary);
}

.panel--running  .panel__badge { color: var(--color-text-info); }
.panel--complete .panel__badge { color: var(--color-text-success); }
.panel--failed   .panel__badge { color: var(--color-text-danger); }

.panel__duration {
  font-size: 0.75rem;
  color: var(--color-text-tertiary);
  text-align: right;
}

.panel__pending,
.panel__error {
  font-size: 0.85rem;
  color: var(--color-text-secondary);
  padding: 0.25rem 0;
}

.panel__error { color: var(--color-text-danger); }

.pulse-bar {
  height: 3px;
  background: linear-gradient(
    90deg,
    var(--color-background-secondary),
    var(--color-text-info),
    var(--color-background-secondary)
  );
  background-size: 200% 100%;
  border-radius: 2px;
  animation: pulse 1.5s ease-in-out infinite;
}

@keyframes pulse {
  0%   { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}

.panel__detail-link {
  font-size: 0.75rem;
  color: var(--color-text-info);
  text-decoration: none;
  padding: 2px 8px;
  border: 0.5px solid var(--color-border-info);
  border-radius: var(--border-radius-md);
  white-space: nowrap;
}

.panel__detail-link:hover {
  background: var(--color-background-info);
}
</style>