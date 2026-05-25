import { ref, reactive } from 'vue'
import axios from 'axios'

// Engine display names and order
const ENGINE_META = {
  redirect_trail:      { label: 'Redirect Trail',        icon: '🔀' },
  dns_propagation:     { label: 'DNS Propagation',        icon: '🌍' },
  tls_timeline:        { label: 'TLS Certificate',        icon: '🔒' },
  cookie_audit:        { label: 'Cookie Audit',           icon: '🍪' },
  packet_journey:      { label: 'Packet Journey',         icon: '📡' },
  dns_resolution_tree: { label: 'DNS Resolution Tree',    icon: '🌲' },
}

export function useAudit() {

  // ── State ──────────────────────────────────────────────────
  const isLoading   = ref(false)
  const error       = ref(null)
  const auditSlug   = ref(null)
  const trustScore  = ref(null)
  const isComplete  = ref(false)
  const signals = ref(null)
  const verdict = ref(null)

  // Each engine gets its own state object
  const engines = reactive(
    Object.fromEntries(
      Object.entries(ENGINE_META).map(([key, meta]) => [
        key,
        {
          ...meta,
          status: 'idle',   // idle | pending | running | complete | failed
          data:   null,
          duration_ms: null,
        }
      ])
    )
  )

  // ── Start an audit ─────────────────────────────────────────
  async function startAudit(url) {

    // Reset state
    isLoading.value  = true
    error.value      = null
    auditSlug.value  = null
    trustScore.value = null
    isComplete.value = false

    Object.keys(engines).forEach(key => {
      engines[key].status      = 'pending'
      engines[key].data        = null
      engines[key].duration_ms = null
    })

    try {
      // Step 1 — create the audit job
      const response = await axios.post('/api/audit/create.php', { url })
      const slug     = response.data.slug
      auditSlug.value = slug

      // Step 2 — open SSE stream
      openStream(slug)

    } catch (err) {
      if (err.response?.status === 429) {
        const retryAfter = err.response.data?.retry_after ?? 3600
        const minutes    = Math.ceil(retryAfter / 60)
        error.value = `Rate limit reached. You can run 10 audits per hour. Try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`
      } else {
        error.value = err.response?.data?.error ?? 'Failed to start audit'
      }
      isLoading.value = false
    }
  }

  // ── Open SSE stream ────────────────────────────────────────
  function openStream(slug) {

    const source = new EventSource(`/api/audit/stream.php?slug=${slug}`)

    // Engine started running
    source.addEventListener('engine_start', (e) => {
      const { engine } = JSON.parse(e.data)
      if (engines[engine]) {
        engines[engine].status = 'running'
      }
    })

    // Engine finished (or failed)
    source.addEventListener('engine_result', (e) => {
      const payload = JSON.parse(e.data)
      const { engine, status, data, duration_ms } = payload

      if (engines[engine]) {
        engines[engine].status      = status
        engines[engine].data        = data ?? null
        engines[engine].duration_ms = duration_ms ?? null
      }
    })

    // All engines done
    source.addEventListener('done', (e) => {
      const payload    = JSON.parse(e.data)
      trustScore.value = payload.trust_score
      isComplete.value = true
      isLoading.value  = false

      // Add signals from done event
      if (payload.signals) {
        signals.value = payload.signals.signals
        verdict.value = payload.signals.verdict
      }

      source.close()   // close the SSE connection cleanly
    })

    // Connection error
    source.onerror = () => {
      error.value     = 'Stream connection lost'
      isLoading.value = false
      source.close()
    }
  }

  return {
    isLoading,
    error,
    auditSlug,
    trustScore,
    isComplete,
    engines,
    signals,
    verdict,
    startAudit,
  }
}