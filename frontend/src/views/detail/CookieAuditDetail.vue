<template>
  <div v-if="loading" class="loading">Loading...</div>
  <div v-else-if="error" class="error">{{ error }}</div>

  <DetailLayout
    v-else-if="data"
    :slug="slug"
    :domain="audit.domain"
    icon="🍪"
    title="Cookie Audit"
    description="Captures all cookies set by the server, classifies each one for tracking and security attributes, and assigns an overall privacy grade."
    :score="engineData?.score"
  >

    <template #visualization>
      <div class="ca-visual">

        <div class="ca-summary">
          <div class="ca-grade" :style="{ color: gradeColor }">
            {{ data.privacy_grade }}
          </div>
          <div class="ca-summary-stats">
            <div class="ca-stat">
              <span class="ca-stat-value">{{ data.total_cookies }}</span>
              <span class="ca-stat-label">Total cookies</span>
            </div>
            <div class="ca-stat">
              <span
                class="ca-stat-value"
                :style="{ color: data.tracking_cookies > 0 ? '#f59e0b' : '#22c55e' }"
              >{{ data.tracking_cookies }}</span>
              <span class="ca-stat-label">Tracking</span>
            </div>
            <div class="ca-stat">
              <span class="ca-stat-value">{{ data.secure_cookies }}</span>
              <span class="ca-stat-label">Secure flag</span>
            </div>
            <div class="ca-stat">
              <span class="ca-stat-value">{{ data.httponly_cookies }}</span>
              <span class="ca-stat-label">HttpOnly</span>
            </div>
          </div>
        </div>

        <div v-if="data.trackers_found?.length" class="ca-trackers">
          <div class="ca-trackers-label">Trackers identified:</div>
          <div class="ca-tracker-tags">
            <span
              v-for="t in data.trackers_found"
              :key="t"
              class="ca-tracker-tag"
            >{{ t }}</span>
          </div>
        </div>

        <!-- Full cookie parser -->
        <div
          v-for="cookie in data.cookies"
          :key="cookie.name"
          class="ca-cookie"
          :class="{ 'ca-cookie--tracking': cookie.is_tracking }"
        >
          <div class="ca-cookie-header">
            <span class="ca-cookie-name">{{ cookie.name }}</span>
            <span class="ca-cookie-tracker" v-if="cookie.tracker_name">
              {{ cookie.tracker_name }}
            </span>
            <span class="ca-cookie-risk" :class="`risk--${cookie.risk}`">
              {{ cookie.risk }}
            </span>
          </div>

          <div class="ca-cookie-attrs">
            <div class="ca-attr" :class="cookie.secure ? 'attr--good' : 'attr--bad'">
              <span class="ca-attr-name">Secure</span>
              <span class="ca-attr-value">{{ cookie.secure ? '✓' : '✗' }}</span>
              <span class="ca-attr-desc">
                {{ cookie.secure
                  ? 'Only sent over HTTPS'
                  : 'Sent over HTTP too — can be intercepted' }}
              </span>
            </div>
            <div class="ca-attr" :class="cookie.httponly ? 'attr--good' : 'attr--bad'">
              <span class="ca-attr-name">HttpOnly</span>
              <span class="ca-attr-value">{{ cookie.httponly ? '✓' : '✗' }}</span>
              <span class="ca-attr-desc">
                {{ cookie.httponly
                  ? 'Cannot be read by JavaScript'
                  : 'JavaScript can read this cookie — XSS risk' }}
              </span>
            </div>
            <div class="ca-attr"
              :class="cookie.samesite === 'Strict' || cookie.samesite === 'Lax'
                ? 'attr--good' : 'attr--warn'"
            >
              <span class="ca-attr-name">SameSite</span>
              <span class="ca-attr-value">{{ cookie.samesite ?? 'not set' }}</span>
              <span class="ca-attr-desc">{{ samesiteDesc(cookie.samesite) }}</span>
            </div>
            <div class="ca-attr">
              <span class="ca-attr-name">Expiry</span>
              <span class="ca-attr-value">
                {{ cookie.session ? 'session' :
                   cookie.expiry_days ? `${cookie.expiry_days} days` : '—' }}
              </span>
              <span class="ca-attr-desc">
                {{ cookie.session
                  ? 'Deleted when browser closes'
                  : cookie.expiry_days > 365
                    ? 'Persists for over a year'
                    : 'Persistent cookie' }}
              </span>
            </div>
            <div class="ca-attr">
              <span class="ca-attr-name">Domain</span>
              <span class="ca-attr-value detail-value--mono">
                {{ cookie.domain ?? 'current domain' }}
              </span>
              <span class="ca-attr-desc">
                {{ cookie.domain?.startsWith('.')
                  ? 'Sent to all subdomains'
                  : 'Current domain only' }}
              </span>
            </div>
          </div>

        </div>

      </div>
    </template>

    <template #data>
      <div class="detail-grid">
        <div class="detail-row">
          <span class="detail-label">Privacy grade</span>
          <span class="detail-value" :style="{ color: gradeColor }">
            {{ data.privacy_grade }}
          </span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Total cookies</span>
          <span class="detail-value">{{ data.total_cookies }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Tracking cookies</span>
          <span class="detail-value">{{ data.tracking_cookies }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Third-party cookies</span>
          <span class="detail-value">{{ data.third_party }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Session cookies</span>
          <span class="detail-value">{{ data.session_cookies }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">With Secure flag</span>
          <span class="detail-value">{{ data.secure_cookies }}/{{ data.total_cookies }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">With HttpOnly</span>
          <span class="detail-value">{{ data.httponly_cookies }}/{{ data.total_cookies }}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">With SameSite</span>
          <span class="detail-value">{{ data.samesite_cookies }}/{{ data.total_cookies }}</span>
        </div>
      </div>
    </template>

    <template #explanation>
      <div class="explanation">

        <div class="explanation__item">
          <h3>What are cookies?</h3>
          <p>Cookies are small pieces of data stored in your browser by websites. They serve legitimate purposes like keeping you logged in and remembering your preferences — but they're also the primary mechanism for tracking your behavior across the web.</p>
        </div>

        <div class="explanation__item">
          <h3>The Secure flag</h3>
          <p>A cookie with the Secure flag is only sent over HTTPS connections. Without it, the cookie is sent over plain HTTP too — meaning anyone on the same network (coffee shop WiFi, your ISP) can intercept and read it, potentially stealing your session.</p>
        </div>

        <div class="explanation__item">
          <h3>The HttpOnly flag</h3>
          <p>HttpOnly cookies cannot be read by JavaScript running on the page. This protects session tokens from Cross-Site Scripting (XSS) attacks — even if an attacker injects malicious JavaScript, they can't steal HttpOnly cookies.</p>
        </div>

        <div class="explanation__item">
          <h3>SameSite attribute</h3>
          <p><strong>Strict</strong> — cookie only sent when navigating directly to the site. Most restrictive, best for sensitive cookies.</p>
          <p><strong>Lax</strong> — cookie sent on top-level navigation (clicking a link). Good balance of security and usability.</p>
          <p><strong>None</strong> — cookie sent on all requests including cross-site. Required for legitimate cross-site features but also enables tracking across sites.</p>
          <p><strong>Not set</strong> — browser defaults vary. Modern browsers treat unset as Lax but this is not guaranteed.</p>
        </div>

        <div class="explanation__item">
          <h3>Privacy grade — {{ data.privacy_grade }}</h3>
          <p><strong>A</strong> — No tracking cookies, good security practices.</p>
          <p><strong>B</strong> — Minor issues — possibly missing HttpOnly or slightly long expiry.</p>
          <p><strong>C</strong> — Some tracking cookies present.</p>
          <p><strong>D</strong> — Significant tracking and security issues.</p>
          <p><strong>F</strong> — Majority of cookies are tracking and poorly secured.</p>
        </div>

      </div>
    </template>

  </DetailLayout>
</template>

<script setup>
import { computed } from 'vue'
import DetailLayout from './DetailLayout.vue'
import { useReport } from '@/composables/useReport.js'

const props = defineProps({
  slug: { type: String, required: true }
})

const { loading, error, audit, engines } = useReport(props.slug)

const engineData = computed(() => engines.value?.cookie_audit)
const data       = computed(() => engineData.value?.data)

const gradeColor = computed(() => ({
  A: '#22c55e', B: '#22c55e',
  C: '#f59e0b', D: '#f59e0b',
  F: '#ef4444',
}[data.value?.privacy_grade] ?? 'var(--color-text-secondary)'))

function samesiteDesc(val) {
  if (val === 'Strict') return 'Only sent on direct navigation — most secure'
  if (val === 'Lax')    return 'Sent on top-level navigation — good balance'
  if (val === 'None')   return 'Sent on all requests — enables cross-site tracking'
  return 'Not set — browser default applies'
}
</script>

<style scoped>
.loading, .error {
  text-align: center;
  padding: 4rem;
  color: var(--color-text-secondary);
}

.ca-visual { display: flex; flex-direction: column; gap: 1.5rem; }

.ca-summary {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  padding: 1.25rem;
  background: var(--color-background-primary);
  border: 0.5px solid var(--color-border-tertiary);
  border-radius: var(--border-radius-lg);
}

.ca-grade {
  font-size: 4rem;
  font-weight: 500;
  line-height: 1;
  min-width: 60px;
}

.ca-summary-stats {
  display: flex;
  gap: 1.5rem;
  flex-wrap: wrap;
}

.ca-stat {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.ca-stat-value {
  font-size: 1.5rem;
  font-weight: 500;
  color: var(--color-text-primary);
  line-height: 1;
}

.ca-stat-label {
  font-size: 0.72rem;
  color: var(--color-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.ca-trackers { display: flex; flex-direction: column; gap: 8px; }

.ca-trackers-label {
  font-size: 0.78rem;
  color: var(--color-text-secondary);
}

.ca-tracker-tags { display: flex; flex-wrap: wrap; gap: 6px; }

.ca-tracker-tag {
  font-size: 0.78rem;
  padding: 3px 10px;
  background: var(--color-background-warning);
  color: var(--color-text-warning);
  border-radius: var(--border-radius-md);
}

.ca-cookie {
  background: var(--color-background-primary);
  border: 0.5px solid var(--color-border-tertiary);
  border-radius: var(--border-radius-lg);
  overflow: hidden;
}

.ca-cookie--tracking {
  border-color: var(--color-border-warning);
}

.ca-cookie-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0.75rem 1rem;
  border-bottom: 0.5px solid var(--color-border-tertiary);
  background: var(--color-background-secondary);
}

.ca-cookie-name {
  font-family: var(--font-mono);
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--color-text-primary);
  flex: 1;
}

.ca-cookie-tracker {
  font-size: 0.72rem;
  padding: 2px 8px;
  background: var(--color-background-warning);
  color: var(--color-text-warning);
  border-radius: var(--border-radius-md);
}

.ca-cookie-risk {
  font-size: 0.72rem;
  padding: 2px 8px;
  border-radius: var(--border-radius-md);
}

.risk--none, .risk--low {
  background: var(--color-background-success);
  color: var(--color-text-success);
}
.risk--medium {
  background: var(--color-background-warning);
  color: var(--color-text-warning);
}
.risk--high {
  background: var(--color-background-danger);
  color: var(--color-text-danger);
}

.ca-cookie-attrs { display: flex; flex-direction: column; }

.ca-attr {
  display: grid;
  grid-template-columns: 80px 80px 1fr;
  gap: 8px;
  align-items: center;
  padding: 6px 1rem;
  border-bottom: 0.5px solid var(--color-border-tertiary);
  font-size: 0.8rem;
}

.ca-attr:last-child { border-bottom: none; }

.ca-attr-name { color: var(--color-text-tertiary); }

.ca-attr-value {
  font-family: var(--font-mono);
  font-size: 0.78rem;
  color: var(--color-text-primary);
}

.attr--good .ca-attr-value { color: var(--color-text-success); }
.attr--bad  .ca-attr-value { color: var(--color-text-danger); }
.attr--warn .ca-attr-value { color: var(--color-text-warning); }

.ca-attr-desc {
  color: var(--color-text-secondary);
  font-size: 0.78rem;
}

.detail-grid {
  display: flex;
  flex-direction: column;
  border: 0.5px solid var(--color-border-tertiary);
  border-radius: var(--border-radius-lg);
  overflow: hidden;
}

.detail-row {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.625rem 1rem;
  border-bottom: 0.5px solid var(--color-border-tertiary);
}

.detail-row:last-child { border-bottom: none; }

.detail-label {
  font-size: 0.8rem;
  color: var(--color-text-secondary);
  min-width: 160px;
  flex-shrink: 0;
}

.detail-value {
  font-size: 0.85rem;
  color: var(--color-text-primary);
}

.detail-value--mono { font-family: var(--font-mono); font-size: 0.8rem; }

.explanation { display: flex; flex-direction: column; gap: 1.5rem; }

.explanation__item h3 {
  font-size: 0.9rem;
  font-weight: 500;
  color: var(--color-text-primary);
  margin: 0 0 6px;
}

.explanation__item p {
  font-size: 0.85rem;
  color: var(--color-text-secondary);
  line-height: 1.6;
  margin: 0 0 6px;
}

.explanation__item p:last-child { margin-bottom: 0; }
</style>