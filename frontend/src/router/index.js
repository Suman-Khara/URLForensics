import { createRouter, createWebHistory } from 'vue-router'
import HomeView   from '../views/HomeView.vue'
import ReportView from '../views/ReportView.vue'

const routes = [
  {
    path: '/',
    component: HomeView,
  },
  {
    path: '/report/:slug',
    component: ReportView,
    props: true,
  },
  {
    path: '/report/:slug/redirect-trail',
    component: () => import('../views/detail/RedirectTrailDetail.vue'),
    props: true,
  },
  
  {
    path: '/report/:slug/dns-propagation',
    component: () => import('../views/detail/DNSPropagationDetail.vue'),
    props: true,
  },
  {
    path: '/report/:slug/tls-timeline',
    component: () => import('../views/detail/TLSTimelineDetail.vue'),
    props: true,
  },
  {
    path: '/report/:slug/cookie-audit',
    component: () => import('../views/detail/CookieAuditDetail.vue'),
    props: true,
  },
  {
    path: '/report/:slug/packet-journey',
    component: () => import('../views/detail/PacketJourneyDetail.vue'),
    props: true,
  },
  {
    path: '/report/:slug/dns-resolution',
    component: () => import('../views/detail/DNSResolutionDetail.vue'),
    props: true,
  },
]

export default createRouter({
  history: createWebHistory(),
  routes,
})