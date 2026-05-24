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
]

export default createRouter({
  history: createWebHistory(),
  routes,
})