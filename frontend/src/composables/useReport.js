import { ref, onMounted } from 'vue'
import axios from 'axios'

export function useReport(slug) {

  const loading = ref(true)
  const error   = ref(null)
  const audit   = ref(null)
  const engines = ref({})

  onMounted(async () => {
    try {
      const response = await axios.get(
        `/api/report/get.php?slug=${slug}`
      )
      audit.value   = response.data.audit
      engines.value = response.data.engines
    } catch (err) {
      error.value = err.response?.status === 404
        ? 'Report not found'
        : 'Failed to load report'
    } finally {
      loading.value = false
    }
  })

  return { loading, error, audit, engines }
}