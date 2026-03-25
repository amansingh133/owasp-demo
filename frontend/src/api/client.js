import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  withCredentials: true,          // send HttpOnly cookies
  headers: { 'Content-Type': 'application/json' },
})

// Auto-refresh on 401
api.interceptors.response.use(
  (r) => r,
  async (err) => {
    const orig = err.config
    if (err.response?.status === 401 && !orig._retry) {
      orig._retry = true
      try {
        await axios.post('/api/auth/refresh', {}, { withCredentials: true })
        return api(orig)
      } catch {
        window.location.href = '/login'
      }
    }
    return Promise.reject(err)
  }
)

export default api
