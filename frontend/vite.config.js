import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'

export default defineConfig({
  plugins: [vue()],

  resolve: {
    alias: {
      // lets you write import '@/components/...' instead of
      // import '../../components/...' — cleaner imports everywhere
      '@': path.resolve(__dirname, './src'),
    }
  },

  server: {
    port: 5173,
    proxy: {
      // Any request from Vue starting with /api
      // gets forwarded to Apache on port 80
      '/api': {
        target: 'http://localhost:80',
        changeOrigin: true,
      }
    }
  },

  build: {
    // When you run npm run build, output goes to project root
    // so Apache serves the built Vue app from /var/www/html
    outDir: '../',
    emptyOutDir: false,  // don't delete your PHP files on build
  }
})