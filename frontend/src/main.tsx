// ===========================
// ©AngelaMos | 2025
// main.tsx
// ===========================

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import './styles.scss'

// A new build renames its script files. A tab opened before the update then
// asks for a file that is gone; reload once to pick up the current page. The
// session flag stops a genuine fault from looping.
window.addEventListener('vite:preloadError', (event) => {
  event.preventDefault()
  try {
    if (sessionStorage.getItem('tlsfp-reloaded') === '1') return
    sessionStorage.setItem('tlsfp-reloaded', '1')
  } catch {
    return
  }
  window.location.reload()
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>
)
