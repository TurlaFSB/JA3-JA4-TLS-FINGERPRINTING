// Sets the colour theme before first paint so the page does not flash. A
// separate file, not inline, so the Content-Security-Policy can forbid inline
// script.
try {
  const saved = JSON.parse(localStorage.getItem('ui-storage') || '{}').state
  let theme = saved?.theme || 'dark'
  if (theme === 'system') {
    theme = matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
  }
  document.documentElement.dataset.theme = theme
} catch {
  // Storage can be blocked; the stylesheet's default theme applies.
}
