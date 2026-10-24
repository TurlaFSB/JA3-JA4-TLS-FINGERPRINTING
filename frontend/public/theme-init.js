// Sets the colour theme before first paint so the page does not flash. A
// separate file, not inline, so the Content-Security-Policy can forbid inline
// script.
try {
  var t = JSON.parse(localStorage.getItem('ui-storage') || '{}').state
  var theme = (t && t.theme) || 'dark'
  if (theme === 'system') {
    theme = matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
  }
  document.documentElement.dataset.theme = theme
} catch (e) {}
