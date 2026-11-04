// Builds serial_deck/web_assets/tailwind.css (see tools/build_css.sh).
// The dashboard no longer ships the Tailwind Play CDN; this is the only config.
// Colors are theme tokens ("R G B" CSS variables set in web.py) so the
// Appearance panel can switch themes without rebuilding.
module.exports = {
  content: ['serial_deck/*.py'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        brand: {
          bg: 'rgb(var(--c-bg) / <alpha-value>)',
          surface: 'rgb(var(--c-surface) / <alpha-value>)',
          surfaceAlt: 'rgb(var(--c-surfaceAlt) / <alpha-value>)',
          border: 'rgb(var(--c-border) / <alpha-value>)',
          accent: 'rgb(var(--c-accent) / <alpha-value>)',
          accentHover: 'rgb(var(--c-cyan) / <alpha-value>)',
          flash: 'rgb(var(--c-flash) / <alpha-value>)',
          flashHover: 'rgb(var(--c-warning) / <alpha-value>)',
          danger: 'rgb(var(--c-danger) / <alpha-value>)',
          success: 'rgb(var(--c-success) / <alpha-value>)',
          warning: 'rgb(var(--c-warning) / <alpha-value>)',
          cyan: 'rgb(var(--c-cyan) / <alpha-value>)',
          blue: 'rgb(var(--c-blue) / <alpha-value>)',
          purple: 'rgb(var(--c-purple) / <alpha-value>)',
          tx: 'rgb(var(--c-tx) / <alpha-value>)',
          muted: 'rgb(var(--c-muted) / <alpha-value>)',
          text: 'rgb(var(--c-text) / <alpha-value>)',
          console: 'rgb(var(--c-console) / <alpha-value>)',
          onFlash: 'rgb(var(--c-onFlash) / <alpha-value>)',
        },
      },
    },
  },
};
