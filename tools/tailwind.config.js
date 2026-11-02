// Builds serial_deck/web_assets/tailwind.css (see tools/build_css.sh).
// The dashboard no longer ships the Tailwind Play CDN; this is the only config.
module.exports = {
  content: ['serial_deck/*.py'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        brand: {
          bg: '#111318', surface: '#1e2024', surfaceAlt: '#1a1c20', border: '#3b494c',
          accent: '#00e5ff', accentHover: '#00daf3', flash: '#fd9000', flashHover: '#ffb778',
          danger: '#ff6b61', success: '#22ef7e', warning: '#ffb778', cyan: '#00daf3',
          blue: '#8fd8ff', purple: '#b1ffbf', tx: '#ff8fd8', muted: '#bac9cc', text: '#e2e2e8',
        },
      },
    },
  },
};
