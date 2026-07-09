/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#0a0a0a',
        primary: '#06b6d4',
        secondary: '#3b82f6',
        accent: '#d946ef',
        glove: '#ff3b3b',
        dim: '#6b7280',
        panel: '#111111',
        border: '#1e293b',
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', 'monospace'],
      },
      boxShadow: {
        neon: '0 0 10px rgba(6, 182, 212, 0.4), 0 0 20px rgba(6, 182, 212, 0.2)',
        'neon-magenta': '0 0 10px rgba(217, 70, 239, 0.4)',
      },
    },
  },
  plugins: [],
}
