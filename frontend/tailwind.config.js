/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        brutal: {
          bg: "#0c0e14",
          card: "#141824",
          border: "#000000",
          lime: "#bef264",       // Electric Lime
          limeDark: "#a3e635",
          amber: "#fde047",      // Electric Yellow/Amber
          amberDark: "#eab308",
          cyan: "#67e8f9",       // High-voltage Cyan
          cyanDark: "#06b6d4",
          coral: "#fca5a5",      // Hot Coral Red
          coralDark: "#ef4444",
          purple: "#d8b4fe",     // Cyber Violet
          purpleDark: "#a855f7",
          cream: "#f4f4f5",
          muted: "#94a3b8"
        }
      },
      boxShadow: {
        'brutal': '4px 4px 0px 0px #000000',
        'brutal-sm': '2px 2px 0px 0px #000000',
        'brutal-lg': '6px 6px 0px 0px #000000',
        'brutal-xl': '8px 8px 0px 0px #000000',
        'brutal-lime': '4px 4px 0px 0px #a3e635',
        'brutal-cyan': '4px 4px 0px 0px #06b6d4',
        'brutal-amber': '4px 4px 0px 0px #eab308',
        'brutal-coral': '4px 4px 0px 0px #ef4444',
        'brutal-purple': '4px 4px 0px 0px #a855f7',
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'Menlo', 'Monaco', 'Courier New', 'monospace'],
        sans: ['"Inter"', 'system-ui', '-apple-system', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
