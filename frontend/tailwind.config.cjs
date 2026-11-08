/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        ops: {
          canvas: "#080e18",
          sidebar: "#0b1421",
          panel: "#101a29",
          elevated: "#142236",
          line: "#26384d",
          muted: "#8b9bb0",
          accent: "#63b6f4",
          success: "#4fce9a",
          warning: "#e7ae61",
          danger: "#e77b7b"
        }
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "monospace"]
      },
      boxShadow: {
        "ops-panel": "0 18px 50px rgba(0, 0, 0, .18)",
        "ops-glow": "0 0 24px rgba(99, 182, 244, .12)"
      }
    }
  },
  plugins: []
};
