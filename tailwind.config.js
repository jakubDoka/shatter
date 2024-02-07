/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./templates/**/*.html", "./assets/style.css"],
  theme: {
    extend: {
      colors: {
        primary: "var(--color-primary)",
        secondary: "var(--color-secondary)",
        highlight: "var(--color-highlight)",
        font: "var(--color-font)",
      }
    },
  },
  plugins: [],
}

