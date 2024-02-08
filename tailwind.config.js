/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./templates/**/*.html", "./assets/style.css", "./src/**/*.rs"],
  theme: {
    extend: {
      colors: {
        primary: "var(--primary-color)",
        secondary: "var(--secondary-color)",
        highlight: "var(--highlight-color)",
        font: "var(--font-color)",
        error: "var(--error-color)",
      }
    },
  },
  plugins: [],
}

