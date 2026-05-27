/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{tsx,ts}', './App.tsx'],
  darkMode: 'selector',
  theme: {
    extend: {
      colors: {
        primary: {
          light: '#3b82f6',
          dark: '#60a5fa',
        },
        secondary: {
          light: '#f3f4f6',
          dark: '#4b5563',
        },
      },
      backgroundImage: {
        'gradient-light': 'linear-gradient(to bottom right, #f9fafb, #e5e7eb)',
        'gradient-dark': 'linear-gradient(to bottom right, #1f2937, #111827)',
      },
    },
  },
  plugins: [require('@tailwindcss/typography')],
};