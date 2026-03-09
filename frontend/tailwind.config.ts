import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/demo-dashboard/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
};

export default config;
