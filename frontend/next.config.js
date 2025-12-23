/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: 'export',
  // Required for static hosting with FastAPI StaticFiles(html=True):
  // ensures routes like /demo map to demo/index.html (instead of demo.html).
  trailingSlash: true,
};

module.exports = nextConfig;
