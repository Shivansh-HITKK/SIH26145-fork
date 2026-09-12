/** @type {import('next').NextConfig} */
const nextConfig = {
  typescript: {
    ignoreBuildErrors: true,
  },
  allowedDevOrigins: ['127.0.0.1', '*.app.github.dev'],
  images: {
    unoptimized: true,
  },
}

export default nextConfig
