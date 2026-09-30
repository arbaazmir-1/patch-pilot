import { defineConfig } from 'astro/config';
import node from '@astrojs/node';

export default defineConfig({
  output: 'server',
  adapter: node({ mode: 'standalone' }),
  // local only, origin check 403s form posts
  security: {
    checkOrigin: false,
  },
  vite: {
    ssr: {
      // native module
      external: ['better-sqlite3'],
    },
  },
});
