// @ts-check
import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
	site: 'https://lund133369.github.io',
	base: 'astro_github_pages_ejemplo',
	integrations: [mdx(), sitemap()],
});
