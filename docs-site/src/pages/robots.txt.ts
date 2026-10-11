import type { APIRoute } from 'astro'

// Search engines and AI assistants are all welcome: the docs are public and meant to be found, quoted and linked. The
// AI crawlers are named so that a blanket rule added elsewhere (a CDN's "block AI bots" switch) is easy to spot.
const AI_CRAWLERS = [
  'GPTBot',
  'OAI-SearchBot',
  'ChatGPT-User',
  'ClaudeBot',
  'Claude-User',
  'Claude-SearchBot',
  'PerplexityBot',
  'Google-Extended',
  'Applebot-Extended',
  'CCBot',
]

export const GET: APIRoute = ({ site }) => {
  const base = import.meta.env.BASE_URL.replace(/\/?$/, '/')
  const sitemap = new URL(`${base}sitemap-index.xml`, site)
  const groups = [...AI_CRAWLERS, '*'].map((agent) => `User-agent: ${agent}\nAllow: /\n`)
  return new Response(`${groups.join('\n')}\nSitemap: ${sitemap}\n`, {
    headers: { 'content-type': 'text/plain; charset=utf-8' },
  })
}
