import { glob } from 'astro/loaders';
import { defineCollection, z } from 'astro:content';

const blog = defineCollection({
  loader: glob({ base: './src/content/blog', pattern: '**/*.{md,mdx}' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    pubDate: z.coerce.date(),
    updatedDate: z.coerce.date().optional(),
    heroImage: z.string().optional(),
  }),
});

const savinotes = defineCollection({
  loader: glob({ base: './src/content/savinotes', pattern: '**/*.{md,mdx}' }),
  schema: z.object({
    title: z.string(),
    description: z.string().optional(),  // opcional
    pubDate: z.coerce.date().optional(), // opcional si date existe
    date: z.coerce.date().optional(),    // acepta 'date' también
    updatedDate: z.coerce.date().optional(),
    heroImage: z.string().optional(),
  }),
});

const blue_team = defineCollection({
  loader: glob({ base: './src/content/blue_team', pattern: '**/*.{md,mdx}' }),
  schema: z.object({
    title: z.string(),
    description: z.string().optional(),  // opcional
    pubDate: z.coerce.date().optional(), // opcional si date existe
    date: z.coerce.date().optional(),    // acepta 'date' también
    updatedDate: z.coerce.date().optional(),
    heroImage: z.string().optional(),
  }),
});

const red_team = defineCollection({
  loader: glob({ base: './src/content/red_team', pattern: '**/*.{md,mdx}' }),
  schema: z.object({
    title: z.string(),
    description: z.string().optional(),  // opcional
    pubDate: z.coerce.date().optional(), // opcional si date existe
    date: z.coerce.date().optional(),    // acepta 'date' también
    updatedDate: z.coerce.date().optional(),
    heroImage: z.string().optional(),
  }),
});

const developer = defineCollection({
  loader: glob({ base: './src/content/developer', pattern: '**/*.{md,mdx}' }),
  schema: z.object({
    title: z.string(),
    description: z.string().optional(),  // opcional
    pubDate: z.coerce.date().optional(), // opcional si date existe
    date: z.coerce.date().optional(),    // acepta 'date' también
    updatedDate: z.coerce.date().optional(),
    heroImage: z.string().optional(),
  }),
});

const devops = defineCollection({
  loader: glob({ base: './src/content/devops', pattern: '**/*.{md,mdx}' }),
  schema: z.object({
    title: z.string(),
    description: z.string().optional(),  // opcional
    pubDate: z.coerce.date().optional(), // opcional si date existe
    date: z.coerce.date().optional(),    // acepta 'date' también
    updatedDate: z.coerce.date().optional(),
    heroImage: z.string().optional(),
  }),
});

export const collections = { blog, savinotes, blue_team, red_team, developer, devops };
