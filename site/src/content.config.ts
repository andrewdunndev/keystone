import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { guideChapter } from '@dunn.dev/reference/folio-guide/schema';

export const collections = {
  docs: defineCollection({ loader: glob({ base: '../docs', pattern: 'setup.md' }) }),
  chapters: defineCollection({ loader: glob({ base: './src/guide', pattern: '*.md' }), schema: guideChapter() }),
};
