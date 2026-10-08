import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';

export const collections = {
  docs: defineCollection({ loader: glob({ base: '../docs', pattern: 'setup.md' }) }),
};
