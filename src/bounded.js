// An isolate's caches are emptied when they reach max, so their memory stays bounded. Call before inserting.
export function bounded(cache, max) {
  if (cache.size >= max) cache.clear();
  return cache;
}
