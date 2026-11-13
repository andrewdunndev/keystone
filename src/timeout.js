// The promise's outcome, or a rejection with `message` once `ms` pass first.
export async function withTimeout(promise, ms, message) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), ms); })]);
  } finally {
    clearTimeout(timer);
  }
}
