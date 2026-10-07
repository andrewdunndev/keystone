import { registerHooks } from 'node:module';
registerHooks({
  resolve(specifier, context, next) {
    if (specifier === 'cloudflare:email') return { url: new URL('./cloudflare-email.mjs', import.meta.url).href, shortCircuit: true };
    return next(specifier, context);
  },
});
