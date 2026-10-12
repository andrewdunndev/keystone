// Stand-in for the cloudflare:workers module, which exists only in the Workers runtime.
export class DurableObject {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }
}
