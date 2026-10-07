// Stand-in for the cloudflare:email module, which exists only in the Workers runtime.
export class EmailMessage {
  constructor(from, to, raw) {
    this.from = from;
    this.to = to;
    this.raw = raw;
  }
}
