// n as len big-endian bytes.
export const be = (n, len) => Uint8Array.from(n.toString(16).padStart(len * 2, '0').match(/../g).map((x) => parseInt(x, 16)));
