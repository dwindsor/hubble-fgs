export function assert(condition: unknown, msg?: string): asserts condition {
  if (!condition) {
    throw new Error(msg);
  }
}

export function assertUnreachable(_x: never, message = "Unhandled case"): never {
  throw new Error(message);
}
