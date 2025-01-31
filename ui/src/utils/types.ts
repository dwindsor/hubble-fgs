// biome-ignore lint/suspicious/noExplicitAny: utility type
export type Builtin = Date | ((...rest: any[]) => any) | Uint8Array | string | number | boolean;

export type DeepPartial<T> = T extends Builtin
  ? T
  : T extends globalThis.Array<infer U>
    ? globalThis.Array<DeepPartial<U>>
    : T extends ReadonlyArray<infer U>
      ? ReadonlyArray<DeepPartial<U>>
      : T extends Record<string, never>
        ? { [K in keyof T]?: DeepPartial<T[K]> }
        : Partial<T>;
