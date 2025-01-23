import type { ApplicationProcess } from "./proto";

export type XY = { x: number; y: number };

export type WH = { width: number; height: number };

export type Line = { from: XY; to: XY };

export type ConnectionLine = Line & { color: string };

export type Connector = XY & { color: string };

export type XYWH = XY & WH;

export type ProcessesMap = WeakMap<ApplicationProcess, ProcessInfo>;

export type PropertyValues<Obj> = Obj[Exclude<keyof Obj, "__proto__">];

export type ProcessInfo = {
  visible?: boolean | undefined;
  xy?: XY | undefined;
};

export type EndpointsMap = Map<string, EndpointInfo>;

export type EndpointInfo = {
  kind: EndpointKind;
  visible?: boolean | undefined;
  xy?: XY | undefined;
};

export const EndpointKind = {
  __proto__: null,
  Ip: "inner-ip",
  OuterDns: "outer-dns",
  InnerDns: "inner-dns",
  K8s: "k8s",
  HostMetadataService: "host-metadata-service",
  Other: "other",
} as const;

export type EndpointKind = PropertyValues<typeof EndpointKind>;

export type ConnectionsMap = Map<string /* endpoint */, Set<ApplicationProcess>>;

// biome-ignore lint/suspicious/noExplicitAny: <explanation>
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
