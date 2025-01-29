import type { ApplicationProcess } from "./proto";

export type XY = { x: number; y: number };

export type WH = { width: number; height: number };

export type Line = { from: XY; to: XY };

export type ConnectionLine = Line & { color: string };

export type Connector = XY & { color: string };

export type XYWH = XY & WH;

export type ProcessesMap = WeakMap<ApplicationProcess, ProcessInfo>;

export type TreeClusterPath = { cluster: true };
export type TreeNodePath = { node: true };
export type TreeHostPath = { host: true };
export type TreeHostProcPath = { path: string[] };
export type TreeNamespacesPath = { namespaces: true };
export type TreeNamespacePath = { namespace: string };
export type TreeWorkloadPath = TreeNamespacePath & { workload: string };
export type TreeWorkloadProcPath = TreeWorkloadPath & { path: string[] };
export type TreePath =
  | TreeClusterPath
  | TreeNodePath
  | TreeHostPath
  | TreeHostProcPath
  | TreeNamespacesPath
  | TreeNamespacePath
  | TreeWorkloadPath
  | TreeWorkloadProcPath;

export type TreePathStatus = {
  expanded?: boolean;
  visible?: boolean;
};

export type PropertyValues<Obj> = Obj[Exclude<keyof Obj, "__proto__">];

export type ProcessInfo = {
  path: TreePath;
  visible?: boolean | undefined;
  xy?: XY | undefined;
};

export type EndpointsMap = Map<string, EndpointInfo>;

export type EndpointInfo = {
  kind: EndpointKindType;
  visible?: boolean | undefined;
  xy?: XY | undefined;
};

export const EndpointKind = {
  __proto__: null,
  OuterIp: "Outer-ip",
  InnerIp: "inner-ip",
  OuterDns: "outer-dns",
  InnerDns: "inner-dns",
  K8s: "k8s",
  HostMetadataService: "host-metadata-service",
  Other: "other",
} as const;

export type EndpointKindType = PropertyValues<typeof EndpointKind>;

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
