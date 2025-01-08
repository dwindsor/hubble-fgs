import { ApplicationProcess } from "./proto";

export type XY = { x: number; y: number };

export type WH = { width: number; height: number };

export type XYWH = XY & WH;

export type ProcessesMap = WeakMap<ApplicationProcess, ProcessInfo>;

export type ProcessInfo = {
  visible?: boolean | undefined;
  xy?: XY | undefined;
  endpoints: Set<string>;
};

export type EndpointsMap = Map<string, EndpointInfo>;

export type EndpointInfo = {
  visible?: boolean | undefined;
  xy?: XY | undefined;
};

export type ConnectionsMap = Map<
  string /* endpoint */,
  Set<ApplicationProcess>
>;

export type Builtin = Date | Function | Uint8Array | string | number | boolean;

export type DeepPartial<T> = T extends Builtin
  ? T
  : T extends globalThis.Array<infer U>
  ? globalThis.Array<DeepPartial<U>>
  : T extends ReadonlyArray<infer U>
  ? ReadonlyArray<DeepPartial<U>>
  : T extends {}
  ? { [K in keyof T]?: DeepPartial<T[K]> }
  : Partial<T>;
