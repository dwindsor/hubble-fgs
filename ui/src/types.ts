import { ApplicationProcess } from "./proto/appmodel";

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
