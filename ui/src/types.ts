import { ApplicationProcess } from "./proto/appmodel";

export type XY = { x: number; y: number };

export type WH = { width: number; height: number };

export type XYWH = XY & WH;

export type ProcessesMap = WeakMap<ApplicationProcess, ProcessInfo>;

export type ProcessInfo = {
  visible?: boolean | undefined;
  xy?: XY | undefined;
  endpoints: string[];
};

export type EndpointsMap = Map<string, EndpointInfo>;

export type EndpointInfo = { xy?: XY };

export type Connection = { proc: ApplicationProcess; endpoint: string };
