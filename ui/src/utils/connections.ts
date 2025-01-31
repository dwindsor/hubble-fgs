import type { ApplicationProcessGroup } from "~/proto";
import type { Endpoint } from "./endpoints";
import type { Line, XY } from "./geometry";

export type ConnectionsMap = Map<Endpoint, Set<ApplicationProcessGroup>>;

export type ConnectionLine = Line & { color: string };

export type Connector = XY & { color: string };
