import { type ApplicationFileEvent, type Destination, FileEventKind } from "~/proto";
import {
  DestinationKind,
  inferEndpointDestinationHash,
  inferEndpointDestinationKind,
  inferEndpointDestinationTitle,
} from "./destination";
import { Enum, type EnumType } from "./enum";
import {
  inferEndpointFileEventHash,
  inferEndpointFileEventKind,
  inferEndpointFileEventTitle,
} from "./file-event";
import type { XY } from "./geometry";
import type { ThrowableMap } from "./throwable-map";

export type Endpoint = Destination | ApplicationFileEvent;

export const EndpointModeKind = Enum({
  Hovered: "hovered",
  Pinned: "pinned",
});

export type EndpointModeKind = EnumType<typeof EndpointModeKind>;

export const EndpointKind = Enum({
  Destination: "destination",
  FileEvent: "file",
});

export type EndpointKind = EnumType<typeof EndpointKind>;

export type EndpointSubKind = EnumType<typeof DestinationKind> | EnumType<typeof FileEventKind>;

export type EndpointsMap = ThrowableMap<Endpoint, EndpointInfo>;

export type EndpointsHashMap = ThrowableMap<string, Endpoint>;

export type EndpointInfo = {
  hash: string;
  kind: EndpointKind;
  subKind: EndpointSubKind;
  visible?: boolean | undefined;
  xy?: XY | undefined;
};

export const endpointsKindOrder = [
  DestinationKind.OuterDns,
  DestinationKind.OuterIp,
  DestinationKind.HostMetadataService,
  DestinationKind.Kubernetes,
  DestinationKind.InnerDns,
  DestinationKind.InnerIp,
  FileEventKind.Read,
  FileEventKind.Write,
].reduce(
  (acc, item, idx) => {
    acc[item] = idx;
    return acc;
  },
  {} as { [key in DestinationKind | FileEventKind]: number },
);

export function inferEndpointSubKind(endpoint: Endpoint, kind: EndpointKind): EndpointSubKind {
  if (kind === EndpointKind.Destination) {
    return inferEndpointDestinationKind(endpoint as Destination);
  }
  if (kind === EndpointKind.FileEvent) {
    return inferEndpointFileEventKind(endpoint as ApplicationFileEvent);
  }
  throw new Error(`Unhandled endpoint type: ${kind}`);
}

export function inferEndpointHash(endpoint: Endpoint, kind: EndpointKind): string {
  if (kind === EndpointKind.Destination) {
    return inferEndpointDestinationHash(endpoint as Destination);
  }
  if (kind === EndpointKind.FileEvent) {
    return inferEndpointFileEventHash(endpoint as ApplicationFileEvent);
  }
  throw new Error(`Unhandled endpoint type: ${kind}`);
}

export function inferEndpointTitle(endpoint: Endpoint, kind: EndpointKind): string {
  if (kind === EndpointKind.Destination) {
    return inferEndpointDestinationTitle(endpoint as Destination);
  }
  if (kind === EndpointKind.FileEvent) {
    return inferEndpointFileEventTitle(endpoint as ApplicationFileEvent);
  }
  throw new Error(`Unhandled endpoint type: ${kind}`);
}
