import ipaddr from "ipaddr.js";
import type { ApplicationConnection } from "~/proto";
import { Enum, type EnumType } from "./enum";
import type { XY } from "./geometry";
import { checkIpAddress, specialIps } from "./ips";

export type Endpoint = string;

export const EndpointMode = Enum({
  Hovered: "hovered",
  Pinned: "pinned",
});

export type EndpointMode = EnumType<typeof EndpointMode>;

export type EndpointsMap = Map<Endpoint, EndpointInfo>;

export type EndpointInfo = {
  kind: EndpointKind;
  visible?: boolean | undefined;
  xy?: XY | undefined;
};

export const EndpointKind = Enum({
  OuterIp: "Outer-ip",
  InnerIp: "inner-ip",
  OuterDns: "outer-dns",
  InnerDns: "inner-dns",
  Kube: "kube",
  HostMetadataService: "host-metadata-service",
  Other: "other",
});

export type EndpointKind = EnumType<typeof EndpointKind>;

export const endpointsKindOrder = [
  EndpointKind.OuterDns,
  EndpointKind.OuterIp,
  EndpointKind.HostMetadataService,
  EndpointKind.Kube,
  EndpointKind.InnerDns,
  EndpointKind.InnerIp,
].reduce(
  (acc, item, idx) => {
    acc[item] = idx;
    return acc;
  },
  {} as { [key in EndpointKind]: number },
);

export function inferEndpointKind(endpoint: Endpoint): EndpointKind {
  const endpointWithoutPort = trimEndpointPort(endpoint);

  if (endpoint === "169.254.169.254:80") {
    return EndpointKind.HostMetadataService;
  }
  if (endpointWithoutPort.includes("/")) {
    return EndpointKind.Kube;
  }
  if (checkIpAddress(endpointWithoutPort)) {
    const ranges = {
      inner: specialIps,
    };
    const type = ipaddr.subnetMatch(ipaddr.parse(endpointWithoutPort), ranges, "outer");
    return type === "inner" ? EndpointKind.InnerIp : EndpointKind.OuterIp;
  }
  if (
    (endpointWithoutPort.startsWith("ip-") && endpointWithoutPort.endsWith(".internal")) ||
    endpointWithoutPort.endsWith(".svc.cluster.local")
  ) {
    return EndpointKind.InnerDns;
  }
  return EndpointKind.OuterDns;
}

export function getEndpointPort(endpoint: Endpoint): string | null {
  let port = "";
  for (let i = endpoint.length - 1; i >= 0; i--) {
    const ch = endpoint[i];
    if (ch === ":") {
      return port;
    }
    port = ch + port;
  }
  return null;
}

export function trimEndpointPort(endpoint: Endpoint): string {
  const port = getEndpointPort(endpoint);
  return endpoint.slice(0, endpoint.length - (port ? port.length + 1 : 0));
}

export function constructEndpoint(conn: ApplicationConnection): Endpoint {
  return `${conn.destinationName}:${conn.destinationPort}`;
}
