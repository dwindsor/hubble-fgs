import { EndpointKind } from "~/types";

export const endpointsKindOrder = [
  EndpointKind.OuterDns,
  EndpointKind.K8s,
  EndpointKind.HostMetadataService,
  EndpointKind.Ip,
  EndpointKind.InnerDns,
].reduce((acc, item, idx) => {
  acc[item] = idx;
  return acc;
}, {} as { [key in EndpointKind]: number });

export function inferEndpointKind(endpoint: string): EndpointKind {
  const endpointWithoutPort = trimEndpointPort(endpoint);

  if (endpoint === "169.254.169.254:80") {
    return EndpointKind.HostMetadataService;
  }
  if (endpointWithoutPort.includes("/")) {
    return EndpointKind.K8s;
  }
  if (checkIpAddress(endpointWithoutPort)) {
    return EndpointKind.Ip;
  }
  if (
    (endpointWithoutPort.startsWith("ip-") &&
      endpointWithoutPort.endsWith(".internal")) ||
    endpointWithoutPort.endsWith(".svc.cluster.local")
  ) {
    return EndpointKind.InnerDns;
  }
  return EndpointKind.OuterDns;
}

export function getEndpointPort(endpoint: string): string | null {
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

export function trimEndpointPort(endpoint: string): string {
  const port = getEndpointPort(endpoint);
  return endpoint.slice(0, endpoint.length - (port ? port.length + 1 : 0));
}

export function checkIpAddress(value: string): boolean {
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/;
  return ipv4Pattern.test(value) || ipv6Pattern.test(value);
}
