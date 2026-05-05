import ipaddr from "ipaddr.js";
import { type Destination, WorkloadKind } from "~/proto";
import { Enum, type EnumType } from "./enum";
import { specialIps } from "./ips";
import { capitalizeFirstLetter } from "./strings";
import { workloadKindAsHumanString } from "./workloads";

export const DestinationKind = Enum({
  ExternalIp: "destination-external-ip",
  InternalIp: "destination-internal-ip",
  ExternalDns: "destination-external-dns",
  InternalDns: "destination-internal-dns",
  Kubernetes: "destination-kubernetes",
  HostMetadataService: "destination-host-metadata-service",
  Other: "destination-other",
});
export type DestinationKind = EnumType<typeof DestinationKind>;

export const DestinationFilterKind = Enum({
  Internal: "destination-internal",
  External: "destination-external",
  Kubernetes: "destination-kubernetes",
  Other: "destination-other",
});
export type DestinationFilterKind = EnumType<typeof DestinationFilterKind>;

type NormalizedDestination =
  | { case: "ip"; ip: string | undefined }
  | { case: "workload"; hashPart: string; titlePart: string }
  | { case: "dns"; names: string[] }
  | { case: "unknown" };

function normalize(destination: Destination): NormalizedDestination {
  if ("type" in destination) {
    switch (destination.type.case) {
      case "ip":
        return { case: "ip", ip: destination.type.value.ip };
      case "workload": {
        const { namespace, kind, name } = destination.type.value;
        const titleNs = namespace ?? "<undefined>";
        const titleName = name ?? "<undefined>";
        return {
          case: "workload",
          hashPart: `${namespace}/${kind}/${name}`,
          titlePart: `${titleNs}/${kind}:${titleName}`,
        };
      }
      case "dns":
        return { case: "dns", names: destination.type.value.destination_names ?? [] };
      default:
        return { case: "unknown" };
    }
  }
  if ("ip" in destination) {
    return { case: "ip", ip: destination.ip?.ip };
  }
  if ("workload" in destination) {
    const { namespace, kind = WorkloadKind.Unspecified, name } = destination.workload ?? {};
    const titleNs = namespace ?? "<undefined>";
    const titleName = name ?? "<undefined>";
    return {
      case: "workload",
      hashPart: `${namespace}/${kind}/${name}`,
      titlePart: `${titleNs}/${capitalizeFirstLetter(workloadKindAsHumanString(kind))}:${titleName}`,
    };
  }
  if ("dns" in destination) {
    return { case: "dns", names: destination.dns?.destination_names ?? [] };
  }
  return { case: "unknown" };
}

function classifyIp(ip: string): DestinationKind {
  if (ip === "169.254.169.254:80") {
    return DestinationKind.HostMetadataService;
  }
  const type = ipaddr.subnetMatch(ipaddr.parse(ip), { internal: specialIps }, "external");
  return type === "internal" ? DestinationKind.InternalIp : DestinationKind.ExternalIp;
}

function classifyDns(name: string): DestinationKind {
  const n = name.replace(/\.$/, "").toLowerCase();
  if (n === "" || n === "localhost") return DestinationKind.InternalDns;
  if (ipaddr.isValid(n)) {
    return classifyIp(n) === DestinationKind.InternalIp
      ? DestinationKind.InternalDns
      : DestinationKind.ExternalDns;
  }
  if (n.startsWith("ip-") && n.endsWith(".internal")) return DestinationKind.InternalDns;
  if (n.endsWith(".local")) return DestinationKind.InternalDns;
  return DestinationKind.ExternalDns;
}

export function inferEndpointDestinationKind(destination: Destination): DestinationKind {
  const n = normalize(destination);
  switch (n.case) {
    case "ip":
      return classifyIp(n.ip ?? "");
    case "workload":
      return DestinationKind.Kubernetes;
    case "dns":
      return classifyDns(n.names.find((x) => x !== "") ?? "");
    case "unknown":
      return DestinationKind.Other;
  }
}

export function inferEndpointDestinationHash(destination: Destination): string {
  const { port } = destination;
  const n = normalize(destination);
  switch (n.case) {
    case "ip":
      return `destination/${n.ip}:${port}`;
    case "workload":
      return `destination/${n.hashPart}:${port}`;
    case "dns":
      return `destination/{${[...n.names].sort().join(",")}}:${port}`;
    case "unknown":
      return "destination/<undefined>";
  }
}

export function inferEndpointDestinationTitle(destination: Destination): string {
  const n = normalize(destination);
  switch (n.case) {
    case "ip":
      return n.ip ?? "<undefined>";
    case "workload":
      return n.titlePart;
    case "dns":
      return n.names
        .filter((x) => x !== "")
        .sort()
        .join(",");
    case "unknown":
      return "<undefined>";
  }
}
