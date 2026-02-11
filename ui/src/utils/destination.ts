import ipaddr from "ipaddr.js";
import { type Destination, WorkloadKind } from "~/proto";
import { Enum, type EnumType } from "./enum";
import { specialIps } from "./ips";
import { capitalizeFirstLetter } from "./strings";
import { workloadKindAsHumanString } from "./workloads";

export const DestinationKind = Enum({
  OuterIp: "destination-outer-ip",
  InnerIp: "destination-inner-ip",
  OuterDns: "destination-outer-dns",
  InnerDns: "destination-inner-dns",
  Kubernetes: "destination-kubernetes",
  HostMetadataService: "destination-host-metadata-service",
  Other: "destination-other",
});
export type DestinationKind = EnumType<typeof DestinationKind>;

export const DestinationFilterKind = Enum({
  Inner: "destination-inner",
  Outer: "destination-outer",
  Kubernetes: "destination-kubernetes",
  Other: "destination-other",
});
export type DestinationFilterKind = EnumType<typeof DestinationFilterKind>;

export function inferEndpointDestinationKind(destination: Destination): DestinationKind {
  if ("type" in destination) {
    switch (destination.type.case) {
      case "ip": {
        if (destination.type.value.ip === "169.254.169.254:80") {
          return DestinationKind.HostMetadataService;
        }
        const ranges = {
          inner: specialIps,
        };
        const type = ipaddr.subnetMatch(
          ipaddr.parse(destination.type.value.ip ?? ""),
          ranges,
          "outer",
        );
        return type === "inner" ? DestinationKind.InnerIp : DestinationKind.OuterIp;
      }

      case "workload": {
        return DestinationKind.Kubernetes;
      }

      case "dns": {
        const dns = destination.type.value.destination_names[0] ?? "";
        if (
          (dns.startsWith("ip-") && dns.endsWith(".internal")) ||
          dns.endsWith(".svc.cluster.local")
        ) {
          return DestinationKind.InnerDns;
        }
        return DestinationKind.OuterDns;
      }
      default:
        break;
    }
  } else {
    if ("ip" in destination) {
      if (destination.ip?.ip === "169.254.169.254:80") {
        return DestinationKind.HostMetadataService;
      }
      const ranges = {
        inner: specialIps,
      };
      const type = ipaddr.subnetMatch(ipaddr.parse(destination.ip?.ip ?? ""), ranges, "outer");
      return type === "inner" ? DestinationKind.InnerIp : DestinationKind.OuterIp;
    }

    if ("workload" in destination) {
      return DestinationKind.Kubernetes;
    }

    if ("dns" in destination) {
      const dns = destination.dns?.destination_names[0] ?? "";
      if (
        (dns.startsWith("ip-") && dns.endsWith(".internal")) ||
        dns.endsWith(".svc.cluster.local")
      ) {
        return DestinationKind.InnerDns;
      }
      return DestinationKind.OuterDns;
    }
  }

  return DestinationKind.Other;
}

export function inferEndpointDestinationHash(destination: Destination): string {
  const { port } = destination;

  if ("type" in destination) {
    switch (destination.type.case) {
      case "ip":
        return `destination/${destination.type.value.ip}:${port}`;
      case "workload":
        return `destination/${destination.type.value.namespace}/${destination.type.value.kind}/${destination.type.value.name}:${port}`;
      case "dns":
        return `destination/{${[...(destination.type.value.destination_names ?? [])].sort().join(",")}}:${port}`;
      default:
        break;
    }
  } else {
    if ("ip" in destination) {
      return `destination/${destination.ip?.ip}:${port}`;
    }
    if ("workload" in destination) {
      return `destination/${destination.workload?.namespace}/${destination.workload?.kind}/${destination.workload?.name}:${port}`;
    }
    if ("dns" in destination) {
      return `destination/{${[...(destination.dns?.destination_names ?? [])].sort().join(",")}}:${port}`;
    }
  }
  return "destination/<undefined>";
}

export function inferEndpointDestinationTitle(destination: Destination): string {
  if ("type" in destination) {
    switch (destination.type.case) {
      case "ip":
        return destination.type.value.ip ?? "<undefined>";
      case "workload": {
        const {
          namespace = "<undefined>",
          kind,
          name = "<undefined>",
        } = destination.type.value ?? {};
        return `${namespace}/${kind}:${name}`;
      }
      case "dns": {
        return `${[...(destination.type.value.destination_names ?? [])].sort().join(",")}`;
      }
      default:
        break;
    }
  } else {
    if ("ip" in destination) {
      return destination.ip?.ip ?? "<undefined>";
    }
    if ("workload" in destination) {
      const {
        namespace = "<undefined>",
        kind = WorkloadKind.Unspecified,
        name = "<undefined>",
      } = destination.workload ?? {};
      return `${namespace}/${capitalizeFirstLetter(workloadKindAsHumanString(kind))}:${name}`;
    }
    if ("dns" in destination) {
      return `${[...(destination.dns?.destination_names ?? [])].sort().join(",")}`;
    }
  }
  return "<undefined>";
}
