import { FileEventKind } from "~/proto";
import { DestinationKind } from "~/utils/destination";

export const colors = {
  page: "#ffffff",
  text: "#000000",
  textMuted: "#999999",
  separator: "#cccccc",

  treeBranch: "#b8b8b8",
  suspicious: "#d59011",

  entityDestinationInner: "#cccccc",
  entityDestinationInnerHighlighted: "#888888",

  entityDestinationOuter: "#9e83df",
  entityDestinationOuterHighlighted: "#7748e4",

  entityDestinationKubernetes: "#78bbe8",
  entityDestinationKubernetesHighlighted: "#0b81d0",

  entityFileEventRead: "#5483d7",
  entityFileEventReadHighlighted: "#3660aa",

  entityFileEventWrite: "#d7a854",
  entityFileEventWriteHighlighted: "#d29c3e",

  entityMuted: "#ddd",
};

export const destinationColorsMap = {
  [DestinationKind.OuterIp]: colors.entityDestinationOuter,
  [DestinationKind.OuterDns]: colors.entityDestinationOuter,
  [DestinationKind.Kubernetes]: colors.entityDestinationKubernetes,
  [DestinationKind.HostMetadataService]: colors.entityDestinationKubernetes,
} as { [key: string]: string };

export const fileEventColorsMap = {
  [FileEventKind.Read]: colors.entityFileEventRead,
  [FileEventKind.Write]: colors.entityFileEventWrite,
} as { [key: string]: string };
