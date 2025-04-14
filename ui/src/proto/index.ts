import * as ProtoAppModel from "@ipa/application_model/v1alpha/application_model_pb";
import type { ObjectToSnake } from "ts-case-convert";
import { Enum, type EnumType, createEnumFromProto } from "~/utils/enum";
import type { DeepPartial } from "~/utils/types";

export type ApplicationModelEvent = ObjectToSnake<DeepPartial<ProtoAppModel.ApplicationModelEvent>>;

export type ApplicationProcessGroup = ObjectToSnake<
  DeepPartial<
    ProtoAppModel.ApplicationProcessGroup & {
      file_events: ApplicationFileEvent[];
    }
  >
>;

export type ApplicationConnection = ObjectToSnake<DeepPartial<ProtoAppModel.ApplicationConnection>>;

export type ApplicationWorkload = ObjectToSnake<DeepPartial<ProtoAppModel.ApplicationWorkload>>;

export type ApplicationHost = ObjectToSnake<DeepPartial<ProtoAppModel.ApplicationHost>>;

export type ApplicationNamespace = ObjectToSnake<DeepPartial<ProtoAppModel.ApplicationNamespace>>;

export type ApplicationFileEvent = ObjectToSnake<
  DeepPartial<{
    file_path: string;
    event: ProtoFileEventKind;
  }>
>;

export type Destination =
  | ObjectToSnake<
      DeepPartial<{
        dns: Pick<ProtoAppModel.DestinationDns, "destinationNames">;
        port: ProtoAppModel.Destination["port"];
      }>
    >
  | ObjectToSnake<
      DeepPartial<{
        ip: Pick<ProtoAppModel.DestinationIP, "ip">;
        port: ProtoAppModel.Destination["port"];
      }>
    >
  | ObjectToSnake<
      DeepPartial<{
        workload: { kind: WorkloadKind } & Pick<
          ProtoAppModel.DestinationWorkload,
          "name" | "namespace"
        >;
        port: ProtoAppModel.Destination["port"];
      }>
    >;

export const WORKLOAD_KIND_KEY_PREFIX = "WORKLOAD_KIND_";
export const WorkloadKind = createEnumFromProto(
  ProtoAppModel.WorkloadKindSchema,
  ProtoAppModel.WorkloadKind,
  WORKLOAD_KIND_KEY_PREFIX,
);
export type WorkloadKind = EnumType<typeof WorkloadKind>;

export enum ProtoFileEventKind {
  UNSPECIFIED = 0,
  READ = 1,
  WRITE = 2,
}

export const FILE_EVENT_KIND_KEY_PREFIX = "FILE_EVENT_KIND_";
export const FileEventKind = Enum({
  Unspecified: "FILE_EVENT_KIND_UNSPECIFIED",
  Read: "FILE_EVENT_KIND_READ",
  Write: "FILE_EVENT_KIND_WRITE",
});
export type FileEventKind = EnumType<typeof FileEventKind>;
