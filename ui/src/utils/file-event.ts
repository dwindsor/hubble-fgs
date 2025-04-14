import type { ApplicationFileEvent, FileEventKind } from "~/proto";
import { Enum, type EnumType } from "./enum";

export const FileEventFilterKind = Enum({
  Read: "file-event-read",
  Write: "file-event-write",
});
export type FileEventFilterKind = EnumType<typeof FileEventFilterKind>;

export function inferEndpointFileEventKind(fileEvent: ApplicationFileEvent): FileEventKind {
  return fileEvent.event as unknown as FileEventKind;
}

export function inferEndpointFileEventHash(fileEvent: ApplicationFileEvent): string {
  return `file/${fileEvent.file_path ?? "<undefined>"}`;
}

export function inferEndpointFileEventTitle(fileEvent: ApplicationFileEvent): string {
  return fileEvent.file_path ?? "";
}
