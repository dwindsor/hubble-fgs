import type * as AppModel from "@ipa/application_model/v1alpha/application_model_pb";
import type { DeepPartial } from "~/utils/types";

export type ApplicationModelEvent = DeepPartial<AppModel.ApplicationModelEvent>;

export type ApplicationProcessGroup = DeepPartial<AppModel.ApplicationProcessGroup>;

export type ApplicationConnection = DeepPartial<AppModel.ApplicationConnection>;

export type ApplicationWorkload = DeepPartial<AppModel.ApplicationWorkload>;

export type ApplicationHost = DeepPartial<AppModel.ApplicationHost>;

export type ApplicationNamespace = DeepPartial<AppModel.ApplicationNamespace>;
