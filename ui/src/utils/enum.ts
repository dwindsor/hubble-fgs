import type { GenEnum } from "@bufbuild/protobuf/codegenv2";
import camelCase from "lodash/camelCase";
import type { ToCamel } from "ts-case-convert";
import { capitalizeFirstLetter } from "./strings";

export type ObjShape = Record<string, string | number>;

export type EnumType<Obj extends ObjShape> = Obj[keyof Obj];

export function Enum<const Obj extends ObjShape>(obj: Obj): Obj {
  return Object.assign(Object.create(null), obj);
}

export function createEnumFromProto<
  Enum extends Record<string, string | number>,
  Prefix extends string,
  Result extends {
    [K in Extract<keyof Enum, string> as Capitalize<ToCamel<Lowercase<K>>>]: `${Prefix}${K}`;
  },
>(schema: GenEnum<number>, _enum: Enum, keyPrefix: Prefix): Result {
  const prefixLen = keyPrefix.length;
  return Enum(
    schema.values.reduce((acc, val) => {
      const key = capitalizeFirstLetter(camelCase(val.name.slice(prefixLen).toLocaleLowerCase()));
      Object.assign(acc, { [key]: val.name });
      return acc;
    }, {} as Result),
  );
}
