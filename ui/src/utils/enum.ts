export type ObjShape = Record<string, string | number>;

export type EnumType<Obj extends ObjShape> = Obj[keyof Obj];

export function Enum<const Obj extends ObjShape>(obj: Obj): Obj {
  return Object.assign(Object.create(null), obj);
}
