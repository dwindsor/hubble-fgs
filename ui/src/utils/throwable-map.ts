export class ThrowableMap<K, V> extends Map<K, V> {
  override get(key: K): V {
    if (!super.has(key)) {
      throw new Error(`key '${String(key)}' not found in map`);
    }
    return super.get(key) as V;
  }

  getOrDefault<D>(key: K, defaultValue: D): V | D {
    return super.get(key) ?? defaultValue;
  }
}
