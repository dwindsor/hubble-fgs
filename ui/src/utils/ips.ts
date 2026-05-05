import ipaddr, { type IPv4, type IPv6 } from "ipaddr.js";

// biome-ignore lint/suspicious/noExplicitAny: `SpecialRanges` isn't presented in TS defs
const v4Ranges = Object.values((ipaddr.IPv4 as any).prototype.SpecialRanges);
// biome-ignore lint/suspicious/noExplicitAny: `SpecialRanges` isn't presented in TS defs
const v6Ranges = Object.values((ipaddr.IPv6 as any).prototype.SpecialRanges);
// IPv4 entries are always `[[ip, prefix], ...]`, but IPv6 entries may be bare `[ip, prefix]`
// tuples. Normalize to array-of-tuples before flattening so `subnetMatch` sees uniform shape.
export const specialIps = [...v4Ranges, ...v6Ranges].reduce<[IPv4 | IPv6, number][]>(
  (acc, ranges) => {
    const tuples = Array.isArray((ranges as unknown[])[0])
      ? (ranges as [IPv4 | IPv6, number][])
      : [ranges as [IPv4 | IPv6, number]];
    return acc.concat(tuples);
  },
  [],
);
