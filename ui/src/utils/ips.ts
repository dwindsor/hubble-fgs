import ipaddr, { type IPv4, type IPv6 } from "ipaddr.js";

// biome-ignore lint/suspicious/noExplicitAny: `SpecialRanges` isn't presented in TS defs
export const specialIps = Object.values((ipaddr.IPv4 as any).prototype.SpecialRanges).reduce<
  [IPv4 | IPv6, number][]
>((acc, ranges) => {
  return acc.concat(ranges as [IPv4 | IPv6, number][]);
}, []);
