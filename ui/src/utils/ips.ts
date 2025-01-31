import ipaddr, { type IPv4, type IPv6 } from "ipaddr.js";

// biome-ignore lint/suspicious/noExplicitAny: `SpecialRanges` isn't presented in TS defs
export const specialIps = Object.values((ipaddr.IPv4 as any).prototype.SpecialRanges).reduce<
  [IPv4 | IPv6, number][]
>((acc, ranges) => {
  return acc.concat(ranges as [IPv4 | IPv6, number][]);
}, []);

export function checkIpAddress(value: string): boolean {
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/;
  return ipv4Pattern.test(value) || ipv6Pattern.test(value);
}
