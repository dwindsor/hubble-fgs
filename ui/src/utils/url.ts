import { Enum, type EnumType } from "./enum";

export const UrlParams = Enum({
  Expanded: "expanded",
  Pinned: "pinned",
});

export type UrlParams = EnumType<typeof UrlParams>;

export function setQueryParam(key: UrlParams, value?: string | undefined | null) {
  const params = new URLSearchParams(window.location.search);
  if (typeof value === "string") {
    params.set(key, value);
  } else {
    params.delete(key);
  }
  let url = window.location.pathname;
  if (params.size) {
    url += `?${params}`;
  }
  window.history.replaceState({}, "", decodeURIComponent(url));
}
