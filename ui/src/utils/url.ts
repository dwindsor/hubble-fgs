import type { PropertyValues } from "~/types";

export const UrlParams = {
  __proto__: null,
  Expanded: "expanded",
  Pinned: "pinned",
} as const;

export type UrlParamsType = PropertyValues<typeof UrlParams>;

export function setQueryParam(key: string, value?: string | undefined | null) {
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
  window.history.pushState({}, "", decodeURIComponent(url));
}
