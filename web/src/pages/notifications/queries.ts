import { queryOptions } from "@tanstack/react-query";
import { api, unwrap } from "../../api/client";
import type { OutboxState } from "./notifications";

// Consultas da tela Notificações. Tudo sob ["notifications"] para invalidar junto depois de uma alteração.

export const notificationsKey = ["notifications"] as const;

export const channelsQuery = queryOptions({
  queryKey: [...notificationsKey, "channels"],
  queryFn: ({ signal }) => unwrap(api.GET("/api/v1/notifications/channels", { signal })),
});

export const rulesQuery = queryOptions({
  queryKey: [...notificationsKey, "rules"],
  queryFn: ({ signal }) => unwrap(api.GET("/api/v1/notifications/rules", { signal })),
});

export function outboxKey(state: OutboxState | "") {
  return [...notificationsKey, "outbox", state] as const;
}

export const OUTBOX_PAGE = 25;
