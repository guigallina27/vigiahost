import "./styles/index.css";
import "./i18n";
import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "react-router";
import { ApiError, sessionQuery } from "./api/client";
import { router } from "./router";

// 401 em qualquer chamada (sessão vencida por inatividade, por exemplo): reconsulta a sessão e o portão volta ao login.
function onApiError(err: unknown) {
  if (err instanceof ApiError && err.status === 401) void queryClient.invalidateQueries({ queryKey: sessionQuery.queryKey });
}

const queryClient: QueryClient = new QueryClient({
  queryCache: new QueryCache({ onError: onApiError }),
  mutationCache: new MutationCache({ onError: onApiError }),
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      // Erro do servidor com resposta (4xx) não melhora repetindo.
      retry: (count, err) => count < 1 && !(err instanceof ApiError && err.status !== undefined && err.status < 500),
    },
  },
});

const root = document.getElementById("root");
if (!root) throw new Error("elemento #root ausente no index.html");

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
