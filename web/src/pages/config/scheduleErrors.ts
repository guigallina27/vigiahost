// Liga a mensagem de validação do servidor (internal/core/handlers_config.go, scheduleFrom) ao campo do formulário.
// As mensagens são texto para o operador, sem código por campo; a associação é por palavra-chave e, sem
// correspondência, o erro fica no topo do formulário.

export type ScheduleField = "name" | "cron" | "timezone" | "profile" | "paths" | "missedPolicy";

const RULES: [RegExp, ScheduleField][] = [
  [/fuso/i, "timezone"],
  [/cron|express[ãa]o|hor[áa]rios futuros/i, "cron"],
  [/nome/i, "name"],
  [/perfil/i, "profile"],
  [/caminho/i, "paths"],
  [/hor[áa]rio perdido/i, "missedPolicy"],
];

export function fieldForServerError(message: string): ScheduleField | null {
  for (const [re, field] of RULES) if (re.test(message)) return field;
  return null;
}
