import type { TFunction } from "i18next";
import { describeCron, type CronDescription } from "./schedules";

function timeOf(hour: number, minute: number, lng: string): string {
  return new Intl.DateTimeFormat(lng, { hour: "2-digit", minute: "2-digit", timeZone: "UTC" }).format(
    Date.UTC(2024, 0, 1, hour, minute),
  );
}

function weekdays(days: number[], lng: string): string {
  // 7 de janeiro de 2024 foi um domingo: dia 0 do cron.
  const fmt = new Intl.DateTimeFormat(lng, { weekday: "long", timeZone: "UTC" });
  const names = days.map((d) => fmt.format(Date.UTC(2024, 0, 7 + d)));
  return new Intl.ListFormat(lng, { style: "long", type: "conjunction" }).format(names);
}

function dayMonth(month: number, day: number, lng: string): string {
  return new Intl.DateTimeFormat(lng, { day: "numeric", month: "long", timeZone: "UTC" }).format(Date.UTC(2024, month - 1, day));
}

export function describeToText(d: CronDescription, t: TFunction, lng: string): string {
  switch (d.key) {
    case "everyMinutes":
      return t("config.cron.everyMinutes", { count: d.n });
    case "hourlyAt":
      return t("config.cron.hourlyAt", { minute: d.minute });
    case "everyHours":
      return t("config.cron.everyHours", { count: d.n, minute: d.minute });
    case "dailyAt":
      return t("config.cron.dailyAt", { time: timeOf(d.hour, d.minute, lng) });
    case "weeklyAt":
      return t("config.cron.weeklyAt", { days: weekdays(d.days, lng), time: timeOf(d.hour, d.minute, lng) });
    case "monthlyAt":
      return t("config.cron.monthlyAt", { day: d.day, time: timeOf(d.hour, d.minute, lng) });
    case "yearlyAt":
      return t("config.cron.yearlyAt", { date: dayMonth(d.month, d.day, lng), time: timeOf(d.hour, d.minute, lng) });
    case "every":
      return t("config.cron.every", { duration: d.duration });
  }
}

/** Expressão cron em linguagem simples; formas não cobertas viram "Expressão personalizada". */
export function cronToText(expr: string, t: TFunction, lng: string): string {
  const d = describeCron(expr);
  return d ? describeToText(d, t, lng) : t("config.cron.custom");
}
