import { CircleCheck, EyeOff, TriangleAlert } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { Schemas } from "../../api/client";
import { Badge } from "../../components/Badge";
import { Panel } from "../../components/Panel";
import { PathText } from "../../components/PathText";
import { TableScroll } from "../../components/TableScroll";
import { formatNumber } from "../../lib/format";
import { SafeText } from "./SafeText";

type HiddenReport = Schemas["HiddenReport"];

/** Quantos processos e portas ocultos a inspeção confirmou (os achados ficam na lista de achados). */
export function hiddenCount(r: HiddenReport): number {
  return r.processes.found.length + r.ports.found.length;
}

/**
 * Processos e portas ocultos da inspeção: o kernel confirma (sinal 0, bind) e as listagens escondem. Sem a busca
 * (inspeção antiga ou fora da rede do sistema), o painel diz que ela não rodou.
 */
export function HiddenPanel({ report }: { report: HiddenReport | undefined }) {
  const { t, i18n } = useTranslation();
  const lng = i18n.language;
  const n = (v: number) => formatNumber(v, lng);
  if (!report || (!report.processes.checked && !report.ports.checked)) {
    return (
      <Panel title={t("inventory.hidden.title")}>
        <p className="m-0 text-ink-muted">{t("inventory.hidden.notChecked")}</p>
      </Panel>
    );
  }
  const total = hiddenCount(report);
  const discarded = report.processes.discarded + report.ports.discarded;
  const errors = [
    report.processes.error ? t("inventory.hidden.processesError", { error: report.processes.error }) : "",
    report.ports.error ? t("inventory.hidden.portsError", { error: report.ports.error }) : "",
  ].filter(Boolean);

  return (
    <Panel
      title={t("inventory.hidden.title")}
      actions={
        total > 0 ? (
          <Badge tone="critical" icon={EyeOff}>
            {t("inventory.hidden.found", { count: total })}
          </Badge>
        ) : (
          <Badge tone="ok" icon={CircleCheck} variant="outline">
            {t("inventory.hidden.found", { count: 0 })}
          </Badge>
        )
      }
    >
      {total === 0 && (
        <p className="m-0">
          {t("inventory.hidden.clean", { processes: n(report.processes.visible), ports: n(report.ports.probed) })}
        </p>
      )}

      {report.processes.found.length > 0 && (
        <TableScroll label={t("inventory.hidden.processesCaption")}>
          <table className="vh-table">
            <caption className="visually-hidden">{t("inventory.hidden.processesCaption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("inventory.hidden.colPid")}</th>
                <th scope="col">{t("inventory.hidden.colProcess")}</th>
                <th scope="col">{t("inventory.hidden.colChecks")}</th>
                <th scope="col">{t("inventory.hidden.colAccess")}</th>
              </tr>
            </thead>
            <tbody>
              {report.processes.found.map((p) => (
                <tr key={p.pid}>
                  <td className="font-semibold tabular-nums">{p.pid}</td>
                  <td className="min-w-48">
                    <span className="flex min-w-0 flex-col gap-0.5">
                      {p.comm && <SafeText text={p.comm} />}
                      {p.exe && <PathText path={p.exe} />}
                      {!p.comm && !p.exe && <span className="text-ink-muted">—</span>}
                    </span>
                  </td>
                  <td className="font-mono text-sm">{p.checks.join(", ")}</td>
                  <td>{t(p.direct_access ? "inventory.hidden.directYes" : "inventory.hidden.directNo")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableScroll>
      )}

      {report.ports.found.length > 0 && (
        <TableScroll label={t("inventory.hidden.portsCaption")}>
          <table className="vh-table">
            <caption className="visually-hidden">{t("inventory.hidden.portsCaption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("inventory.hidden.colPort")}</th>
                <th scope="col">{t("inventory.hidden.colReason")}</th>
              </tr>
            </thead>
            <tbody>
              {report.ports.found.map((p) => (
                <tr key={`${p.proto}/${p.port}`}>
                  <td className="font-semibold whitespace-nowrap tabular-nums">
                    {p.proto.toUpperCase()} {p.port}
                  </td>
                  <td className="min-w-64">{t(`inventory.hidden.reason.${p.reason}`)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableScroll>
      )}

      {(discarded > 0 || report.ports.skipped > 0) && (
        <ul className="m-0 flex list-none flex-col gap-1 p-0 text-sm text-ink-muted">
          {discarded > 0 && <li>{t("inventory.hidden.discarded", { count: discarded })}</li>}
          {report.ports.skipped > 0 && <li>{t("inventory.hidden.skipped", { count: report.ports.skipped })}</li>}
        </ul>
      )}
      {errors.length > 0 && (
        <ul className="m-0 flex list-none flex-col gap-1 p-0">
          {errors.map((e) => (
            <li key={e} className="flex gap-2">
              <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-(--vh-high-fg)" />
              <span className="min-w-0 [overflow-wrap:anywhere]">{e}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
