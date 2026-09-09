"""Presentación de resultados para personas y para otras herramientas."""

from __future__ import annotations

import json

from .models import AnalysisReport


def render_text(report: AnalysisReport) -> str:
    """Crea un informe legible, sin colores ni dependencias externas."""

    email = report.email
    lines = [
        "ANÁLISIS OFFLINE DE CORREO",
        "=" * 29,
        f"Archivo: {report.source}",
        f"Asunto: {email.subject or '(sin asunto)'}",
        f"Remitente: {email.sender or '(no indicado)'}",
        f"Reply-To: {email.reply_to or '(no indicado)'}",
        "",
        f"Enlaces encontrados: {len(email.urls)}",
    ]

    if email.urls:
        lines.extend(f"  {number}. {url}" for number, url in enumerate(email.urls, 1))
    else:
        lines.append("  (ninguno)")

    lines.extend(["", report.summary, ""])
    if report.findings:
        lines.append("SEÑALES")
        lines.append("-------")
        for index, finding in enumerate(report.findings, 1):
            lines.extend(
                [
                    f"{index}. [{finding.severity.upper()}] {finding.title} ({finding.rule_id})",
                    f"   Por qué: {finding.explanation}",
                    f"   Evidencia: {'; '.join(finding.evidence)}",
                    f"   Recomendación: {finding.recommendation}",
                    "",
                ]
            )
    else:
        lines.extend(["SEÑALES", "-------", "No se activó ninguna regla.", ""])

    lines.append(
        "Aviso: son reglas simples; revisa el contexto antes de decidir si un correo es legítimo."
    )
    return "\n".join(lines)


def render_json(report: AnalysisReport) -> str:
    """Crea JSON estable y legible."""

    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)

