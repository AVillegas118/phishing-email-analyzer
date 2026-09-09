"""Modelos de datos pequeños y fáciles de convertir a JSON."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EmailMetadata:
    """Datos observables extraídos del correo, sin consultar Internet."""

    subject: str
    sender: str
    sender_address: str
    sender_domain: str | None
    reply_to: str
    reply_to_address: str
    reply_to_domain: str | None
    urls: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "sender": self.sender,
            "sender_address": self.sender_address,
            "sender_domain": self.sender_domain,
            "reply_to": self.reply_to,
            "reply_to_address": self.reply_to_address,
            "reply_to_domain": self.reply_to_domain,
            "urls": list(self.urls),
        }


@dataclass(frozen=True)
class Finding:
    """Una señal heurística que merece revisión humana."""

    rule_id: str
    severity: str
    title: str
    explanation: str
    evidence: tuple[str, ...]
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "explanation": self.explanation,
            "evidence": list(self.evidence),
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class AnalysisReport:
    """Resultado completo del análisis."""

    source: str
    email: EmailMetadata
    findings: tuple[Finding, ...]

    @property
    def summary(self) -> str:
        count = len(self.findings)
        if count == 0:
            return "No se activaron las reglas incluidas; esto no demuestra que el correo sea seguro."
        return f"Se encontraron {count} señal(es) para revisar; esto no demuestra que sea phishing."

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "summary": self.summary,
            "email": self.email.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
            "disclaimer": (
                "El análisis usa reglas simples y offline. Una persona debe revisar el contexto "
                "antes de tomar una decisión."
            ),
        }

