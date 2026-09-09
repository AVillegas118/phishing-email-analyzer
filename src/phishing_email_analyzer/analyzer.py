"""Extracción y reglas defensivas para archivos de correo RFC 5322 (.eml)."""

from __future__ import annotations

import ipaddress
import re
import stat
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlsplit

from .models import AnalysisReport, EmailMetadata, Finding

MAX_EMAIL_BYTES = 10 * 1024 * 1024

# La expresión sólo reconoce HTTP(S). No abre ni valida los enlaces.
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
TRAILING_URL_PUNCTUATION = ".,;:!?"

URGENCY_TERMS = (
    "acción requerida",
    "actúa ahora",
    "de inmediato",
    "inmediatamente",
    "último aviso",
    "urgente",
    "urgent",
    "immediately",
)

SENSITIVE_TERMS = (
    "código de acceso",
    "contraseña",
    "credenciales",
    "cuenta bancaria",
    "número de tarjeta",
    "password",
    "credit card",
)


def analyze_file(path: str | Path, *, max_bytes: int = MAX_EMAIL_BYTES) -> AnalysisReport:
    """Lee y analiza un archivo local. Nunca realiza solicitudes de red."""

    email_path = Path(path)
    metadata = email_path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("La entrada debe ser un archivo de correo normal.")
    size = metadata.st_size
    if size > max_bytes:
        raise ValueError(
            f"El archivo mide {size} bytes y supera el límite de {max_bytes} bytes."
        )
    # Se limita también la lectura: el tamaño puede cambiar después de stat().
    with email_path.open("rb") as source:
        data = source.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"El correo supera el límite de {max_bytes} bytes.")
    return analyze_bytes(data, source=str(email_path))


def analyze_bytes(data: bytes, *, source: str = "<memoria>") -> AnalysisReport:
    """Analiza bytes de un correo; resulta útil para pruebas y otras herramientas."""

    message = BytesParser(policy=policy.default).parsebytes(data)
    body_text = _extract_text(message)
    searchable_text = f"{_header(message, 'Subject')}\n{body_text}"

    sender = _header(message, "From")
    reply_to = _header(message, "Reply-To")
    _, sender_address = parseaddr(sender)
    _, reply_to_address = parseaddr(reply_to)
    sender_domain = _email_domain(sender_address)
    reply_to_domain = _email_domain(reply_to_address)
    urls = _extract_urls(body_text)

    metadata = EmailMetadata(
        subject=_header(message, "Subject"),
        sender=sender,
        sender_address=sender_address,
        sender_domain=sender_domain,
        reply_to=reply_to,
        reply_to_address=reply_to_address,
        reply_to_domain=reply_to_domain,
        urls=urls,
    )

    findings: list[Finding] = []
    mismatch = _reply_to_mismatch(sender_domain, reply_to_domain)
    if mismatch is not None:
        findings.append(mismatch)

    ip_link = _literal_ip_urls(urls)
    if ip_link is not None:
        findings.append(ip_link)

    plain_http = _plain_http_urls(urls)
    if plain_http is not None:
        findings.append(plain_http)

    urgency = _term_finding(searchable_text, URGENCY_TERMS, urgency=True)
    if urgency is not None:
        findings.append(urgency)

    sensitive = _term_finding(searchable_text, SENSITIVE_TERMS, urgency=False)
    if sensitive is not None:
        findings.append(sensitive)

    return AnalysisReport(source=source, email=metadata, findings=tuple(findings))


def _header(message: Message, name: str) -> str:
    value = message.get(name, "")
    return str(value).strip()


def _extract_text(message: Message) -> str:
    pieces: list[str] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        if part.get_content_disposition() == "attachment":
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        if isinstance(content, str):
            pieces.append(content)
    return "\n".join(pieces)


def _extract_urls(text: str) -> tuple[str, ...]:
    found: list[str] = []
    seen: set[str] = set()
    for match in URL_PATTERN.finditer(text):
        url = _clean_url(match.group(0))
        if url and url not in seen:
            found.append(url)
            seen.add(url)
    return tuple(found)


def _clean_url(raw_url: str) -> str:
    """Retira puntuación de una frase sin romper IPv6 ni paréntesis válidos."""

    url = raw_url.rstrip(TRAILING_URL_PUNCTUATION)
    while url.endswith(")") and url.count(")") > url.count("("):
        url = url[:-1]
    while url.endswith("]") and url.count("]") > url.count("["):
        url = url[:-1]
    return url


def _email_domain(address: str) -> str | None:
    if "@" not in address:
        return None
    local_part, domain = address.rsplit("@", 1)
    normalized = domain.strip().lower().rstrip(".")
    if not local_part or not normalized:
        return None
    return normalized


def _reply_to_mismatch(
    sender_domain: str | None, reply_to_domain: str | None
) -> Finding | None:
    if not sender_domain or not reply_to_domain or sender_domain == reply_to_domain:
        return None
    return Finding(
        rule_id="HEADER-001",
        severity="media",
        title="El dominio de Reply-To es diferente",
        explanation=(
            "Las respuestas se enviarían a un dominio distinto del que aparece en From. "
            "Puede ser legítimo, pero conviene verificarlo."
        ),
        evidence=(f"From: {sender_domain}", f"Reply-To: {reply_to_domain}"),
        recommendation="Confirma el dominio con el remitente por un canal conocido.",
    )


def _literal_ip_urls(urls: tuple[str, ...]) -> Finding | None:
    evidence: list[str] = []
    for url in urls:
        try:
            host = urlsplit(url).hostname
            if host is not None:
                ipaddress.ip_address(host)
                evidence.append(url)
        except ValueError:
            # Un host normal o una URL incompleta no es una IP literal.
            continue
    if not evidence:
        return None
    return Finding(
        rule_id="URL-001",
        severity="media",
        title="Un enlace usa una dirección IP literal",
        explanation=(
            "El enlace muestra una IP en lugar de un nombre de dominio. Esto reduce las "
            "pistas que una persona puede usar para reconocer el sitio."
        ),
        evidence=tuple(evidence),
        recommendation="No abras el enlace; verifica el destino con información oficial.",
    )


def _plain_http_urls(urls: tuple[str, ...]) -> Finding | None:
    evidence_list: list[str] = []
    for url in urls:
        try:
            if urlsplit(url).scheme.lower() == "http":
                evidence_list.append(url)
        except ValueError:
            # Una URL mal formada no debe detener el análisis del resto del correo.
            continue
    evidence = tuple(evidence_list)
    if not evidence:
        return None
    return Finding(
        rule_id="URL-002",
        severity="media",
        title="Un enlace usa HTTP sin cifrado",
        explanation=(
            "HTTP no protege la comunicación con cifrado de transporte. HTTPS tampoco "
            "garantiza por sí solo que un sitio sea legítimo."
        ),
        evidence=evidence,
        recommendation="Evita introducir información en ese sitio y busca la página oficial.",
    )


def _term_finding(text: str, terms: tuple[str, ...], *, urgency: bool) -> Finding | None:
    normalized = text.casefold()
    matches = tuple(
        term
        for term in terms
        if re.search(
            rf"(?<!\w){re.escape(term.casefold())}(?!\w)",
            normalized,
        )
    )
    if not matches:
        return None
    if urgency:
        return Finding(
            rule_id="TEXT-001",
            severity="baja",
            title="El mensaje utiliza lenguaje de urgencia",
            explanation=(
                "La presión de tiempo puede intentar reducir la atención del lector, aunque "
                "también aparece en mensajes legítimos."
            ),
            evidence=matches,
            recommendation="Pausa y confirma la solicitud antes de actuar.",
        )
    return Finding(
        rule_id="TEXT-002",
        severity="baja",
        title="El mensaje menciona información sensible",
        explanation=(
            "Se encontraron palabras relacionadas con datos que no deberían compartirse sin "
            "verificar primero la identidad del solicitante."
        ),
        evidence=matches,
        recommendation="No compartas secretos ni datos financieros por medio del enlace.",
    )
