from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from phishing_email_analyzer.analyzer import analyze_bytes, analyze_file
from phishing_email_analyzer.reporting import render_json, render_text


def make_email(
    *,
    sender: str = "Persona <persona@example.com>",
    reply_to: str = "respuesta@example.com",
    subject: str = "Mensaje de prueba",
    body: str = "Consulta https://example.com/ayuda",
) -> bytes:
    return (
        f"From: {sender}\n"
        f"Reply-To: {reply_to}\n"
        "To: estudiante@example.org\n"
        f"Subject: {subject}\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=UTF-8\n"
        "\n"
        f"{body}\n"
    ).encode("utf-8")


class AnalyzerTests(unittest.TestCase):
    def test_extracts_headers_and_urls(self) -> None:
        report = analyze_bytes(make_email(), source="prueba.eml")

        self.assertEqual(report.source, "prueba.eml")
        self.assertEqual(report.email.sender_address, "persona@example.com")
        self.assertEqual(report.email.reply_to_domain, "example.com")
        self.assertEqual(report.email.urls, ("https://example.com/ayuda",))

    def test_detects_reply_to_domain_mismatch(self) -> None:
        report = analyze_bytes(make_email(reply_to="respuesta@example.net"))

        self.assertIn("HEADER-001", {finding.rule_id for finding in report.findings})

    def test_same_reply_to_domain_is_not_flagged(self) -> None:
        report = analyze_bytes(make_email())

        self.assertNotIn("HEADER-001", {finding.rule_id for finding in report.findings})

    def test_detects_ipv4_literal_link(self) -> None:
        report = analyze_bytes(make_email(body="Visita https://192.0.2.9/inicio"))

        self.assertIn("URL-001", {finding.rule_id for finding in report.findings})

    def test_detects_ipv6_literal_link(self) -> None:
        report = analyze_bytes(make_email(body="Visita https://[2001:db8::9]"))

        self.assertIn("URL-001", {finding.rule_id for finding in report.findings})
        self.assertEqual(report.email.urls, ("https://[2001:db8::9]",))

    def test_detects_unencrypted_http(self) -> None:
        report = analyze_bytes(make_email(body="Visita http://example.com/inicio"))

        self.assertIn("URL-002", {finding.rule_id for finding in report.findings})

    def test_malformed_url_does_not_stop_analysis(self) -> None:
        report = analyze_bytes(make_email(body="Mira http://[dirección-incompleta"))

        self.assertEqual(report.email.urls, ("http://[dirección-incompleta",))

    def test_detects_urgency_and_sensitive_words(self) -> None:
        report = analyze_bytes(
            make_email(subject="Último aviso", body="Comparte tu contraseña de inmediato")
        )
        rule_ids = {finding.rule_id for finding in report.findings}

        self.assertIn("TEXT-001", rule_ids)
        self.assertIn("TEXT-002", rule_ids)

    def test_english_urgent_is_not_matched_inside_spanish_urgente(self) -> None:
        report = analyze_bytes(make_email(subject="Mensaje urgente"))
        finding = next(item for item in report.findings if item.rule_id == "TEXT-001")

        self.assertEqual(finding.evidence, ("urgente",))

    def test_deduplicates_repeated_urls(self) -> None:
        report = analyze_bytes(
            make_email(body="https://example.com/a https://example.com/a.")
        )

        self.assertEqual(report.email.urls, ("https://example.com/a",))

    def test_json_report_has_expected_shape(self) -> None:
        report = analyze_bytes(make_email())
        payload = json.loads(render_json(report))

        self.assertEqual(payload["email"]["sender_domain"], "example.com")
        self.assertIsInstance(payload["findings"], list)
        self.assertIn("no demuestra", payload["summary"])

    def test_text_report_includes_disclaimer(self) -> None:
        output = render_text(analyze_bytes(make_email()))

        self.assertIn("reglas simples", output)
        self.assertIn("antes de decidir", output)

    def test_analyze_file_rejects_file_above_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "grande.eml"
            path.write_bytes(b"12345")

            with self.assertRaises(ValueError):
                analyze_file(path, max_bytes=4)

    def test_analyze_file_enforces_limit_even_if_size_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "grande.eml"
            path.write_bytes(b"123456789")
            metadata = SimpleNamespace(st_size=1, st_mode=path.stat().st_mode)
            with patch.object(Path, "stat", return_value=metadata):
                with self.assertRaises(ValueError):
                    analyze_file(path, max_bytes=4)

    def test_analyze_file_rejects_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                analyze_file(directory)


if __name__ == "__main__":
    unittest.main()
