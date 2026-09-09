import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from phishing_email_analyzer.cli import main


class CliTests(unittest.TestCase):
    def test_output_cannot_overwrite_source_or_an_existing_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary, "correo.eml")
            original = b"From: persona@example.com\n\nHola\n"
            source.write_bytes(original)
            existing = Path(temporary, "report.json")
            existing.write_bytes(original)
            link = Path(temporary, "link.json")
            link.symlink_to(source)
            for destination in (source, existing, link):
                with self.subTest(destination=destination.name), redirect_stderr(StringIO()):
                    self.assertEqual(main([str(source), "--output", str(destination)]), 2)
                    self.assertEqual(destination.read_bytes(), original)

    def test_json_output_is_written_to_a_new_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary, "correo.eml")
            source.write_bytes(b"From: persona@example.com\n\nHola\n")
            output = Path(temporary, "report.json")
            with redirect_stdout(StringIO()):
                self.assertEqual(main([str(source), "--json", "--output", str(output)]), 0)
            self.assertEqual(json.loads(output.read_text())["email"]["sender_domain"], "example.com")

    def test_missing_email_is_a_readable_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            error = StringIO()
            with redirect_stderr(error):
                code = main([str(Path(temporary, "missing.eml"))])
            self.assertEqual(code, 2)
            self.assertIn("Error:", error.getvalue())

    def test_output_to_missing_directory_is_a_readable_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary, "correo.eml")
            source.write_bytes(b"From: persona@example.com\n\nHola\n")
            with redirect_stderr(StringIO()):
                code = main([str(source), "--output", str(Path(temporary, "missing", "out.json"))])
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
