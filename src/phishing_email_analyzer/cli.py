"""Interfaz de línea de comandos."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analyzer import analyze_file
from .reporting import render_json, render_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishcheck",
        description=(
            "Analiza señales sencillas de un archivo .eml sin abrir enlaces ni usar Internet."
        ),
    )
    parser.add_argument("email", type=Path, help="Ruta del archivo .eml que deseas revisar")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Muestra el resultado como JSON en vez del informe para personas",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Guarda el resultado en un archivo nuevo; no reemplaza archivos existentes",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = analyze_file(args.email)
        output = render_json(report) if args.json else render_text(report)
        if args.output:
            # El modo x impide borrar el correo original, un enlace o un informe previo.
            with args.output.open("x", encoding="utf-8") as destination:
                destination.write(output + "\n")
            print(f"Informe guardado en: {args.output}")
        else:
            print(output)
    except FileExistsError:
        print("Error: el archivo de salida ya existe; elige otro nombre.", file=sys.stderr)
        return 2
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
