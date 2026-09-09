# Analizador de correos sospechosos

Proyecto de ciberseguridad defensiva para aprender cómo se revisan señales básicas de un
correo electrónico. Recibe un archivo `.eml`, lo analiza **sin conectarse a Internet** y
explica qué elementos merecen una revisión humana.

La herramienta no decide si un correo es phishing. Sus reglas son pistas sencillas que
pueden producir falsos positivos y siempre necesitan contexto.

## ¿Qué demuestra este proyecto?

- Manejo de correo electrónico con la biblioteca estándar de Python.
- Extracción local de encabezados, texto y enlaces.
- Creación de reglas de detección fáciles de explicar.
- Diseño de una herramienta de línea de comandos.
- Reportes para personas y reportes JSON para automatización.
- Pruebas automatizadas y ejecución continua con GitHub Actions.

## Señales que revisa

| Regla | Qué observa | Por qué sólo es una señal |
| --- | --- | --- |
| `HEADER-001` | `From` y `Reply-To` usan dominios diferentes | Empresas legítimas pueden usar otro servicio para recibir respuestas. |
| `URL-001` | Un enlace usa una IP literal | Puede ocultar un destino poco reconocible, pero algunos sistemas internos usan IP. |
| `URL-002` | Un enlace comienza con `http://` | No cifra el transporte, aunque usar HTTPS tampoco prueba legitimidad. |
| `TEXT-001` | Palabras de urgencia | La presión es común en engaños y también en avisos reales. |
| `TEXT-002` | Palabras relacionadas con datos sensibles | El contexto determina si la solicitud es apropiada. |

La herramienta **no abre enlaces**, no consulta reputación, no descarga imágenes y no
ejecuta archivos adjuntos.

## Requisitos

- Python 3.11 o posterior.
- Ninguna dependencia externa durante la ejecución.

## Probarlo en menos de un minuto

Desde la carpeta del proyecto:

```bash
PYTHONPATH=src python -m phishing_email_analyzer sample-data/correo-sospechoso.eml
```

El resultado mostrará los datos encontrados y explicará cada señal:

```text
ANÁLISIS OFFLINE DE CORREO
=============================
Archivo: sample-data/correo-sospechoso.eml
Asunto: Acción urgente: verifica tu contraseña
Remitente: Soporte de ejemplo <avisos@example.com>
Reply-To: ayuda@example.net

Enlaces encontrados: 2
  1. http://192.0.2.25/verificar
  2. https://example.org/ayuda

Se encontraron 5 señal(es) para revisar; esto no demuestra que sea phishing.
```

También hay un correo que no activa las reglas:

```bash
PYTHONPATH=src python -m phishing_email_analyzer sample-data/correo-normal.eml
```

Todos los dominios `example.com`, `example.net` y `example.org`, además de las direcciones
IP usadas en los ejemplos, están reservados para documentación. Los datos son ficticios.

## Obtener JSON

Para verlo en la terminal:

```bash
PYTHONPATH=src python -m phishing_email_analyzer \
  sample-data/correo-sospechoso.eml --json
```

Para guardarlo:

```bash
PYTHONPATH=src python -m phishing_email_analyzer \
  sample-data/correo-sospechoso.eml --json --output reporte.json
```

El archivo de salida debe ser nuevo. Si ya existe, la herramienta muestra un error
para conservar el correo original y los informes anteriores. Usa otro nombre al repetirlo.
El código de salida es `0` si terminó el análisis y `2` si ocurrió un error; encontrar
señales sospechosas no cambia el código a un error.

## Instalar el comando opcional

Una instalación editable permite usar `phishcheck` mientras se modifica el código:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
phishcheck sample-data/correo-sospechoso.eml
```

El proyecto no instala librerías de ejecución adicionales.

## Ejecutar las pruebas

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

GitHub Actions repite estas pruebas con varias versiones de Python cada vez que se sube
un cambio o se abre un pull request.

## Cómo funciona

El recorrido de los datos es pequeño a propósito:

```text
archivo .eml
    │
    ├─ lectura local con límite de 10 MiB
    ├─ parser de correo de Python
    ├─ extracción de From, Reply-To, asunto, texto y URLs
    ├─ cinco reglas independientes y explicables
    └─ informe de texto o JSON
```

Archivos principales:

- `analyzer.py`: extrae datos y aplica las reglas.
- `models.py`: define la forma del correo, las señales y el informe.
- `reporting.py`: convierte el resultado a texto o JSON.
- `cli.py`: recibe argumentos y muestra errores comprensibles.
- `tests/test_analyzer.py`: comprueba los casos importantes sin usar red.

## Ideas para aprender y mejorarlo

1. Agregar una regla para dominios Unicode y explicar los posibles falsos positivos.
2. Comparar el texto visible de un enlace HTML con su dirección real.
3. Mostrar los resultados en una pequeña página local.
4. Crear archivos de prueba multipartes y con diferentes codificaciones.
5. Añadir una puntuación configurable, documentando por qué cada peso es discutible.

No conviene añadir consultas a sitios reales hasta comprender privacidad, límites de uso
y manejo seguro de datos. Un correo puede contener información personal.

## Limitaciones

- No verifica SPF, DKIM ni DMARC: un encabezado `From` puede ser falso.
- No analiza archivos adjuntos, reputación de dominios ni redirecciones.
- Busca HTTP(S) y palabras literales; un enlace oculto o texto dentro de una imagen
  puede pasar inadvertido. En HTML no compara el texto visible con el destino.
- Un correo sin señales no queda certificado como seguro. Un correo legítimo puede
  activar varias reglas.
- El límite de entrada es 10 MiB (10.485.760 bytes). No es un entorno aislado para
  procesar de forma masiva archivos hostiles.

## Cómo explicarlo después de estudiarlo y personalizarlo

> Este proyecto analiza archivos `.eml` localmente. Extrae encabezados y enlaces con
> Python y aplica cinco reglas explicables. Cada señal puede tener una causa legítima;
> los resultados requieren revisión humana. Tiene salida JSON, pruebas y un límite
> de tamaño, y conserva los archivos existentes al guardar un informe.

Describe como aportación propia sólo las partes que hayas trabajado y entendido.

## Uso responsable

Analiza únicamente correos propios o archivos que tengas permiso de revisar. No subas
mensajes privados al repositorio. Las muestras incluidas son ficticias y no contactan
servicios reales.

## Licencia

MIT © 2026 AVillegas118.
