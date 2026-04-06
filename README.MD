Joomlatools DOCman Package Normalizer
=========================================

- Recreates the wrapper's important preflight checks more closely
- Preserves the wrapper's success URL and success text
- Redirects directly to the extension success URL after install
- Carries wrapper metadata into the package manifest
- Includes a conversion report and README inside the generated package

Verified against com_docman_v6.0.3.zip:

Usage:
python3 joomlatools_normalizer_v2.py /path/to/input.zip
python3 joomlatools_normalizer_v2.py /path/to/input.zip /path/to/output.zip
