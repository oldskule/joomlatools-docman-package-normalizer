# Joomlatools Package Normalizer

Creates a repackaged ZIP that installs cleanly via Watchful, Joomla API or other remote Joomla management tools by converting Joomlatools’ wrapper installer into a standard Joomla package.

## Features

- Recreates the wrapper’s critical preflight checks (PHP, Joomla version, legacy upgrade guards)
- Preserves and enforces the Joomlatools Framework downgrade guard when present
- Maintains correct install order (Framework → Component)
- Preserves the wrapper’s success URL and success messaging
- Redirects directly to the extension success URL after installation
- Carries wrapper metadata into the generated package manifest
- Performs post-install cleanup to mimic Joomlatools’ temporary installer behavior (removes package entry and manifest)
- Generates a conversion report inside the package for traceability
- Rebuilds packages using proper compression (no unnecessary file size inflation)
- Ensures payload integrity (child packages are preserved file-for-file)

## Verified Against

- com_docman_v6.0.3.zip
- com_fileman_v6.0.2.zip
- com_textman_v6.0.2.zip
- com_logman_v6.0.2.zip

## Usage

```bash
python3 joomlatools_normalizer.py /path/to/input.zip /path/to/output.zip
