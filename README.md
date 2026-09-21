# File Integrity Monitor

A small Python command-line project for checking whether files in a chosen folder have changed. It uses SHA-256 hashes to record a trusted baseline and reports files that were **added, removed, or modified** since that baseline.

Built as a cybersecurity programming exercise using only the Python standard library.

## Why this project?

File integrity monitoring is one way to notice unexpected changes to configurations, scripts, or other important files. A hash cannot tell *why* a file changed, so the results require investigation.

## Requirements

Python 3.9+; no external packages.

## Try it

```bash
python fim.py init sample_files --manifest baseline.json
python fim.py check sample_files --manifest baseline.json
```

Edit `sample_files/config.txt`, then run `check` again. You should see the file under `MODIFIED`.

To exclude files from a baseline:

```bash
python fim.py init sample_files --manifest baseline.json --exclude "*.log"
```

`init` replaces an existing baseline, so use it only when you trust the current files. Run `check` first if you are investigating changes.

## Output and exit codes

- `0`: No changes (`check`) or baseline created (`init`).
- `1`: Changes were detected.
- `2`: Invalid input or an error occurred.

## Test

From the repository root:

```bash
python -m unittest discover -s tests -v
```

The tests cover known hash values, unchanged files, added/removed/modified files, exclude patterns, and keeping the baseline in the monitored directory.

## Scope and limitations

This is a learning project, **not a production security agent**. It checks on demand, not continuously; an attacker who can edit both the files and the baseline could hide modifications. SHA-256 identifies content changes but does not determine whether those changes are malicious. Symlinks and selected development directories (`.git`, `.venv`, `__pycache__`) are skipped.
