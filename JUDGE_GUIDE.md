# Sandbox Zero: start here

**OffGrid Dev / Hack in Hills '26 / Track 04**

Extract the complete ZIP first. On Windows, double-click **START_JUDGES.cmd**.
Python **3.11 or newer** must already be installed. The launcher does not install
software or download models. If Python is missing, get it from
https://www.python.org/downloads/ and enable the installer’s PATH option.

The launcher starts a server on numeric loopback, opens the Judge quickstart page,
connects that browser tab and displays the access key in both the terminal and
the page. Keep the terminal open. **Ctrl+C** stops it. A busy port is skipped
automatically; use the printed address rather than assuming port 8000.

If the browser does not open, visit the printed address and paste its access key.
The key changes each launch. Do not publish it. Judge evaluations use `.judge-data/`
and do not modify the original `.data/` evidence. Opening the launcher never starts
Ollama, runs models, contacts a paid provider or exposes the server to your network.

On macOS/Linux, run `python3 judge_start.py` from the extracted folder instead.

## A short evaluation

1. Click **Run six fixture cases**. Inspect the actual outcomes and request paths.
2. Open **Requests** or **Audit integrity** to inspect what ran and verify the ledger.
3. Return to **Judge quickstart** for the recorded Qwen comparison and its limits.
4. `CONTAINER_VALIDATION.html` contains the separate, recorded Linux VM deployment
   checks. The normal local demo does not establish container isolation.

Optional Proof Studio signing needs `cryptography`. To enable that feature with
your chosen Python, run `python -m pip install -r requirements-proof.txt`.
The core fixture and audit demo require only the Python standard library.

## Caution: Qwen ran on our machine

The included Qwen observations were recorded on **OffGrid Dev’s Windows machine**
using **Ollama and qwen2.5:0.5b with CPU inference**. We have not verified this setup
on your computer. Compatibility, memory use, speed and model responses can differ.

You do **not** receive access to our computer or its Ollama service. Model weights,
private keys and private workspace ledgers are not included. The displayed table
is a deliberately limited export of recorded outcomes, not a live run, signed
attestation or a promise that your results will match. No generation runs when you
open this page. Local inference is disabled by default in the judge session.

### Optional: run it on your own Windows machine

1. Install and open Ollama from https://ollama.com/download/windows . Its local
   service must be available on `http://127.0.0.1:11434`. If it is not running,
   use `ollama serve` in a separate terminal. If it is already running, leave it running.
2. Download the exact target: `ollama pull qwen2.5:0.5b` (about 398 MB for the
   target weights; the runtime and optional Red/Blue weights need additional space).
3. In this project folder, create a separate Python environment and install the
   optional local ML dependencies:

   ```powershell
   python -m venv .judge-venv
   .\.judge-venv\Scripts\python.exe -m pip install -r requirements-ml.txt -r requirements-proof.txt
   .\.judge-venv\Scripts\python.exe setup_models.py
   ```

   `setup_models.py` downloads the pinned MiniLM and DeBERTa files. The six-request
   Qwen comparison uses Blue’s classifier as well as the Ollama target.
4. Stop the first judge server with Ctrl+C. Restart explicitly with:

   ```powershell
   .\START_JUDGES.cmd --enable-local-models
   ```

   The launcher uses `.judge-venv` when it exists. On macOS/Linux, use the equivalent
   environment’s `bin/python judge_start.py --enable-local-models`.
5. Open **Local ML lab**, scroll to **Meet the real target**, then click
   **Run real local target**. This is the step that actually requests CPU inference.
   First use can be slow. Missing dependencies/models produce an error, never a
   substituted fixture answer. Inspect your actual outcomes rather than expecting
   the recorded ones. Your new local run appears separately in that lab.

Official setup references: https://docs.ollama.com/windows and
https://ollama.com/library/qwen2.5:0.5b .

## Scope

Fixture outcomes, recorded Qwen observations and recorded container checks are
separate evidence categories. The gateway and host remain trusted. A refusal or
valid signature does not establish general model safety. The recorded 35-check
container report identifies the tested build; the later judge launcher/UI changes
have not repeated that deployment validation.
