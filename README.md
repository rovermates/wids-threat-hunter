# WIDS Threat Hunter

A local research dashboard for analyzing Wi-Fi PCAP captures and AWID CSV files.
Includes the FastAPI backend, React dashboard, trained rogue-advertisement model,
a prebuilt frontend, and small test captures. No training or Node.js installation
is needed to run the included build.

## Windows quick start

1. Install **Python 3.12 (64-bit)** from https://www.python.org/downloads/ .
   Include the Python launcher during installation.
2. Install **Wireshark 4.4 or newer** from https://www.wireshark.org/download.html .
   Include the **TShark** component. Its standard location is
   `C:\Program Files\Wireshark\tshark.exe`. Npcap/live capture is not required to
   analyze uploaded files. CSV analysis works without tshark.
3. Download this repository using **Code > Download ZIP**, then extract it.
   Open the extracted folder containing this README and `setup.cmd`.
4. Double-click **setup.cmd**. Internet access is required to install Python
   packages. Wait for setup and its smoke check to finish successfully.
5. Double-click **start.cmd**, keep that terminal open, and visit
   **http://127.0.0.1:8000** in your browser. Press Ctrl+C in the terminal to stop.

If Windows hides extensions, these may appear as `setup` and `start`.
No GitHub account is needed for a public download. For a private repository,
the owner must invite you and you must sign in to download it.

### Manual PowerShell setup

Run from the folder containing this README:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.\.venv\Scripts\python.exe smoke_check.py
.\.venv\Scripts\python.exe -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

No PowerShell activation or execution-policy change is required. Use one server
worker. If port 8000 is occupied, stop the earlier instance or use `--port 8001`.
For a nonstandard tshark installation, set `TSHARK_PATH` to the full executable
path in the same terminal before starting the server.

The Python dependencies are pinned to the model's tested environment. Do not
independently upgrade scikit-learn: saved sklearn models are version-sensitive.
Only load the bundled trusted joblib file; joblib loading can execute Python code.

## Using the dashboard

- **Load sample** checks the application using 100 normal AWID sample rows.
- **Upload capture** accepts `.pcap`, `.pcapng`, or AWID-format `.csv` files.
  Generic CSV files are not supported. Select ATK/CLS when applicable.
- Search packets by MAC, attack type or severity; inspect suspected APs and
  evidence tags; download filtered JSON/CSV results.
- Accuracy/F1 are saved research benchmark values, not scores for your upload.
- The rule panel exports templates for manual review; it does not execute blocks.
- Analysis is local. A new successful upload replaces the displayed capture;
  failed uploads keep previous results. Local state lives in `data/dashboard/`.
- Keep the server bound to 127.0.0.1. This distribution is a local, single-user
  application, not an authenticated public web service.

## Test files and known limitations

Try files under `data/dashboard-tests-new/`. Its README provides measured results.
Three are public Wireshark samples; one is newly generated synthetic traffic.
Historical v6 testing raised an unverified alert on the Nokia sample, missed the
synthetic impersonator, and rejected `wpa-Induction.pcap` with a parser error.
These failures are recorded rather than hidden. No guarantee of detecting every
rogue AP is made.

Detection applies to **beacons and probe responses**. Other packets provide
context and are marked not evaluated. Zero alerts does not prove a network safe.
There is **no live Wi-Fi monitoring, router integration, or automatic mitigation**.

The active artifact is `backend/models/v7_error_reduction_final/trained_ensemble.joblib`.
SHA256: `2eed9cb24f21fbb453f18ea11924712b15d66fac0e8e8ab1fd4fcd75cf7d66ac`.
This v7 reduces RogueAP misses from 44 to 33 and false flags from 184 to 175.
F1 rises from 82.02% to 83.62%. No FP/FN counts increase across the five
regression sets. Full results and limits are in `docs/v7-error-reduction-results.md`. These are previously examined
capture regressions, not independent production accuracy claims.

Restart the server and re-upload existing captures after updating. Previous v7
is retained at `backend/models/v7_advertiser_combined/trained_ensemble.joblib` for rollback using
`WIDS_MODEL_PATH`. Five new external PCAP compatibility checks are in
`data/dashboard-independent-round3`; these do not have verified rogue labels.
The older labelled tests in `data/dashboard-round2-heldout` have updated expected
counts. Full raw research datasets are excluded from this package.

Latest development update (2026-09-29): 15 additional training runs and new
control captures were evaluated. The candidate increased RogueAP false flags
and was rejected; the deployed model above is unchanged. See
`docs/v7-hard-negative-results.md` and `docs/experiments/` for results.
Experimental training scripts are included, with optional dependencies in
`backend/requirements-training.txt`. Reproducing training requires the external
datasets and feature caches described in the report; they are not bundled.

## What is included and excluded

Included: runtime source, training utilities for reference, deployed model and
its JSON reports, built UI plus frontend source, smoke check, and small samples.
Excluded: training datasets/caches, most historical model variants, full development
test suite, virtual environment, node_modules, personal captures, saved user
analyses, portable Wireshark binaries and local logs. Historical paths mentioned
in research reports refer to the development workspace and may not be bundled.
Training utilities need separately acquired datasets and are not a one-command
retraining workflow in this runtime distribution.

To edit/rebuild the UI, install a Node.js version supported by the pinned Vite
release (Node 22.12+ is a suitable baseline), then run:

```powershell
cd frontend
npm.cmd ci
npm.cmd run build
cd ..
```

Keep `frontend/dist` and the deployed model in Git; they are intentionally not
ignored. The built UI is supplied so end users can skip this step.

## Credits and distribution

Wireshark test capture sources and hashes: `data/dashboard-tests-new/sources.json`.
Training sources: AWID and WPA3 Attacks Dataset v2
(https://data.mendeley.com/datasets/cxx5t5nw7z/2, CC BY 4.0); see the model metadata
and research report for evaluation provenance. The original sample AWID CSV is
an ingestion example, not an attack evaluation dataset.
Frontend notices are in `frontend/THIRD_PARTY_NOTICES.md`,
`frontend/LICENSE-lucide.txt` and `frontend/DEPENDENCY_LICENSES.txt`.
No project-wide open-source license has been selected by the project owner.
Use a private repository for sharing with the intended collaborator until the
owner decides on public redistribution and licensing.
