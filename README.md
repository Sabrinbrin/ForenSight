# ForenSight

An evidence-grounded digital-forensics investigation interface. ForenSight reconstructs a timeline from normalized evidence, makes provenance visible, and separates conclusions from uncertainty.

## Run locally

For the most reliable demo, start both local services with one command. It keeps artifacts on the investigator machine; only normalized evidence is sent to the optional OpenAI reasoning step.

```powershell
.\scripts\start-windows.ps1
```

On Linux:

```bash
chmod +x scripts/start-linux.sh
./scripts/start-linux.sh
```

Before the demo, run this known-good verification after the services start:

```powershell
.\scripts\verify-demo.ps1
```

The frontend requires Node.js. The local API runs in a Python virtual environment.

```powershell
npm install
npm run dev
```

### Linux demo API

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

Then copy `.env.example` to a frontend `.env` file and run `npm run dev`. The initial local API deliberately returns deterministic, evidence-cited analysis. It is useful for a reliable demo before configuring a hosted AI backend. The frontend remains usable with no backend at all.

## Evidence inputs

ForenSight accepts normalized `.json`/`.csv` event bundles and local raw artifacts including E01, EVTX, browser History SQLite, ZIP, PDF, image, MP3, MP4, and PCAP files. It never mounts or executes uploaded evidence.

For an E01, the Windows path uses Sleuth Kit to extract filesystem metadata. It additionally detects embedded Windows Registry hives, MFT, and USN artifacts; when a dedicated parser is unavailable it labels them as **discovered**, not semantically parsed. Embedded Windows EVTX and Chromium/Edge History are read into normalized events when found and readable.

The UI includes a small NIST CFReDS Data-Leakage-Case-inspired demo; it contains no raw image or answer key.

Required event fields: `event_id`, `timestamp`, `event_type`, and `source`.

```json
{
  "case_id": "case-001",
  "title": "Removable-media review",
  "events": [{
    "event_id": "E001",
    "timestamp": "2026-04-17T14:08:31Z",
    "event_type": "FILE_COPY",
    "actor": "alice",
    "object": "financial_report.xlsx",
    "device": "USB-E",
    "source": "USN Journal"
  }]
}
```

Supported event types: `USB_INSERT`, `FILE_ACCESS`, `FILE_COPY`, `USB_REMOVE`, `PROCESS_START`, `BROWSER_ACTIVITY`, `OTHER`.

## Deployment

The GitHub Actions workflow builds and deploys the static frontend to GitHub Pages after a push to `main`. Enable **Settings → Pages → GitHub Actions** in the repository.

## Security model

The hosted Investigate/Challenge API is in `supabase/functions/analyze/index.ts`. It accepts only normalized events, limits request size, asks the model for schema-constrained output, and rejects any response that cites evidence IDs not present in the submitted case.

Set these **Supabase Edge Function secrets** before deployment:

```text
OPENAI_API_KEY=...
OPENAI_MODEL=...  # a model that supports Responses structured outputs
```

The OpenAI API key must be stored only as the `OPENAI_API_KEY` Supabase secret—never in frontend code, GitHub Actions variables, or a checked-in `.env` file. Update the function's `allowedOrigins` list with the final GitHub Pages URL if it differs from `https://sabrinbrin.github.io`.

## Optional ElevenLabs case brief

The local FastAPI service exposes `POST /audio/brief`. It turns the current deterministic, evidence-cited case summary into an MP3 only when these values are present in `backend/.env`:

```text
ELEVENLABS_API_KEY=...
ELEVENLABS_VOICE_ID=...
ELEVENLABS_MODEL_ID=eleven_multilingual_v2
```

The browser requests audio from the local backend; the ElevenLabs key is never sent to the browser. ElevenLabs accepts the key through an `xi-api-key` request header and its synchronous text-to-speech endpoint returns audio. [ElevenLabs TTS API documentation](https://elevenlabs.io/docs/api-reference/text-to-speech/convert?explorer=true)

## Optional VirusTotal hash enrichment

The local backend exposes `POST /enrich/virustotal` for a **SHA-256 hash only**. It never uploads a file or a disk image to VirusTotal. Add `VIRUSTOTAL_API_KEY` to `backend/.env`; results are marked as external intelligence and should support, never replace, artifact evidence. VirusTotal identifies file objects by SHA-256 and provides the latest analysis statistics for known files. [VirusTotal file API documentation](https://docs.virustotal.com/reference/files)

## Linux E01 filesystem timeline

The default requirements keep Windows profiling lightweight. For a local Linux investigator environment that needs E01 filesystem timeline extraction, install the extra reader before starting the backend:

```bash
python -m pip install -r backend/requirements-linux.txt
```

The E01 pipeline stays read-only: `libewf` opens the E01 container and `pytsk3` enumerates recoverable filesystem metadata into normalized timeline events. It does not mount or modify the evidence image.

## Evidence grounding and CTF workflow

Every AI result is rejected if it cites an event ID that is not in the submitted case. For each valid citation, the interface now exposes the literal timestamp, source, object, and detail fields that the model was permitted to use.

The CTF Hunt runs a bounded local scan of the first 8 MB for generic `prefix{value}` candidates and strict Base64-decoded candidates. Change the convention in the UI for the competition you are solving. Hits are leads only—not automatically proven flags.
