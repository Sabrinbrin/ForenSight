"""Small Linux-friendly API for the ForenSight demo.

This service intentionally accepts only normalized event bundles. It never
opens, mounts, or executes files from raw E01/DD images.
"""
from __future__ import annotations

import os
import json
import re
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

EventType = Literal[
    "USB_INSERT", "FILE_ACCESS", "FILE_COPY", "USB_REMOVE",
    "PROCESS_START", "BROWSER_ACTIVITY", "OTHER",
]


class EvidenceEvent(BaseModel):
    event_id: str = Field(min_length=1, max_length=128)
    timestamp: datetime
    event_type: EventType
    actor: str | None = Field(default=None, max_length=256)
    object: str | None = Field(default=None, max_length=512)
    device: str | None = Field(default=None, max_length=256)
    source: str = Field(min_length=1, max_length=256)
    detail: str | None = Field(default=None, max_length=2000)


class EvidenceCase(BaseModel):
    case_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=2000)
    events: list[EvidenceEvent] = Field(min_length=1)

    @field_validator("events")
    @classmethod
    def evidence_ids_are_unique(cls, events: list[EvidenceEvent]) -> list[EvidenceEvent]:
        ids = [event.event_id for event in events]
        if len(ids) != len(set(ids)):
            raise ValueError("event_id values must be unique")
        limit = int(os.getenv("FORENSIGHT_MAX_EVENTS", "5000"))
        if len(events) > limit:
            raise ValueError(f"event bundles are limited to {limit} events")
        return events


class AnalysisRequest(BaseModel):
    case: EvidenceCase


class BriefRequest(AnalysisRequest):
    mode: Literal["investigate", "challenge"] = "investigate"


class VirusTotalLookup(BaseModel):
    """Hash-only lookup: evidence files never leave the investigator's machine."""
    sha256: str = Field(min_length=64, max_length=64)

    @field_validator("sha256")
    @classmethod
    def sha256_is_valid(cls, value: str) -> str:
        normalized = value.lower()
        if not re.fullmatch(r"[a-f0-9]{64}", normalized):
            raise ValueError("A SHA-256 hash must contain exactly 64 hexadecimal characters")
        return normalized


def correlated_events(events: list[EvidenceEvent]) -> list[EvidenceEvent]:
    return [event for event in events if event.event_type in {
        "USB_INSERT", "FILE_ACCESS", "FILE_COPY", "USB_REMOVE"
    }]


def citation_ids(events: list[EvidenceEvent]) -> list[str]:
    return [event.event_id for event in correlated_events(events)]


def build_investigation(case: EvidenceCase) -> dict:
    evidence = correlated_events(case.events)
    event_types = {event.event_type for event in evidence}
    complete_chain = {"USB_INSERT", "FILE_ACCESS", "FILE_COPY", "USB_REMOVE"}.issubset(event_types)
    copied = next((event for event in evidence if event.event_type == "FILE_COPY"), None)
    confidence = 87 if complete_chain else 45
    target = copied.object if copied and copied.object else "a file"
    device = copied.device if copied and copied.device else "removable media"
    return {
        "mode": "investigate",
        "hypothesis": f"The evidence supports a likely transfer of {target} to {device}." if copied else "The evidence does not yet establish a removable-media transfer.",
        "confidence": confidence,
        "supporting_evidence": citation_ids(case.events),
        "contradicting_evidence": [],
        "alternative_explanations": [],
        "missing_evidence": ["No process-level copy event identifies the application responsible for the transfer."],
        "generated_by": "deterministic-demo",
    }


def build_challenge(case: EvidenceCase) -> dict:
    contradictions = [event.event_id for event in case.events if event.event_type == "OTHER"]
    return {
        "mode": "challenge",
        "hypothesis": "The removable-media transfer hypothesis is plausible but not proven.",
        "confidence": 67 if contradictions else 75,
        "supporting_evidence": citation_ids(case.events),
        "contradicting_evidence": contradictions,
        "alternative_explanations": ["The file may have existed on the removable device during an earlier session."],
        "missing_evidence": ["Process-level copy telemetry or complete removable-media metadata would better distinguish the alternatives."],
        "generated_by": "deterministic-demo",
    }


def narration_text(case: EvidenceCase, mode: Literal["investigate", "challenge"]) -> str:
    analysis = build_challenge(case) if mode == "challenge" else build_investigation(case)
    evidence = ", ".join(analysis["supporting_evidence"][:4]) or "no corroborating events"
    gaps = analysis["missing_evidence"][0] if analysis["missing_evidence"] else "No material gaps were identified."
    alternatives = analysis["alternative_explanations"][0] if analysis["alternative_explanations"] else "No alternative explanation was identified."
    return (
        f"ForenSight case brief for {case.title}. {analysis['hypothesis']} "
        f"Confidence is {analysis['confidence']} percent. Supporting evidence: {evidence}. "
        f"{('Alternative explanation: ' + alternatives + '. ') if mode == 'challenge' else ''}"
        f"Investigation gap: {gaps}"
    )[:1800]


allowed_origins = [origin.strip() for origin in os.getenv(
    "FORENSIGHT_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
).split(",") if origin.strip()]

app = FastAPI(title="ForenSight local demo API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["content-type"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "forensight-local-demo"}


@app.post("/analyze/investigate")
def investigate(request: AnalysisRequest) -> dict:
    return build_investigation(request.case)


@app.post("/analyze/challenge")
def challenge(request: AnalysisRequest) -> dict:
    return build_challenge(request.case)


@app.post("/audio/brief")
def create_case_brief(request: BriefRequest) -> Response:
    """Create an optional MP3 narration; the ElevenLabs key stays on this server."""
    api_key = os.getenv("ELEVENLABS_API_KEY")
    voice_id = os.getenv("ELEVENLABS_VOICE_ID")
    if not api_key or not voice_id:
        raise HTTPException(status_code=503, detail="ElevenLabs narration is not configured.")
    payload = json.dumps({
        "text": narration_text(request.case, request.mode),
        "model_id": os.getenv("ELEVENLABS_MODEL_ID", "eleven_multilingual_v2"),
    }).encode("utf-8")
    eleven_request = urllib.request.Request(
        f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}?output_format=mp3_44100_128",
        data=payload,
        headers={"xi-api-key": api_key, "content-type": "application/json", "accept": "audio/mpeg"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(eleven_request, timeout=30) as eleven_response:
            audio = eleven_response.read()
    except urllib.error.HTTPError as error:
        raise HTTPException(status_code=502, detail=f"ElevenLabs request failed ({error.code}).") from error
    except urllib.error.URLError as error:
        raise HTTPException(status_code=502, detail="Could not reach ElevenLabs.") from error
    return Response(content=audio, media_type="audio/mpeg", headers={"cache-control": "no-store"})


@app.post("/enrich/virustotal")
def enrich_with_virustotal(lookup: VirusTotalLookup) -> dict:
    """Retrieve public reputation for a known hash without uploading a file."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise HTTPException(status_code=503, detail="VirusTotal enrichment is not configured.")
    vt_request = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{lookup.sha256}",
        headers={"x-apikey": api_key, "accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(vt_request, timeout=20) as vt_response:
            raw = json.loads(vt_response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {"sha256": lookup.sha256, "status": "not_found", "source": "VirusTotal"}
        raise HTTPException(status_code=502, detail=f"VirusTotal request failed ({error.code}).") from error
    except urllib.error.URLError as error:
        raise HTTPException(status_code=502, detail="Could not reach VirusTotal.") from error

    attributes = raw.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    return {
        "sha256": lookup.sha256,
        "status": "found",
        "source": "VirusTotal",
        "meaningful_name": attributes.get("meaningful_name"),
        "reputation": attributes.get("reputation"),
        "analysis_stats": {key: stats.get(key, 0) for key in ("malicious", "suspicious", "harmless", "undetected")},
        "permalink": f"https://www.virustotal.com/gui/file/{lookup.sha256}",
    }
