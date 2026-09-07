import type { EvidenceCase } from "./evidence";

export type ArtifactProfile = {
  artifact_id: string;
  filename: string;
  kind: string;
  size_bytes: number;
  sha256: string;
  profiled_at: string;
  parser_version: string;
  signals: string[];
  tamper_signals: string[];
  strings: string[];
  ctf_candidates: string[];
  ctf_notes: string[];
  ctf_scanned_bytes: number;
  ctf_scan_scope?: "local-offline";
  case: EvidenceCase;
};

export type AnalysisMode = "investigate" | "challenge";

export type AnalysisResult = {
  mode: AnalysisMode;
  hypothesis: string;
  confidence: number;
  supporting_evidence: string[];
  contradicting_evidence: string[];
  alternative_explanations: string[];
  missing_evidence: string[];
  generated_by: string;
  evidence_basis?: EvidenceBasis[];
};

export type EvidenceBasis = {
  event_id: string;
  timestamp: string;
  event_type: string;
  object?: string | null;
  device?: string | null;
  source: string;
  detail?: string | null;
};

function validResult(value: unknown, evidenceIds: Set<string>): value is AnalysisResult {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<AnalysisResult>;
  return (candidate.mode === "investigate" || candidate.mode === "challenge")
    && typeof candidate.hypothesis === "string"
    && typeof candidate.confidence === "number"
    && candidate.confidence >= 0 && candidate.confidence <= 100
    && Array.isArray(candidate.supporting_evidence)
    && Array.isArray(candidate.contradicting_evidence)
    && candidate.supporting_evidence.every((id) => typeof id === "string" && evidenceIds.has(id))
    && candidate.contradicting_evidence.every((id) => typeof id === "string" && evidenceIds.has(id))
    && (!candidate.evidence_basis || (Array.isArray(candidate.evidence_basis) && candidate.evidence_basis.every((fact) => fact && typeof fact.event_id === "string" && evidenceIds.has(fact.event_id))));
}

export async function requestAnalysis(mode: AnalysisMode, caseFile: EvidenceCase): Promise<AnalysisResult | null> {
  const endpoint = import.meta.env.VITE_ANALYSIS_API_URL?.replace(/\/$/, "");
  if (!endpoint) return null;
  const response = await fetch(`${endpoint}/analyze/${mode}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode, case: caseFile }),
  });
  if (!response.ok) throw new Error(`Analysis service returned ${response.status}.`);
  const result: unknown = await response.json();
  const evidenceIds = new Set(caseFile.events.map((event) => event.event_id));
  if (!validResult(result, evidenceIds)) throw new Error("Analysis response was rejected: it contains invalid evidence references.");
  return result;
}

export async function requestNarration(mode: AnalysisMode, caseFile: EvidenceCase): Promise<string> {
  const endpoint = import.meta.env.VITE_ANALYSIS_API_URL?.replace(/\/$/, "");
  if (!endpoint) throw new Error("Narration needs a configured analysis API.");
  const response = await fetch(`${endpoint}/audio/brief`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode, case: caseFile }),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => null) as { detail?: string } | null;
    throw new Error(error?.detail ?? `Narration service returned ${response.status}.`);
  }
  if (!response.headers.get("content-type")?.includes("audio")) throw new Error("Narration service did not return audio.");
  return URL.createObjectURL(await response.blob());
}

export function profileArtifact(file: File, onProgress?: (percent: number) => void): Promise<ArtifactProfile> {
  const endpoint = import.meta.env.VITE_ANALYSIS_API_URL?.replace(/\/$/, "");
  if (!endpoint) return Promise.reject(new Error("Artifact profiling needs the local ForenSight backend running."));
  const body = new FormData();
  body.append("file", file);
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open("POST", `${endpoint}/artifacts/profile`);
    request.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress?.(Math.min(95, Math.round((event.loaded / event.total) * 100)));
    };
    request.onerror = () => reject(new Error("Artifact profiler could not be reached."));
    request.onload = () => {
      let response: ArtifactProfile | { detail?: string } | null = null;
      try { response = JSON.parse(request.responseText) as ArtifactProfile | { detail?: string }; } catch { /* handled below */ }
      if (request.status < 200 || request.status >= 300) {
        reject(new Error((response as { detail?: string } | null)?.detail ?? `Artifact profiler returned ${request.status}.`));
        return;
      }
      onProgress?.(100);
      resolve(response as ArtifactProfile);
    };
    request.send(body);
  });
}

export type RecoveredFile = { url: string; blob: Blob; sha256: string; size: number; kind: string };

export type LocalCaseSummary = {
  case_id: string;
  artifact_id: string;
  filename: string;
  sha256: string;
  profiled_at: string;
};

export type AuditEntry = {
  occurred_at: string;
  action: string;
  detail: Record<string, unknown>;
};

function configuredEndpoint() {
  return import.meta.env.VITE_ANALYSIS_API_URL?.replace(/\/$/, "");
}

export async function getLocalCases(): Promise<LocalCaseSummary[]> {
  const endpoint = configuredEndpoint();
  if (!endpoint) return [];
  const response = await fetch(`${endpoint}/cases`);
  if (!response.ok) throw new Error(`Local case archive returned ${response.status}.`);
  const body = await response.json() as { cases?: LocalCaseSummary[] };
  return Array.isArray(body.cases) ? body.cases : [];
}

export async function getLocalCase(caseId: string): Promise<ArtifactProfile> {
  const endpoint = configuredEndpoint();
  if (!endpoint) throw new Error("Opening a saved case needs the local ForenSight backend running.");
  const response = await fetch(`${endpoint}/cases/${encodeURIComponent(caseId)}`);
  if (!response.ok) throw new Error(`Saved case could not be opened (${response.status}).`);
  return response.json() as Promise<ArtifactProfile>;
}

export async function getCaseAudit(caseId: string): Promise<AuditEntry[]> {
  const endpoint = configuredEndpoint();
  if (!endpoint) return [];
  const response = await fetch(`${endpoint}/cases/${encodeURIComponent(caseId)}/audit`);
  if (!response.ok) throw new Error(`Local audit trail returned ${response.status}.`);
  const body = await response.json() as { entries?: AuditEntry[] };
  return Array.isArray(body.entries) ? body.entries : [];
}

export async function extractArtifactFile(file: File, inode: string, filename: string, caseId?: string, partitionOffset?: string): Promise<RecoveredFile> {
  const endpoint = import.meta.env.VITE_ANALYSIS_API_URL?.replace(/\/$/, "");
  if (!endpoint) throw new Error("Extraction needs the local ForenSight backend running.");
  const body = new FormData();
  body.append("file", file); body.append("inode", inode); body.append("filename", filename);
  if (caseId) body.append("case_id", caseId);
  if (partitionOffset) body.append("partition_offset", partitionOffset);
  const response = await fetch(`${endpoint}/artifacts/extract`, { method: "POST", body });
  if (!response.ok) throw new Error((await response.json().catch(() => null) as { detail?: string } | null)?.detail ?? "Safe extraction failed.");
  const blob = await response.blob();
  return { url: URL.createObjectURL(blob), blob, sha256: response.headers.get("x-forensight-sha256") ?? "Not available", size: Number(response.headers.get("x-forensight-size") ?? blob.size), kind: response.headers.get("x-forensight-kind") ?? "Recovered binary" };
}
