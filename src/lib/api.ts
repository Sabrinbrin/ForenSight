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
    && candidate.contradicting_evidence.every((id) => typeof id === "string" && evidenceIds.has(id));
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

export async function extractArtifactFile(file: File, inode: string, filename: string): Promise<string> {
  const endpoint = import.meta.env.VITE_ANALYSIS_API_URL?.replace(/\/$/, "");
  if (!endpoint) throw new Error("Extraction needs the local ForenSight backend running.");
  const body = new FormData();
  body.append("file", file); body.append("inode", inode); body.append("filename", filename);
  const response = await fetch(`${endpoint}/artifacts/extract`, { method: "POST", body });
  if (!response.ok) throw new Error((await response.json().catch(() => null) as { detail?: string } | null)?.detail ?? "Safe extraction failed.");
  return URL.createObjectURL(await response.blob());
}
