import type { EvidenceCase } from "./evidence";

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
