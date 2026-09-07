// Supabase Edge Function: evidence-grounded Investigate / Challenge analysis.
// Deploy only after setting OPENAI_API_KEY and OPENAI_MODEL as Supabase secrets.

const allowedOrigins = new Set(["http://localhost:5173", "https://sabrinbrin.github.io"]);

type EvidenceEvent = { event_id: string; timestamp: string; event_type: string; actor?: string; object?: string; device?: string; source: string; detail?: string };
type Analysis = {
  mode: "investigate" | "challenge";
  hypothesis: string;
  confidence: number;
  supporting_evidence: string[];
  contradicting_evidence: string[];
  alternative_explanations: string[];
  missing_evidence: string[];
  generated_by: "openai";
};

function corsHeaders(origin: string | null) {
  return { "access-control-allow-origin": origin && allowedOrigins.has(origin) ? origin : "", "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "content-type", "content-type": "application/json; charset=utf-8", "vary": "Origin" };
}
function response(body: unknown, status: number, origin: string | null) { return new Response(JSON.stringify(body), { status, headers: corsHeaders(origin) }); }
function hasOnlyKnownIds(ids: unknown, knownIds: Set<string>): ids is string[] { return Array.isArray(ids) && ids.every((id) => typeof id === "string" && knownIds.has(id)); }
function extractOutputText(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;
  const responseBody = body as { output_text?: unknown; output?: Array<{ content?: Array<{ type?: string; text?: string }> }> };
  if (typeof responseBody.output_text === "string") return responseBody.output_text;
  for (const item of responseBody.output ?? []) {
    for (const content of item.content ?? []) if (content.type === "output_text" && typeof content.text === "string") return content.text;
  }
  return null;
}
function isValidAnalysis(value: unknown, knownIds: Set<string>, mode: string): value is Analysis {
  if (!value || typeof value !== "object") return false;
  const analysis = value as Partial<Analysis>;
  return analysis.mode === mode && typeof analysis.hypothesis === "string" && typeof analysis.confidence === "number" && analysis.confidence >= 0 && analysis.confidence <= 100 && hasOnlyKnownIds(analysis.supporting_evidence, knownIds) && hasOnlyKnownIds(analysis.contradicting_evidence, knownIds) && Array.isArray(analysis.alternative_explanations) && analysis.alternative_explanations.every((item) => typeof item === "string") && Array.isArray(analysis.missing_evidence) && analysis.missing_evidence.every((item) => typeof item === "string");
}

const analysisSchema = {
  type: "object", additionalProperties: false,
  required: ["mode", "hypothesis", "confidence", "supporting_evidence", "contradicting_evidence", "alternative_explanations", "missing_evidence", "generated_by"],
  properties: {
    mode: { type: "string", enum: ["investigate", "challenge"] }, hypothesis: { type: "string" }, confidence: { type: "number", minimum: 0, maximum: 100 },
    supporting_evidence: { type: "array", items: { type: "string" } }, contradicting_evidence: { type: "array", items: { type: "string" } },
    alternative_explanations: { type: "array", items: { type: "string" } }, missing_evidence: { type: "array", items: { type: "string" } }, generated_by: { type: "string", enum: ["openai"] },
  },
};

Deno.serve(async (req) => {
  const origin = req.headers.get("origin");
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(origin) });
  if (req.method !== "POST") return response({ error: "Method not allowed" }, 405, origin);
  if (!origin || !allowedOrigins.has(origin)) return response({ error: "Origin not allowed" }, 403, origin);
  try {
    const input = await req.json();
    const mode = input?.mode;
    const evidence = input?.case?.events;
    if ((mode !== "investigate" && mode !== "challenge") || !Array.isArray(evidence) || evidence.length === 0 || evidence.length > 5000) return response({ error: "Expected mode and 1–5000 normalized events." }, 400, origin);
    if (!evidence.every((event: EvidenceEvent) => event?.event_id && event?.timestamp && event?.event_type && event?.source)) return response({ error: "Each event needs event_id, timestamp, event_type, and source." }, 400, origin);
    const knownIds = new Set(evidence.map((event: EvidenceEvent) => event.event_id));
    if (knownIds.size !== evidence.length) return response({ error: "event_id values must be unique." }, 400, origin);
    const apiKey = Deno.env.get("OPENAI_API_KEY");
    const model = Deno.env.get("OPENAI_MODEL");
    if (!apiKey || !model) return response({ error: "AI analysis is not configured." }, 503, origin);
    const instruction = mode === "challenge" ? "Attempt to disprove the primary removable-media / data-leakage interpretation. Identify only evidence-backed contradictions, alternatives, and gaps." : "Reconstruct the most likely incident from the evidence. State uncertainty precisely and do not infer facts outside the events.";
    const openAiResponse = await fetch("https://api.openai.com/v1/responses", {
      method: "POST", headers: { "authorization": `Bearer ${apiKey}`, "content-type": "application/json" },
      body: JSON.stringify({ model, input: [{ role: "developer", content: "You are an evidence-grounded digital-forensics analyst. Every evidence reference must be an event_id from the supplied case. Never invent an evidence ID." }, { role: "user", content: `${instruction}\n\nMODE: ${mode}\n\nCASE:\n${JSON.stringify(input.case)}` }], text: { format: { type: "json_schema", name: "forensight_analysis", strict: true, schema: analysisSchema } } }),
    });
    if (!openAiResponse.ok) return response({ error: "Analysis provider request failed." }, 502, origin);
    const providerBody = await openAiResponse.json();
    const outputText = extractOutputText(providerBody);
    if (!outputText) return response({ error: "Analysis provider returned no structured output." }, 502, origin);
    const analysis = JSON.parse(outputText);
    if (!isValidAnalysis(analysis, knownIds, mode)) return response({ error: "Analysis result rejected by evidence validator." }, 422, origin);
    return response(analysis, 200, origin);
  } catch { return response({ error: "Invalid analysis request." }, 400, origin); }
});
