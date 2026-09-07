import { useEffect, useMemo, useRef, useState } from "react";
import { demoCase } from "./data/demoCase";
import { parseCsv, validateCase, type EvidenceCase, type EvidenceEvent } from "./lib/evidence";
import { extractArtifactFile, getCaseAudit, getLocalCase, getLocalCases, profileArtifact, requestAnalysis, requestNarration, type AnalysisResult, type AnalysisMode, type ArtifactProfile, type AuditEntry, type LocalCaseSummary } from "./lib/api";

const eventLabels: Record<EvidenceEvent["event_type"], string> = {
  USB_INSERT: "USB connected", FILE_ACCESS: "File accessed", FILE_COPY: "File copied", USB_REMOVE: "USB removed", PROCESS_START: "Process started", BROWSER_ACTIVITY: "Browser activity", FILE_MODIFIED: "File metadata", FILE_DELETED: "Deleted file recovered", ARCHIVE_FOUND: "Archive found", MEDIA_FOUND: "Media found", DOCUMENT_FOUND: "Document found", EXECUTABLE_FOUND: "Executable or script found", OTHER: "Evidence note",
};

function time(event: EvidenceEvent) { return new Date(event.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
function detailValue(detail: string | undefined, pattern: RegExp) { return detail?.match(pattern)?.[1] ?? "Not recovered"; }
function flagMatcher(convention: string) {
  const trimmed = convention.trim();
  if (!trimmed) return null;
  if (trimmed.includes("...")) return new RegExp(`${trimmed.slice(0, trimmed.indexOf("...")).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[^\\s}]{1,200}\\}`, "gi");
  try { return new RegExp(trimmed, "gi"); } catch { return new RegExp(`${trimmed.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[^\\s}]{1,200}\\}`, "gi"); }
}

export default function App() {
  const [caseFile, setCaseFile] = useState<EvidenceCase>(demoCase);
  const [selected, setSelected] = useState<EvidenceEvent>(demoCase.events[2]);
  const [message, setMessage] = useState("Demo evidence loaded. Every claim must cite these IDs.");
  const [mode, setMode] = useState<AnalysisMode>("investigate");
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [narrating, setNarrating] = useState(false);
  const [replaying, setReplaying] = useState(false);
  const [activeHypothesis, setActiveHypothesis] = useState<"H1" | "H2">("H1");
  const [reviewStarted, setReviewStarted] = useState(false);
  const [evidenceUploaded, setEvidenceUploaded] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<"ALL" | EvidenceEvent["event_type"]>("ALL");
  const [deletedOnly, setDeletedOnly] = useState(false);
  const [selectedEvidenceIds, setSelectedEvidenceIds] = useState<Set<string>>(new Set());
  const [artifactFile, setArtifactFile] = useState<File | null>(null);
  const [flagConvention, setFlagConvention] = useState("picoCTF{...}");
  const [recoveredInspection, setRecoveredInspection] = useState<{ name: string; sha256: string; size: number; kind: string; candidates: string[]; strings: string[] } | null>(null);
  const [artifactProfile, setArtifactProfile] = useState<ArtifactProfile | null>(null);
  const [recentCases, setRecentCases] = useState<LocalCaseSummary[]>([]);
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const input = useRef<HTMLInputElement>(null);
  const events = useMemo(() => [...caseFile.events].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp)), [caseFile]);
  const visibleEvents = useMemo(() => events.filter((event) => {
    const matchesType = typeFilter === "ALL" || event.event_type === typeFilter;
    const matchesDeleted = !deletedOnly || event.event_type === "FILE_DELETED";
    const text = `${event.object ?? ""} ${event.detail ?? ""} ${event.source}`.toLowerCase();
    return matchesType && matchesDeleted && (!query || text.includes(query.toLowerCase()));
  }), [events, typeFilter, deletedOnly, query]);
  const triage = useMemo(() => ({ deleted: events.filter((event) => event.event_type === "FILE_DELETED").length, archives: events.filter((event) => event.event_type === "ARCHIVE_FOUND").length, executables: events.filter((event) => event.event_type === "EXECUTABLE_FOUND").length, documents: events.filter((event) => event.event_type === "DOCUMENT_FOUND").length }), [events]);
  const analysisEvents = selectedEvidenceIds.size ? events.filter((event) => selectedEvidenceIds.has(event.event_id)) : visibleEvents;
  const flagCandidates = useMemo(() => {
    const matcher = artifactProfile ? flagMatcher(flagConvention.replace("...", "")) : null;
    if (!matcher) return [];
    return [...(artifactProfile!.ctf_candidates ?? []), ...artifactProfile!.strings].flatMap((value) => Array.from(value.matchAll(matcher)).map((match) => match[0])).filter((value, index, values) => values.indexOf(value) === index).slice(0, 12);
  }, [artifactProfile, flagConvention]);
  const directEvidence = events.filter((event) => event.event_type === "USB_INSERT" || event.event_type === "FILE_ACCESS" || event.event_type === "FILE_COPY" || event.event_type === "USB_REMOVE");
  const hasCurrentAnalysis = analysis?.mode === mode;
  const containerOnly = artifactProfile?.kind === "E01 forensic image" && events.length <= 1;
  const confidence = hasCurrentAnalysis ? analysis.confidence : 0;
  const hypothesis = hasCurrentAnalysis
    ? analysis.hypothesis
    : containerOnly
      ? "Timeline extraction is required before this image can be investigated."
      : "Review the submitted evidence to generate an evidence-backed finding.";
  const alternative = hasCurrentAnalysis ? analysis.alternative_explanations[0] : undefined;

  async function refreshLocalCases() {
    try { setRecentCases(await getLocalCases()); } catch { /* Archive remains optional when backend is offline. */ }
  }

  async function refreshAudit(caseId: string) {
    try { setAuditEntries(await getCaseAudit(caseId)); } catch { setAuditEntries([]); }
  }

  useEffect(() => { void refreshLocalCases(); }, []);

  async function chooseMode(next: AnalysisMode) {
    if (!evidenceUploaded) {
      setMessage("Upload an evidence artifact before starting a review.");
      input.current?.click();
      return;
    }
    setReviewStarted(true); setMode(next); setAnalyzing(true);
    try {
      if (!analysisEvents.length) throw new Error("Select or filter at least one evidence event before reviewing.");
      const scopedCase = { ...caseFile, title: `${caseFile.title} (${analysisEvents.length} selected event${analysisEvents.length === 1 ? "" : "s"})`, events: analysisEvents };
      const result = await requestAnalysis(next, scopedCase);
      if (result) {
        setAnalysis(result);
        void refreshAudit(caseFile.case_id);
        setMessage(`${next === "challenge" ? "Challenge" : "Investigation"} complete for ${analysisEvents.length} event${analysisEvents.length === 1 ? "" : "s"} (${result.generated_by}). Every cited ID was validated.`);
      } else {
        setAnalysis(null);
        setMessage("Deterministic demo mode. Set VITE_ANALYSIS_API_URL to use the local analysis service.");
      }
    } catch (error) {
      setAnalysis(null);
      setMessage(error instanceof Error ? error.message : "Analysis request failed.");
    } finally { setAnalyzing(false); }
  }

  function exportReport() {
    const reportEvents = analysisEvents.length ? analysisEvents : events;
    const content = [`# ForenSight case report`, ``, `## Case`, `- Title: ${caseFile.title}`, `- Case ID: ${caseFile.case_id}`, artifactProfile ? `- Artifact: ${artifactProfile.filename}` : "", artifactProfile ? `- SHA-256: ${artifactProfile.sha256}` : "", `- Exported: ${new Date().toISOString()}`, ``, `## Investigation finding`, `- ${hypothesis}`, `- Confidence: ${confidence}%`, analysis ? `- Engine: ${analysis.generated_by}` : "", ``, `## Evidence scope (${reportEvents.length} events)`, ...reportEvents.map((event) => `- ${event.event_id} | ${event.timestamp} | ${eventLabels[event.event_type]} | ${event.object ?? event.source}`), ``, `## Gaps / next inspection`, `- ${analysis?.missing_evidence[0] ?? "No automated gap assessment has been generated yet."}`].filter(Boolean).join("\n");
    const url = URL.createObjectURL(new Blob([content], { type: "text/markdown" }));
    const link = document.createElement("a"); link.href = url; link.download = `${caseFile.case_id}-forensight-report.md`; link.click(); URL.revokeObjectURL(url);
    setMessage("Local case report downloaded. No evidence files were exported or uploaded.");
  }

  async function copySelectedPath() {
    if (!selected.object) return;
    await navigator.clipboard?.writeText(selected.object);
    setMessage("Selected evidence path copied locally.");
  }
  function showLikelyCtfFiles() {
    const likely = events.find((event) => /flag|pico|ctf|secret/i.test(`${event.object ?? ""} ${event.detail ?? ""}`));
    setQuery("flag"); setReviewStarted(true);
    if (likely) { setSelected(likely); setMessage(`Showing likely local CTF evidence. Select ${likely.object ?? likely.event_id}, then use Extract safe copy to inspect its bytes.`); }
    else setMessage("No flag-named path was recovered. Try searching the timeline for ctf, pico, secret, or deleted.");
  }
  async function extractSelectedFile() {
    const inode = detailValue(selected.detail, /inode (\d+)/);
    if (!artifactFile || inode === "Not recovered" || !selected.object) { setMessage("Select a recovered filesystem entry from an uploaded E01."); return; }
    try { const partitionOffset = detailValue(selected.detail, /partition sector (\d+)/); const recovered = await extractArtifactFile(artifactFile, inode, selected.object, caseFile.case_id, partitionOffset === "Not recovered" ? undefined : partitionOffset); const inspectedBytes = Math.min(recovered.size, 8 * 1024 * 1024); const inspectedBlob = recovered.blob.slice(0, inspectedBytes); const rawBytes = await inspectedBlob.arrayBuffer(); const text = await inspectedBlob.text(); const utf16LeText = new TextDecoder("utf-16le").decode(rawBytes); const utf16BeText = new TextDecoder("utf-16be").decode(rawBytes); const strings = Array.from(text.matchAll(/[\x20-\x7e]{6,}/g), (match) => match[0]).slice(0, 30); const matcher = flagMatcher(flagConvention); const candidates = matcher ? Array.from(`${text}\n${utf16LeText}\n${utf16BeText}`.matchAll(matcher), (match) => match[0]).filter((value, index, values) => values.indexOf(value) === index).slice(0, 12) : []; const name = selected.object.split("/").pop() || `inode-${inode}.bin`; setRecoveredInspection({ name, sha256: recovered.sha256, size: recovered.size, kind: recovered.kind, candidates, strings }); const link = document.createElement("a"); link.href = recovered.url; link.download = name; link.click(); URL.revokeObjectURL(recovered.url); void refreshAudit(caseFile.case_id); const scannedLabel = inspectedBytes < 1024 ? `${inspectedBytes} bytes` : `${Math.round(inspectedBytes / 1024).toLocaleString()} KB`; setMessage(`Recovered copy inspected locally (${scannedLabel} scanned). ${candidates.length} flag candidate${candidates.length === 1 ? "" : "s"} found.`); } catch (error) { setMessage(error instanceof Error ? error.message : "Safe extraction failed."); }
  }

  async function playBrief() {
    setNarrating(true);
    try {
      const audioUrl = await requestNarration(mode, caseFile);
      const player = new Audio(audioUrl);
      player.onended = () => URL.revokeObjectURL(audioUrl);
      await player.play();
      setMessage("Playing an evidence-backed case brief. It is generated only from this submitted case.");
    } catch (error) {
      if ("speechSynthesis" in window) {
        window.speechSynthesis.cancel();
        const voice = new SpeechSynthesisUtterance(`${hypothesis}. The evidence chain contains ${directEvidence.map((event) => event.event_id).join(", ")}.`);
        voice.rate = 1;
        window.speechSynthesis.speak(voice);
        setMessage("Playing a local browser voice preview. Add ElevenLabs keys to use the production case brief.");
      } else setMessage(error instanceof Error ? error.message : "Narration request failed.");
    }
    finally { setNarrating(false); }
  }

  async function replayEvidence() {
    if (replaying) return;
    const delay = Math.max(120, Math.min(500, Math.floor(8000 / events.length)));
    setReplaying(true); setMode("investigate"); setMessage(`Replaying ${events.length} observed events from the earliest timestamp.`);
    for (const event of events) {
      setSelected(event);
      await new Promise((resolve) => window.setTimeout(resolve, delay));
    }
    setMessage("Replay complete. This is an evidence replay, not a claim that causality is proven.");
    setReplaying(false);
  }

  async function upload(file?: File) {
    if (!file) return;
    setUploading(true); setUploadProgress(0); setMessage(`Uploading ${file.name} securely to the local analyzer…`);
    try {
      const structuredEvidence = file.name.toLowerCase().endsWith(".csv") || file.name.toLowerCase().endsWith(".json");
      const raw = structuredEvidence ? await file.text() : "";
      if (structuredEvidence) setUploadProgress(70);
      const profile = structuredEvidence ? null : await profileArtifact(file, setUploadProgress);
      setUploadProgress(100);
      setMessage("Evidence received. Building the local timeline…");
      const next = file.name.toLowerCase().endsWith(".csv") ? parseCsv(raw) : file.name.toLowerCase().endsWith(".json") ? validateCase(JSON.parse(raw)) : validateCase(profile!.case);
      setCaseFile(next); setSelected(next.events[0]); setMode("investigate"); setAnalysis(null); setReviewStarted(false); setEvidenceUploaded(true); setQuery(""); setTypeFilter("ALL"); setDeletedOnly(false); setSelectedEvidenceIds(new Set()); setArtifactFile(structuredEvidence ? null : file);
      setArtifactProfile(profile);
      setRecoveredInspection(null); setAuditEntries([]);
      if (profile) { void refreshLocalCases(); void refreshAudit(profile.case.case_id); }
      setMessage(profile ? `${profile.kind} profiled locally. Press Start reviewing when you are ready.` : `${next.events.length} events loaded. Press Start reviewing when you are ready.`);
    } catch (error) { setMessage(error instanceof Error ? error.message : "Unable to parse this evidence bundle."); }
    finally { setUploading(false); if (input.current) input.current.value = ""; }
  }

  async function openSavedCase(caseId: string) {
    try {
      const profile = await getLocalCase(caseId);
      setCaseFile(profile.case); setSelected(profile.case.events[0]); setArtifactProfile(profile); setArtifactFile(null);
      setEvidenceUploaded(true); setReviewStarted(false); setAnalysis(null); setSelectedEvidenceIds(new Set()); setRecoveredInspection(null);
      await refreshAudit(caseId);
      setMessage("Saved metadata reopened locally. Re-upload the original E01 if you want to extract a safe copy.");
    } catch (error) { setMessage(error instanceof Error ? error.message : "Saved case could not be opened."); }
  }

  return <main>
    <header className="topbar">
      <a className="brand" href="#top"><span className="brand-mark" role="img" aria-label="Time machine">🕰️</span> FORENSIGHT</a>
      <div className="case-chip"><span className="pulse" /> {evidenceUploaded ? caseFile.case_id : "NO EVIDENCE LOADED"}</div>
      <input ref={input} type="file" accept="*/*" onChange={(event) => upload(event.target.files?.[0])} disabled={uploading} hidden />
    </header>

    <section className="hero" id="top">
      <div className="hero-copy"><p className="eyebrow">FORENSIGHT CASE REVIEW</p><h1>Understand your<br /><em>evidence clearly.</em></h1><p className="lede">Upload a timeline of device and file activity. ForenSight puts it in order, explains what it may mean, and shows what is still uncertain.</p><div className="hero-actions"><button className="primary-action" onClick={() => evidenceUploaded ? chooseMode("investigate") : input.current?.click()} disabled={analyzing || uploading}>{analyzing ? "Looking at evidence…" : evidenceUploaded ? selectedEvidenceIds.size ? `Review ${selectedEvidenceIds.size} selected` : `Review ${analysisEvents.length} visible` : "Upload evidence"}</button>{evidenceUploaded && <button className="quiet-action" onClick={() => input.current?.click()} disabled={uploading}>Replace evidence</button>}{evidenceUploaded && <button className="quiet-action" onClick={exportReport}>Export report</button>}{reviewStarted && <button className="quiet-action" onClick={playBrief} disabled={narrating}>{narrating ? "Preparing brief…" : "Hear the summary"}</button>}</div></div>
      <div className="hero-status">{evidenceUploaded ? <><span>READY TO REVIEW</span><strong>Your evidence is loaded</strong><p>{events.length} events are ready. Start reviewing to see the timeline and conclusions.</p><div><b>{events.length}</b><small>events ready</small></div></> : <><span>HOW IT WORKS</span><strong>Start with your evidence</strong><p>Upload an artifact or a JSON/CSV timeline to begin a private local review.</p><div><b>01</b><small>upload evidence</small></div></>}</div>
    </section>

    {!evidenceUploaded && recentCases.length > 0 && <section className="local-case-archive" aria-label="Saved local cases"><div><p className="panel-label">LOCAL CASE ARCHIVE</p><h2>Continue a recent review</h2><p>Only normalized case metadata and the audit trail are saved. Original artifacts stay where you chose them.</p></div><ul>{recentCases.slice(0, 3).map((saved) => <li key={saved.case_id}><button onClick={() => openSavedCase(saved.case_id)}><strong>{saved.filename}</strong><small>{new Date(saved.profiled_at).toLocaleString()} · {saved.sha256.slice(0, 12)}</small></button></li>)}</ul></section>}

    {uploading && <section className="upload-progress" aria-live="polite" aria-label="Evidence upload progress">
      <div><span>LOCAL EVIDENCE INTAKE</span><strong>{uploadProgress < 100 ? `Uploading ${uploadProgress}%` : "Profiling evidence locally…"}</strong></div>
      <div className="progress-track"><i style={{ width: `${Math.max(4, uploadProgress)}%` }} /></div>
      <p>Your artifact stays on this machine. It is not sent to OpenAI.</p>
    </section>}

    {evidenceUploaded && <section className="fact-strip" aria-label="Case facts">
      <div><span>EVENTS REVIEWED</span><strong>{events.length}</strong></div><div><span>ARTIFACT SOURCES</span><strong>{new Set(events.map((event) => event.source)).size}</strong></div><div><span>TIME WINDOW</span><strong>{time(events[0])}—{time(events.at(-1)!)}</strong></div><div><span>STATUS</span><strong className="status-text">Open review</strong></div>
    </section>}

    {evidenceUploaded && <section className="triage" aria-label="Evidence triage"><div className="triage-heading"><div><p className="panel-label">INVESTIGATOR TRIAGE</p><h2>Start with the highest-value evidence</h2></div><button onClick={() => { setQuery(""); setTypeFilter("ALL"); setDeletedOnly(false); }}>Clear filters</button></div><div className="triage-cards"><button onClick={() => { setDeletedOnly(true); setTypeFilter("ALL"); }}><b>{triage.deleted}</b><span>deleted files</span></button><button onClick={() => { setDeletedOnly(false); setTypeFilter("ARCHIVE_FOUND"); }}><b>{triage.archives}</b><span>archives</span></button><button onClick={() => { setDeletedOnly(false); setTypeFilter("EXECUTABLE_FOUND"); }}><b>{triage.executables}</b><span>scripts / executables</span></button><button onClick={() => { setDeletedOnly(false); setTypeFilter("DOCUMENT_FOUND"); }}><b>{triage.documents}</b><span>documents</span></button></div><div className="triage-controls"><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search paths, names, or metadata" /><select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value as "ALL" | EvidenceEvent["event_type"])}><option value="ALL">All event types</option>{Array.from(new Set(events.map((event) => event.event_type))).map((type) => <option key={type} value={type}>{eventLabels[type]}</option>)}</select><label><input type="checkbox" checked={deletedOnly} onChange={(event) => setDeletedOnly(event.target.checked)} /> Deleted only</label><strong>{visibleEvents.length} of {events.length} shown</strong></div></section>}

    {artifactProfile && <>
      <section className="artifact-profile" aria-label="Local artifact profile"><div><p className="panel-label">LOCAL ARTIFACT PROFILE</p><h2>{artifactProfile.filename}</h2><p>{artifactProfile.kind} · {(artifactProfile.size_bytes / 1024).toFixed(1)} KB</p></div><div><span>SHA-256</span><code>{artifactProfile.sha256}</code></div><ul>{artifactProfile.signals.slice(0, 3).map((signal) => <li key={signal}>{signal}</li>)}</ul></section>
      <section className="artifact-findings" aria-label="Artifact findings"><div><p className="panel-label">POSSIBLE TAMPER SIGNALS</p><strong>{artifactProfile.tamper_signals.length ? "Review recommended" : "No structural signals found"}</strong><p>{artifactProfile.tamper_signals[0] ?? "This does not prove the artifact is original; it means this quick local profile found no structural warning."}</p></div>{artifactProfile.strings.length > 0 && <div><p className="panel-label">CTF / EXTRACTED STRINGS</p><code>{artifactProfile.strings.slice(0, 3).join(" · ")}</code></div>}<div><p className="panel-label">CHAIN OF CUSTODY</p><code>{artifactProfile.parser_version} · profiled locally {new Date(artifactProfile.profiled_at).toLocaleString()}</code>{auditEntries.length > 0 && <small>{auditEntries.length} local audit action{auditEntries.length === 1 ? "" : "s"} recorded</small>}</div></section>
    </>}
    {artifactProfile?.kind === "E01 forensic image" && artifactProfile.case.events.length <= 1 && <section className="extraction-notice"><p className="panel-label">E01 EXTRACTION STATUS</p><h2>This is a verified image, not an extracted timeline yet.</h2><p>Windows has validated the E01 container and calculated its hash. The actual file and timestamp timeline will appear only after running the Linux filesystem extractor with <code>backend/requirements-linux.txt</code>.</p></section>}

    {!reviewStarted && <section className="getting-started" aria-label="How to use ForenSight">
      <div className={!evidenceUploaded ? "current-step" : ""}><b>1</b><span><strong>Upload your evidence</strong><small>Add a JSON or CSV timeline to begin.</small></span></div>
      <div className={evidenceUploaded ? "current-step" : ""}><b>2</b><span><strong>Start reviewing</strong><small>See the evidence in the order it happened.</small></span></div>
      <div><b>3</b><span><strong>Hear the summary</strong><small>Listen after you have reviewed the case.</small></span></div>
    </section>}

    {reviewStarted && <div className="review-content"><nav className="modes" aria-label="Investigation modes">
      <button className={mode === "investigate" ? "active" : ""} onClick={() => chooseMode("investigate")} disabled={analyzing}>{analyzing && mode === "investigate" ? "Reviewing…" : "Review evidence"}</button>
      <button className={mode === "challenge" ? "active challenge" : ""} onClick={() => chooseMode("challenge")} disabled={analyzing}>{analyzing && mode === "challenge" ? "Checking…" : "Check assumptions"}</button>
      <button onClick={replayEvidence} disabled={analyzing || replaying}>{replaying ? "Replaying…" : "Watch replay"}</button>
    </nav>

    <p className="notice">{message}</p>
    <section className="dashboard">
      <aside className="summary panel"><p className="panel-label">OUR BEST EXPLANATION</p><h2>{caseFile.title}</h2><div className="confidence"><span>{confidence}<b>%</b></span><p>{hypothesis}</p></div><hr />
        <p className="panel-label">OTHER POSSIBILITIES</p>
        <button className={`hypothesis ${activeHypothesis === "H1" ? "selected" : ""}`} onClick={() => { setActiveHypothesis("H1"); setMessage("Viewing H1: the evidence-backed removable-media transfer theory."); }}>H1 <span>{confidence}%</span><small>{hypothesis}</small></button>
        {alternative && <button className={`hypothesis ${activeHypothesis === "H2" ? "selected" : ""}`} onClick={() => { setActiveHypothesis("H2"); setSelected(events.at(-1)!); setMessage("Viewing the evidence-backed alternative explanation."); }}>H2 <span>Alternative</span><small>{alternative}</small></button>}
      </aside>

      <section className="timeline panel"><div className="panel-heading"><div><p className="panel-label">WHAT HAPPENED, IN ORDER</p><h2>Evidence timeline</h2></div><span>{events.length} events</span></div><p className="timeline-hint">All recovered events are shown below — scroll this panel to browse them.</p>
        <ol>{visibleEvents.map((event) => <li key={event.event_id}><label className="event-select"><input type="checkbox" checked={selectedEvidenceIds.has(event.event_id)} onChange={() => setSelectedEvidenceIds((current) => { const next = new Set(current); next.has(event.event_id) ? next.delete(event.event_id) : next.add(event.event_id); return next; })} /><span className="sr-only">Select {event.event_id}</span></label><button className={selected.event_id === event.event_id ? "event active" : "event"} onClick={() => setSelected(event)}><time>{time(event)}</time><i className={event.event_type.toLowerCase()} /> <span><strong>{eventLabels[event.event_type]}</strong><small>{event.object ?? event.device ?? event.source}</small></span><code>{event.event_id}</code></button></li>)}{visibleEvents.length === 0 && <li className="empty-events">No events match these filters.</li>}</ol>
      </section>

      <aside className="why panel"><p className="panel-label">ABOUT THIS EVENT</p><h2>{eventLabels[selected.event_type]}</h2><p className="event-detail">{selected.detail ?? "No further detail supplied."}</p><dl><div><dt>Evidence reference</dt><dd>{selected.event_id}</dd></div><div><dt>Where it came from</dt><dd>{selected.source}</dd></div><div><dt>When it happened</dt><dd>{new Date(selected.timestamp).toLocaleString()}</dd></div></dl>{selected.object && <section className="file-inspector"><p className="panel-label">SELECTED FILE INSPECTION</p><code>{selected.object}</code><dl><div><dt>Classification</dt><dd>{eventLabels[selected.event_type]}</dd></div><div><dt>Deletion state</dt><dd>{selected.event_type === "FILE_DELETED" ? "Recovered deleted entry" : "No deletion state recovered"}</dd></div><div><dt>Filesystem size</dt><dd>{detailValue(selected.detail, /size ([^;]+) bytes/)} bytes</dd></div><div><dt>Inode</dt><dd>{detailValue(selected.detail, /inode (\d+)/)}</dd></div></dl><button onClick={copySelectedPath}>Copy evidence path</button>{artifactFile && <button onClick={extractSelectedFile}>Extract safe copy</button>}<small>Metadata only. The original image remains read-only.</small></section>}
        {artifactProfile && artifactFile && <section className="ctf-utility" aria-label="Offline CTF hunt"><div className="ctf-utility-heading"><p className="panel-label">OFFLINE CTF HUNT</p><span>local evidence only</span></div><label>Flag pattern<input value={flagConvention} onChange={(event) => setFlagConvention(event.target.value)} placeholder="picoCTF{...} or a regex" /></label><button className="ctf-paths" onClick={showLikelyCtfFiles}>Find likely flag files</button>{flagCandidates.length ? <p className="ctf-result">{flagCandidates.map((candidate) => <code key={candidate}>{candidate}</code>)}</p> : <small>Initial triage found no match. Inspect a recovered copy for a full local scan.</small>}</section>}
        {recoveredInspection && <section className="recovered-inspection"><p className="panel-label">RECOVERED COPY INSPECTION</p><strong>{recoveredInspection.name}</strong><small>{recoveredInspection.kind} · {recoveredInspection.size.toLocaleString()} bytes</small><code>SHA-256 {recoveredInspection.sha256}</code><p>{recoveredInspection.candidates.length ? recoveredInspection.candidates.map((candidate) => <code key={candidate}>{candidate}</code>) : "No matching flag candidate was found in the local inspection window. Try another convention or inspect the downloaded copy."}</p></section>}
        <div className="evidence-chain"><p className="panel-label">RELATED EVENTS</p>{directEvidence.map((event) => <button key={event.event_id} onClick={() => setSelected(event)}>↳ {event.event_id} — {eventLabels[event.event_type]}</button>)}</div>
        {analysis?.evidence_basis?.length ? <section className="claim-basis"><p className="panel-label">WHY THE MODEL COULD CITE THIS</p>{analysis.evidence_basis.slice(0, 5).map((fact) => <button key={fact.event_id} onClick={() => { const event = events.find((item) => item.event_id === fact.event_id); if (event) setSelected(event); }}><code>{fact.event_id}</code><span>{fact.source}</span><small>{fact.object ?? fact.detail ?? "No object recovered"}</small></button>)}</section> : null}
      </aside>
    </section>

    <section className="bottom-grid">
      <section className="panel graph"><div className="panel-heading"><div><p className="panel-label">SELECTED EVIDENCE PATH</p><h2>What this record establishes</h2></div><span>Artifact-backed</span></div><div className="graph-flow"><span>{selected.source}</span><b>recorded</b><span>{selected.object ?? "filesystem entry"}</span><b>as</b><span className="device">{eventLabels[selected.event_type]}</span></div><p>Only relationships present in the selected evidence are shown.</p></section>
      <section className="panel gaps"><p className="panel-label">{mode === "challenge" ? "WHAT ELSE COULD BE TRUE?" : "WHAT WE STILL NEED TO KNOW"}</p>{mode === "challenge" ? <><h2>{analysis?.alternative_explanations[0] ? "Another explanation is possible" : "Check the conclusion"}</h2><p>{analysis?.alternative_explanations[0] ?? "USB metadata is incomplete, so the file could have been present before this session."}</p><code>{analysis?.contradicting_evidence[0] ?? "E227"}</code></> : <><h2>One important gap remains</h2><p>{analysis?.missing_evidence[0] ?? "We do not have a process record showing exactly which app copied the file."}</p><code>Missing evidence</code></>}</section>
    </section>
    </div>}
    <footer><span>Built by <a href="https://github.com/Sabrinbrin" target="_blank" rel="noreferrer"><b>@Sabrinbrin</b></a> with Codex</span></footer>
  </main>;
}
