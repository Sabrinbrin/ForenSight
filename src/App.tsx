import { useMemo, useRef, useState } from "react";
import { demoCase } from "./data/demoCase";
import { parseCsv, validateCase, type EvidenceCase, type EvidenceEvent } from "./lib/evidence";
import { profileArtifact, requestAnalysis, requestNarration, type AnalysisResult, type AnalysisMode, type ArtifactProfile } from "./lib/api";

const eventLabels: Record<EvidenceEvent["event_type"], string> = {
  USB_INSERT: "USB connected", FILE_ACCESS: "File accessed", FILE_COPY: "File copied", USB_REMOVE: "USB removed", PROCESS_START: "Process started", BROWSER_ACTIVITY: "Browser activity", OTHER: "Evidence note",
};

function time(event: EvidenceEvent) { return new Date(event.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }

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
  const [artifactProfile, setArtifactProfile] = useState<ArtifactProfile | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const events = useMemo(() => [...caseFile.events].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp)), [caseFile]);
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

  async function chooseMode(next: AnalysisMode) {
    if (!evidenceUploaded) {
      setMessage("Upload an evidence artifact before starting a review.");
      input.current?.click();
      return;
    }
    setReviewStarted(true); setMode(next); setAnalyzing(true);
    try {
      const result = await requestAnalysis(next, caseFile);
      if (result) {
        setAnalysis(result);
        setMessage(`${next === "challenge" ? "Challenge" : "Investigation"} analysis complete (${result.generated_by}). Every cited ID was validated.`);
      } else {
        setAnalysis(null);
        setMessage("Deterministic demo mode. Set VITE_ANALYSIS_API_URL to use the local analysis service.");
      }
    } catch (error) {
      setAnalysis(null);
      setMessage(error instanceof Error ? error.message : "Analysis request failed.");
    } finally { setAnalyzing(false); }
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
      setCaseFile(next); setSelected(next.events[0]); setMode("investigate"); setAnalysis(null); setReviewStarted(false); setEvidenceUploaded(true);
      setArtifactProfile(profile);
      setMessage(profile ? `${profile.kind} profiled locally. Press Start reviewing when you are ready.` : `${next.events.length} events loaded. Press Start reviewing when you are ready.`);
    } catch (error) { setMessage(error instanceof Error ? error.message : "Unable to parse this evidence bundle."); }
    finally { setUploading(false); if (input.current) input.current.value = ""; }
  }

  return <main>
    <header className="topbar">
      <a className="brand" href="#top"><span className="brand-mark">F</span> FORENSIGHT</a>
      <div className="case-chip"><span className="pulse" /> {evidenceUploaded ? caseFile.case_id : "NO EVIDENCE LOADED"}</div>
      <button className="upload" onClick={() => input.current?.click()} disabled={uploading}>{uploading ? "Uploading…" : evidenceUploaded ? "New evidence" : "Upload evidence"}</button>
      <input ref={input} type="file" accept="*/*" onChange={(event) => upload(event.target.files?.[0])} disabled={uploading} hidden />
    </header>

    <section className="hero" id="top">
      <div className="hero-copy"><p className="eyebrow">FORENSIGHT CASE REVIEW</p><h1>Understand your<br /><em>evidence clearly.</em></h1><p className="lede">Upload a timeline of device and file activity. ForenSight puts it in order, explains what it may mean, and shows what is still uncertain.</p><div className="hero-actions"><button className="primary-action" onClick={() => evidenceUploaded ? chooseMode("investigate") : input.current?.click()} disabled={analyzing || uploading}>{analyzing ? "Looking at evidence…" : evidenceUploaded ? "Start reviewing" : "Upload evidence"}</button>{evidenceUploaded && <button className="quiet-action" onClick={() => input.current?.click()} disabled={uploading}>Replace evidence</button>}{reviewStarted && <button className="quiet-action" onClick={playBrief} disabled={narrating}>{narrating ? "Preparing brief…" : "Hear the summary"}</button>}</div></div>
      <div className="hero-status">{evidenceUploaded ? <><span>READY TO REVIEW</span><strong>Your evidence is loaded</strong><p>{events.length} events are ready. Start reviewing to see the timeline and conclusions.</p><div><b>{events.length}</b><small>events ready</small></div></> : <><span>HOW IT WORKS</span><strong>Start with your evidence</strong><p>Upload an artifact or a JSON/CSV timeline to begin a private local review.</p><div><b>01</b><small>upload evidence</small></div></>}</div>
    </section>

    {uploading && <section className="upload-progress" aria-live="polite" aria-label="Evidence upload progress">
      <div><span>LOCAL EVIDENCE INTAKE</span><strong>{uploadProgress < 100 ? `Uploading ${uploadProgress}%` : "Profiling evidence locally…"}</strong></div>
      <div className="progress-track"><i style={{ width: `${Math.max(4, uploadProgress)}%` }} /></div>
      <p>Your artifact stays on this machine. It is not sent to OpenAI.</p>
    </section>}

    {evidenceUploaded && <section className="fact-strip" aria-label="Case facts">
      <div><span>EVENTS REVIEWED</span><strong>{events.length}</strong></div><div><span>ARTIFACT SOURCES</span><strong>{new Set(events.map((event) => event.source)).size}</strong></div><div><span>TIME WINDOW</span><strong>{time(events[0])}—{time(events.at(-1)!)}</strong></div><div><span>STATUS</span><strong className="status-text">Open review</strong></div>
    </section>}

    {artifactProfile && <><section className="artifact-profile" aria-label="Local artifact profile"><div><p className="panel-label">LOCAL ARTIFACT PROFILE</p><h2>{artifactProfile.filename}</h2><p>{artifactProfile.kind} · {(artifactProfile.size_bytes / 1024).toFixed(1)} KB</p></div><div><span>SHA-256</span><code>{artifactProfile.sha256}</code></div><ul>{artifactProfile.signals.slice(0, 3).map((signal) => <li key={signal}>{signal}</li>)}</ul></section><section className="artifact-findings" aria-label="Artifact findings"><div><p className="panel-label">POSSIBLE TAMPER SIGNALS</p><strong>{artifactProfile.tamper_signals.length ? "Review recommended" : "No structural signals found"}</strong><p>{artifactProfile.tamper_signals[0] ?? "This does not prove the artifact is original; it means this quick local profile found no structural warning."}</p></div>{artifactProfile.strings.length > 0 && <div><p className="panel-label">CTF / EXTRACTED STRINGS</p><code>{artifactProfile.strings.slice(0, 3).join(" · ")}</code></div>}<div><p className="panel-label">CHAIN OF CUSTODY</p><code>{artifactProfile.parser_version} · profiled locally {new Date(artifactProfile.profiled_at).toLocaleString()}</code></div></section></>}
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
        <ol>{events.map((event) => <li key={event.event_id}><button className={selected.event_id === event.event_id ? "event active" : "event"} onClick={() => setSelected(event)}><time>{time(event)}</time><i className={event.event_type.toLowerCase()} /> <span><strong>{eventLabels[event.event_type]}</strong><small>{event.object ?? event.device ?? event.source}</small></span><code>{event.event_id}</code></button></li>)}</ol>
      </section>

      <aside className="why panel"><p className="panel-label">ABOUT THIS EVENT</p><h2>{eventLabels[selected.event_type]}</h2><p className="event-detail">{selected.detail ?? "No further detail supplied."}</p><dl><div><dt>Evidence reference</dt><dd>{selected.event_id}</dd></div><div><dt>Where it came from</dt><dd>{selected.source}</dd></div><div><dt>When it happened</dt><dd>{new Date(selected.timestamp).toLocaleString()}</dd></div></dl>
        <div className="evidence-chain"><p className="panel-label">RELATED EVENTS</p>{directEvidence.map((event) => <button key={event.event_id} onClick={() => setSelected(event)}>↳ {event.event_id} — {eventLabels[event.event_type]}</button>)}</div>
      </aside>
    </section>

    <section className="bottom-grid">
      <section className="panel graph"><div className="panel-heading"><div><p className="panel-label">THE EVIDENCE STORY</p><h2>How these events connect</h2></div><span>Based on the timeline</span></div><div className="graph-flow"><span>{events.find((event) => event.actor)?.actor ?? "Known user"}</span><b>opened</b><span>{events.find((event) => event.object)?.object ?? "Document"}</span><b>then used</b><span className="device">{events.find((event) => event.device)?.device ?? "USB device"}</span></div><p>Each part links back to an event in the timeline above.</p></section>
      <section className="panel gaps"><p className="panel-label">{mode === "challenge" ? "WHAT ELSE COULD BE TRUE?" : "WHAT WE STILL NEED TO KNOW"}</p>{mode === "challenge" ? <><h2>{analysis?.alternative_explanations[0] ? "Another explanation is possible" : "Check the conclusion"}</h2><p>{analysis?.alternative_explanations[0] ?? "USB metadata is incomplete, so the file could have been present before this session."}</p><code>{analysis?.contradicting_evidence[0] ?? "E227"}</code></> : <><h2>One important gap remains</h2><p>{analysis?.missing_evidence[0] ?? "We do not have a process record showing exactly which app copied the file."}</p><code>Missing evidence</code></>}</section>
    </section>
    </div>}
    <footer><span>Built by <a href="https://github.com/Sabrinbrin" target="_blank" rel="noreferrer"><b>@Sabrinbrin</b></a> with Codex</span></footer>
  </main>;
}
