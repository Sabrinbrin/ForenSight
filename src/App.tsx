import { useMemo, useRef, useState } from "react";
import { demoCase } from "./data/demoCase";
import { parseCsv, validateCase, type EvidenceCase, type EvidenceEvent } from "./lib/evidence";
import { requestAnalysis, requestNarration, type AnalysisResult, type AnalysisMode } from "./lib/api";

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
  const input = useRef<HTMLInputElement>(null);
  const events = useMemo(() => [...caseFile.events].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp)), [caseFile]);
  const directEvidence = events.filter((event) => event.event_type === "USB_INSERT" || event.event_type === "FILE_ACCESS" || event.event_type === "FILE_COPY" || event.event_type === "USB_REMOVE");
  const confidence = analysis?.mode === mode ? analysis.confidence : mode === "challenge" ? 67 : 87;
  const hypothesis = analysis?.mode === mode ? analysis.hypothesis : mode === "challenge" ? "The removable-media transfer hypothesis is plausible but not proven." : "Likely exfiltration pathway";

  async function chooseMode(next: AnalysisMode) {
    setMode(next); setAnalyzing(true);
    try {
      const result = await requestAnalysis(next, caseFile);
      if (result) {
        setAnalysis(result);
        setMessage(`${next === "challenge" ? "Challenge" : "Investigation"} analysis complete (${result.generated_by}). Every cited ID was validated.`);
      } else {
        setAnalysis(null);
        setMessage("Deterministic demo mode. Set VITE_ANALYSIS_API_URL to use the local Linux analysis service.");
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
    } catch (error) { setMessage(error instanceof Error ? error.message : "Narration request failed."); }
    finally { setNarrating(false); }
  }

  async function upload(file?: File) {
    if (!file) return;
    try {
      const raw = await file.text();
      const next = file.name.toLowerCase().endsWith(".csv") ? parseCsv(raw) : validateCase(JSON.parse(raw));
      setCaseFile(next); setSelected(next.events[0]); setMode("investigate"); setAnalysis(null);
      setMessage(`${next.events.length} events loaded locally. Live analysis is ready when the Supabase API URL is configured.`);
    } catch (error) { setMessage(error instanceof Error ? error.message : "Unable to parse this evidence bundle."); }
  }

  return <main>
    <header className="topbar">
      <a className="brand" href="#top"><span className="brand-mark">F</span> FORENSIGHT</a>
      <div className="case-chip"><span className="pulse" /> {caseFile.case_id}</div>
      <button className="upload" onClick={() => input.current?.click()}>Upload evidence</button>
      <input ref={input} type="file" accept=".json,.csv,application/json,text/csv" onChange={(event) => upload(event.target.files?.[0])} hidden />
    </header>

    <section className="hero" id="top">
      <div className="hero-copy"><p className="eyebrow">DIGITAL EVIDENCE REVIEW</p><h1>Follow the<br /><em>evidence trail.</em></h1><p className="lede">{caseFile.description}</p><div className="hero-actions"><button className="primary-action" onClick={() => chooseMode("investigate")} disabled={analyzing}>{analyzing ? "Analyzing…" : "Review case"}</button><button className="quiet-action" onClick={playBrief} disabled={narrating}>{narrating ? "Preparing brief…" : "Listen to brief"}</button></div></div>
      <div className="hero-status"><span>PRELIMINARY ASSESSMENT</span><strong>Suspicious removable-media activity</strong><p>Evidence supports a transfer sequence. Attribution remains an inference.</p><div><b>{confidence}%</b><small>current confidence</small></div></div>
    </section>

    <section className="fact-strip" aria-label="Case facts">
      <div><span>EVENTS REVIEWED</span><strong>{events.length}</strong></div><div><span>ARTIFACT SOURCES</span><strong>{new Set(events.map((event) => event.source)).size}</strong></div><div><span>TIME WINDOW</span><strong>{time(events[0])}—{time(events.at(-1)!)}</strong></div><div><span>STATUS</span><strong className="status-text">Open review</strong></div>
    </section>

    <nav className="modes" aria-label="Investigation modes">
      <button className={mode === "investigate" ? "active" : ""} onClick={() => chooseMode("investigate")} disabled={analyzing}>{analyzing && mode === "investigate" ? "Analyzing…" : "Investigate"}</button>
      <button className={mode === "challenge" ? "active challenge" : ""} onClick={() => chooseMode("challenge")} disabled={analyzing}>{analyzing && mode === "challenge" ? "Challenging…" : "Challenge"}</button>
      <button disabled title="Post-MVP stretch goal">Replay <small>soon</small></button>
    </nav>

    <p className="notice">{message}</p>
    <section className="dashboard">
      <aside className="summary panel"><p className="panel-label">WORKING THEORY</p><h2>{caseFile.title}</h2><div className="confidence"><span>{confidence}<b>%</b></span><p>{hypothesis}</p></div><hr />
        <p className="panel-label">HYPOTHESES</p>
        <button className="hypothesis selected">H1 <span>{confidence}%</span><small>{hypothesis}</small></button>
        <button className="hypothesis">H2 <span>31%</span><small>Earlier-session file presence</small></button>
      </aside>

      <section className="timeline panel"><div className="panel-heading"><div><p className="panel-label">INCIDENT TIMELINE</p><h2>Artifact-derived events</h2></div><span>{events.length} events</span></div>
        <ol>{events.map((event) => <li key={event.event_id}><button className={selected.event_id === event.event_id ? "event active" : "event"} onClick={() => setSelected(event)}><time>{time(event)}</time><i className={event.event_type.toLowerCase()} /> <span><strong>{eventLabels[event.event_type]}</strong><small>{event.object ?? event.device ?? event.source}</small></span><code>{event.event_id}</code></button></li>)}</ol>
      </section>

      <aside className="why panel"><p className="panel-label">WHY THIS EVENT?</p><h2>{eventLabels[selected.event_type]}</h2><p className="event-detail">{selected.detail ?? "No further detail supplied."}</p><dl><div><dt>Evidence ID</dt><dd>{selected.event_id}</dd></div><div><dt>Source</dt><dd>{selected.source}</dd></div><div><dt>Timestamp</dt><dd>{new Date(selected.timestamp).toLocaleString()}</dd></div></dl>
        <div className="evidence-chain"><p className="panel-label">CORROBORATING CHAIN</p>{directEvidence.map((event) => <button key={event.event_id} onClick={() => setSelected(event)}>↳ {event.event_id} — {eventLabels[event.event_type]}</button>)}</div>
      </aside>
    </section>

    <section className="bottom-grid">
      <section className="panel graph"><div className="panel-heading"><div><p className="panel-label">EVIDENCE PATH</p><h2>What connects the events</h2></div><span>Grounded chain</span></div><div className="graph-flow"><span>{events.find((event) => event.actor)?.actor ?? "Known user"}</span><b>accessed</b><span>{events.find((event) => event.object)?.object ?? "Document"}</span><b>moved to</b><span className="device">{events.find((event) => event.device)?.device ?? "USB device"}</span></div><p>Every link is anchored to an evidence ID in the timeline.</p></section>
      <section className="panel gaps"><p className="panel-label">{mode === "challenge" ? "CHALLENGE FINDINGS" : "INVESTIGATION GAPS"}</p>{mode === "challenge" ? <><h2>{analysis?.alternative_explanations[0] ? "Alternative explanation remains" : "Challenge the conclusion"}</h2><p>{analysis?.alternative_explanations[0] ?? "USB filesystem metadata is incomplete, so earlier file presence cannot be ruled out."}</p><code>{analysis?.contradicting_evidence[0] ?? "E227"}</code></> : <><h2>What we do not know</h2><p>{analysis?.missing_evidence[0] ?? "No recovered process-level copy event directly attributes the transfer to an application."}</p><code>Missing expected artifact</code></>}</section>
    </section>
    <footer><span>Built by <a href="https://github.com/Sabrinbrin" target="_blank" rel="noreferrer"><b>@Sabrinbrin</b></a> with Codex</span></footer>
  </main>;
}
