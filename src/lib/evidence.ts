export type EventType = "USB_INSERT" | "FILE_ACCESS" | "FILE_COPY" | "USB_REMOVE" | "PROCESS_START" | "BROWSER_ACTIVITY" | "OTHER";

export type EvidenceEvent = {
  event_id: string;
  timestamp: string;
  event_type: EventType;
  actor?: string;
  object?: string;
  device?: string;
  source: string;
  detail?: string;
};

export type EvidenceCase = {
  case_id: string;
  title: string;
  description: string;
  events: EvidenceEvent[];
};

const eventTypes: EventType[] = ["USB_INSERT", "FILE_ACCESS", "FILE_COPY", "USB_REMOVE", "PROCESS_START", "BROWSER_ACTIVITY", "OTHER"];

export function validateCase(value: unknown): EvidenceCase {
  if (!value || typeof value !== "object") throw new Error("The upload must be a JSON object.");
  const candidate = value as Partial<EvidenceCase>;
  if (!candidate.case_id || !candidate.title || !Array.isArray(candidate.events)) {
    throw new Error("Expected case_id, title, and an events array.");
  }
  if (candidate.events.length === 0) throw new Error("The evidence bundle has no events.");
  const ids = new Set<string>();
  const events = candidate.events.map((event, index) => {
    if (!event || typeof event !== "object" || !event.event_id || !event.timestamp || !event.event_type || !event.source) {
      throw new Error(`Event ${index + 1} is missing event_id, timestamp, event_type, or source.`);
    }
    if (!eventTypes.includes(event.event_type)) throw new Error(`Event ${event.event_id} has an unsupported event_type.`);
    if (Number.isNaN(Date.parse(event.timestamp))) throw new Error(`Event ${event.event_id} has an invalid timestamp.`);
    if (ids.has(event.event_id)) throw new Error(`Duplicate evidence ID: ${event.event_id}.`);
    ids.add(event.event_id);
    return event as EvidenceEvent;
  });
  return { case_id: candidate.case_id, title: candidate.title, description: candidate.description ?? "User-uploaded evidence bundle.", events };
}

export function parseCsv(text: string): EvidenceCase {
  const [header, ...rows] = text.trim().split(/\r?\n/);
  if (!header || rows.length === 0) throw new Error("The CSV needs a header and at least one event.");
  const columns = header.split(",").map((column) => column.trim());
  const required = ["event_id", "timestamp", "event_type", "source"];
  if (!required.every((column) => columns.includes(column))) throw new Error(`CSV must include: ${required.join(", ")}.`);
  const events = rows.filter(Boolean).map((row) => {
    const values = row.split(",");
    return Object.fromEntries(columns.map((column, index) => [column, values[index]?.trim()])) as EvidenceEvent;
  });
  return validateCase({ case_id: `upload-${crypto.randomUUID()}`, title: "Uploaded evidence", events });
}
