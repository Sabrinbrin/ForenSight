import type { EvidenceCase } from "../lib/evidence";

// A deliberately small, normalized demo bundle inspired by the NIST CFReDS
// Data Leakage Case. It is not a copy of a raw forensic image or NIST answer key.
export const demoCase: EvidenceCase = {
  case_id: "demo-usb-leakage",
  title: "Demo case: removable-media review",
  description: "A normalized, NIST-inspired evidence bundle for demonstrating traceable reasoning.",
  events: [
    { event_id: "E177", timestamp: "2015-03-24T14:07:02+09:00", event_type: "USB_INSERT", actor: "Iaman Informant", device: "RM#2 USB", source: "Windows Registry", detail: "Removable device attachment recorded." },
    { event_id: "E191", timestamp: "2015-03-24T14:08:11+09:00", event_type: "FILE_ACCESS", actor: "Iaman Informant", object: "confidential_design.docx", device: "Workstation", source: "LNK / RecentDocs", detail: "Sensitive document opened during active session." },
    { event_id: "E183", timestamp: "2015-03-24T14:08:31+09:00", event_type: "FILE_COPY", actor: "Iaman Informant", object: "confidential_design.docx", device: "RM#2 USB", source: "NTFS transaction log", detail: "File-system activity associates the document with removable media." },
    { event_id: "E204", timestamp: "2015-03-24T14:10:04+09:00", event_type: "USB_REMOVE", actor: "Iaman Informant", device: "RM#2 USB", source: "Windows event log", detail: "Removable device removal recorded." },
    { event_id: "E227", timestamp: "2015-03-24T14:11:21+09:00", event_type: "OTHER", object: "RM#2 USB", source: "USB filesystem review", detail: "Prior-session metadata is incomplete; earlier file presence cannot be ruled out." }
  ]
};
