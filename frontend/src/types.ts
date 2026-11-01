export interface TraceStep { line: number; kind: "source" | "propagate" | "call" | "sink" | "param"; detail: string }
export interface Remediation { advice: string; secure_example: string; source_to_sink: string | null; reference: string }
export interface Finding {
  id?: number; status?: string; rule_id: string; cwe: string; title: string; file: string; line: number;
  snippet: string; function: string | null; tainted: boolean; trace: TraceStep[]; engine: string;
  confidence: number; severity: string; cvss: number; priority: number; triage_prob: number | null; remediation: Remediation;
}
export interface ScanResult { id: number; files?: number; loc?: number; seconds?: number; name?: string;
  severity_breakdown?: Record<string, number>; severity?: Record<string, number>; findings: Finding[] }
export interface ScanSummary { id: number; name: string; files: number; loc: number; seconds: number;
  severity: Record<string, number>; created_at: string }
