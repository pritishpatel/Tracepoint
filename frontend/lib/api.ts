export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";

export type Severity = "critical" | "high" | "medium" | "low" | "unknown" | string;

export type DashboardBucket = {
  name: string;
  count: number;
};

export type Finding = {
  id: string;
  title: string;
  description: string;
  source: string;
  severity: Severity;
  status: string;
  category: string | null;
  affected_asset: string | null;
  reporter: string | null;
  confidence: number;
  created_at: string;
  updated_at: string;
};

export type FindingListResponse = {
  items: Finding[];
  total: number;
  limit: number;
  offset: number;
};

export type RecentFinding = Pick<
  Finding,
  "id" | "title" | "severity" | "status" | "source" | "category" | "affected_asset" | "created_at"
>;

export type DashboardSummary = {
  total_findings: number;
  open_findings: number;
  triage_results: number;
  high_severity_findings: number;
  by_severity: DashboardBucket[];
  by_status: DashboardBucket[];
  by_source: DashboardBucket[];
  by_category: DashboardBucket[];
  recent_findings: RecentFinding[];
};

export type KevSummaryItem = {
  finding_id: string;
  title: string;
  cve: string | null;
  vendor_project: string | null;
  product: string | null;
  severity: string;
  category: string | null;
  kev_due_date: string | null;
  days_until_due: number | null;
  is_overdue: boolean;
  known_ransomware_use: boolean;
  priority_reason: string;
};

export type KevSummary = {
  total_kev_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  overdue: number;
  due_soon: number;
  known_ransomware_use: number;
  top_due_items: KevSummaryItem[];
};

export type ActivityItem = {
  type: string;
  entity_id: string;
  title: string;
  severity: string | null;
  category: string | null;
  source: string | null;
  routing_team: string | null;
  created_at: string;
};

export type ActivityTimeline = {
  items: ActivityItem[];
  total: number;
  limit: number;
};

export type RiskFactor = {
  name: string;
  value: string;
  weight: number;
  contribution: number;
};

export type FindingRisk = {
  finding_id: string;
  title: string;
  severity: string;
  category: string | null;
  affected_asset: string | null;
  confidence: number;
  risk_score: number;
  risk_level: string;
  priority: string;
  factors: RiskFactor[];
  recommendation: string;
};

export type FindingSla = {
  finding_id: string;
  title: string;
  priority: string;
  risk_level: string;
  risk_score: number;
  sla_hours: number;
  created_at: string;
  due_at: string;
  is_overdue: boolean;
  escalation_required: boolean;
  recommendation: string;
};

export type ImportPayload = {
  source: string;
  persist: boolean;
  check_duplicates: boolean;
  items: Array<{
    title: string;
    description: string;
    source?: string | null;
    severity?: string | null;
    category?: string | null;
    affected_asset?: string | null;
    reporter?: string | null;
    confidence?: number | null;
  }>;
};

export type ImportSummary = {
  received: number;
  created: number;
  duplicates: number;
  failed: number;
  results: Array<{
    index: number;
    title: string;
    finding_id: string | null;
    triage_result_id: string | null;
    persisted: boolean;
    duplicate_decision: string;
    duplicate_score: number;
    category: string;
    severity: string;
  }>;
  failures: Array<{ index: number; title: string | null; reason: string }>;
};

export type WorkspaceData = {
  dashboard: DashboardSummary;
  kevSummary: KevSummary;
  findings: FindingListResponse;
  activity: ActivityTimeline;
};

class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export class TracepointApiClient {
  constructor(private readonly baseUrl: string = API_BASE_URL) {}

  async workspace(): Promise<WorkspaceData> {
    const [dashboard, kevSummary, findings, activity] = await Promise.all([
      this.dashboardSummary(),
      this.kevSummary(),
      this.findings({ limit: 100 }),
      this.activity(),
    ]);

    return { dashboard, kevSummary, findings, activity };
  }

  async dashboardSummary(): Promise<DashboardSummary> {
    return this.fetchJson<DashboardSummary>("/dashboard/summary");
  }

  async kevSummary(): Promise<KevSummary> {
    return this.fetchJson<KevSummary>("/findings/kev-summary");
  }

  async findings(params: Record<string, string | number | boolean | undefined> = {}) {
    const query = new URLSearchParams();

    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== "") {
        query.set(key, String(value));
      }
    }

    const suffix = query.size > 0 ? `?${query.toString()}` : "";
    return this.fetchJson<FindingListResponse>(`/findings${suffix}`);
  }

  async finding(findingId: string): Promise<Finding> {
    return this.fetchJson<Finding>(`/findings/${findingId}`);
  }

  async risk(findingId: string): Promise<FindingRisk> {
    return this.fetchJson<FindingRisk>(`/risk/findings/${findingId}`);
  }

  async sla(findingId: string): Promise<FindingSla> {
    return this.fetchJson<FindingSla>(`/risk/findings/${findingId}/sla`);
  }

  async activity(limit = 20): Promise<ActivityTimeline> {
    return this.fetchJson<ActivityTimeline>(`/activity?limit=${limit}`);
  }

  async importFindings(payload: ImportPayload): Promise<ImportSummary> {
    return this.fetchJson<ImportSummary>("/import/findings", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  private async fetchJson<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        ...init.headers,
      },
      ...init,
    });

    if (!response.ok) {
      throw new ApiError(
        `Tracepoint API request failed: ${response.status} ${response.statusText}`,
        response.status,
      );
    }

    return response.json() as Promise<T>;
  }
}

export const tracepointApi = new TracepointApiClient();
