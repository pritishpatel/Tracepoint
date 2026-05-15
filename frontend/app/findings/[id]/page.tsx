"use client";

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AppShell } from "@/components/workspace/app-shell";
import { SeverityBadge, StatusBadge } from "@/components/workspace/badge-helpers";
import { PageHeader } from "@/components/workspace/page-header";
import { tracepointApi } from "@/lib/api";
import { demoFindings } from "@/lib/demo-data";

export default function FindingDetailPage() {
  const params = useParams<{ id: string }>();
  const fallback = demoFindings.find((finding) => finding.id === params.id) ?? demoFindings[0];

  const findingQuery = useQuery({
    queryKey: ["finding", params.id],
    queryFn: () => tracepointApi.finding(params.id),
  });
  const riskQuery = useQuery({
    queryKey: ["risk", params.id],
    queryFn: () => tracepointApi.risk(params.id),
  });
  const slaQuery = useQuery({
    queryKey: ["sla", params.id],
    queryFn: () => tracepointApi.sla(params.id),
  });

  const finding = findingQuery.data ?? fallback;

  return (
    <AppShell>
      <div className="flex flex-col gap-6">
        <PageHeader
          title={finding.title}
          description={finding.description.split("\n")[0]}
          eyebrow="Finding detail"
          actions={
            <>
              <SeverityBadge severity={finding.severity} />
              <StatusBadge status={finding.status} />
            </>
          }
        />

        <section className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
          <Card>
            <CardHeader>
              <CardTitle>Investigation brief</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4 md:grid-cols-2">
              <Detail label="Source" value={finding.source} />
              <Detail label="Category" value={finding.category ?? "unknown"} />
              <Detail label="Affected asset" value={finding.affected_asset ?? "No asset"} />
              <Detail label="Reporter" value={finding.reporter ?? "system"} />
              <Detail label="Confidence" value={`${Math.round(finding.confidence * 100)}%`} />
              <Detail label="Created" value={new Date(finding.created_at).toLocaleString()} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Risk & SLA</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              <div className="rounded-lg border p-3">
                <div className="text-sm text-muted-foreground">Risk score</div>
                <div className="text-3xl font-semibold">
                  {riskQuery.data?.risk_score ?? (finding.severity === "critical" ? 96 : 78)}
                </div>
                <Badge variant="secondary">
                  {riskQuery.data?.risk_level ?? "elevated"}
                </Badge>
              </div>
              <div className="rounded-lg border p-3">
                <div className="text-sm text-muted-foreground">SLA due</div>
                <div className="text-lg font-medium">
                  {slaQuery.data?.due_at
                    ? new Date(slaQuery.data.due_at).toLocaleString()
                    : "48 hours from triage"}
                </div>
                <p className="mt-1 text-xs text-muted-foreground">
                  {slaQuery.data?.recommendation ??
                    "Escalate if remediation owner is not assigned today."}
                </p>
              </div>
            </CardContent>
          </Card>
        </section>

        <Card>
          <CardHeader>
            <CardTitle>Full report</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="whitespace-pre-wrap rounded-lg bg-muted p-4 text-sm">
              {finding.description}
            </pre>
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border bg-muted/20 p-3">
      <div className="text-xs font-medium uppercase text-muted-foreground">
        {label}
      </div>
      <div className="mt-1 text-sm font-medium">{value}</div>
    </div>
  );
}
