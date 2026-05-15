"use client";

import { useQuery } from "@tanstack/react-query";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { AppShell } from "@/components/workspace/app-shell";
import { SeverityBadge, StatusBadge } from "@/components/workspace/badge-helpers";
import { PageHeader } from "@/components/workspace/page-header";
import { tracepointApi } from "@/lib/api";
import { demoFindingsResponse } from "@/lib/demo-data";

export default function RiskSlaPage() {
  const findingsQuery = useQuery({
    queryKey: ["risk-sla-findings"],
    queryFn: () => tracepointApi.findings({ limit: 100 }),
  });
  const findings = findingsQuery.data ?? demoFindingsResponse;

  return (
    <AppShell>
      <div className="flex flex-col gap-6">
        <PageHeader
          title="Risk and SLA"
          description="Spot operational exposure, overdue remediation, escalation triggers, and high-confidence findings."
          eyebrow="Remediation control"
        />
        <Card>
          <CardHeader>
            <CardTitle>Prioritized remediation queue</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Finding</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Risk proxy</TableHead>
                  <TableHead>SLA posture</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.items.map((finding) => (
                  <TableRow key={finding.id}>
                    <TableCell className="font-medium">{finding.title}</TableCell>
                    <TableCell>
                      <SeverityBadge severity={finding.severity} />
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={finding.status} />
                    </TableCell>
                    <TableCell>{riskScore(finding.severity, finding.confidence)}</TableCell>
                    <TableCell>
                      {finding.severity === "critical" || finding.severity === "high"
                        ? "Escalate within 24h"
                        : "Track in weekly queue"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}

function riskScore(severity: string, confidence: number) {
  const base = severity === "critical" ? 90 : severity === "high" ? 78 : 54;
  return Math.min(100, Math.round(base + confidence * 10));
}
