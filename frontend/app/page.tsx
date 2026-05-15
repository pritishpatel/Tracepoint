"use client";

import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  Clock,
  Database,
  Flame,
  ShieldAlert,
  Workflow,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { AppShell } from "@/components/workspace/app-shell";
import { SeverityBadge, StatusBadge } from "@/components/workspace/badge-helpers";
import { PageHeader } from "@/components/workspace/page-header";
import { ErrorPanel, LoadingPanel } from "@/components/workspace/state-panels";
import { tracepointApi } from "@/lib/api";
import { demoWorkspace } from "@/lib/demo-data";

export default function OverviewPage() {
  const workspaceQuery = useQuery({
    queryKey: ["workspace"],
    queryFn: () => tracepointApi.workspace(),
  });

  const workspace = workspaceQuery.data ?? demoWorkspace;
  const { dashboard, kevSummary, findings, activity } = workspace;
  const apiFallback = workspaceQuery.isError;

  const severityData = dashboard.by_severity.map((item) => ({
    name: item.name,
    count: item.count,
  }));

  const reviewQueue = findings.items.filter((finding) =>
    ["new", "needs_human_review"].includes(finding.status),
  );

  return (
    <AppShell>
      <div className="flex flex-col gap-6">
        <PageHeader
          eyebrow="Production operations"
          title="SecOps command center"
          description="Prioritize exploited vulnerabilities, high-risk findings, SLA exposure, and analyst workflow from one operational surface."
          actions={
            <>
              <Button variant="outline">Export report</Button>
              <Button>Import findings</Button>
            </>
          }
        />

        {workspaceQuery.isLoading ? <LoadingPanel title="Loading workspace data" /> : null}
        {apiFallback ? <ErrorPanel message={(workspaceQuery.error as Error).message} /> : null}

        <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
          <MetricCard
            title="Total Findings"
            value={dashboard.total_findings}
            detail="Across CISA KEV, bounty, cloud, identity, and scanners"
            icon={<Database data-icon="inline-start" />}
          />
          <MetricCard
            title="High / Critical"
            value={dashboard.high_severity_findings}
            detail="Immediate analyst attention"
            icon={<ShieldAlert data-icon="inline-start" />}
          />
          <MetricCard
            title="KEV Overdue"
            value={kevSummary.overdue}
            detail="Past remediation target"
            icon={<Clock data-icon="inline-start" />}
          />
          <MetricCard
            title="Ransomware Linked"
            value={kevSummary.known_ransomware_use}
            detail="Known campaign use"
            icon={<Flame data-icon="inline-start" />}
          />
          <MetricCard
            title="Needs Review"
            value={reviewQueue.length}
            detail="Human-in-the-loop decisions"
            icon={<AlertTriangle data-icon="inline-start" />}
          />
        </section>

        <section className="grid gap-4 xl:grid-cols-[1.5fr_1fr]">
          <Card>
            <CardHeader>
              <CardTitle>Severity distribution</CardTitle>
            </CardHeader>
            <CardContent className="overflow-x-auto">
              <BarChart width={760} height={300} data={severityData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" radius={[8, 8, 0, 0]} />
              </BarChart>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Workflow bottlenecks</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              {dashboard.by_status.map((item) => (
                <div
                  key={item.name}
                  className="flex items-center justify-between rounded-lg border bg-muted/30 px-3 py-2"
                >
                  <div className="flex items-center gap-2">
                    <Workflow data-icon="inline-start" />
                    <span className="text-sm font-medium">
                      {item.name.replaceAll("_", " ")}
                    </span>
                  </div>
                  <Badge variant="secondary">{item.count}</Badge>
                </div>
              ))}
            </CardContent>
          </Card>
        </section>

        <section className="grid gap-4 xl:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>KEV urgency queue</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>CVE / finding</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Due</TableHead>
                    <TableHead>Reason</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {kevSummary.top_due_items.map((item) => (
                    <TableRow key={item.finding_id}>
                      <TableCell>
                        <div className="font-medium">{item.cve ?? item.title}</div>
                        <div className="text-xs text-muted-foreground">
                          {item.vendor_project ?? "Unknown vendor"} ·{" "}
                          {item.product ?? "Unknown product"}
                        </div>
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={item.severity} />
                      </TableCell>
                      <TableCell>{item.kev_due_date ?? "No date"}</TableCell>
                      <TableCell className="max-w-xs text-sm text-muted-foreground">
                        {item.priority_reason}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Needs review</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col gap-3">
                {reviewQueue.map((finding) => (
                  <div key={finding.id} className="rounded-lg border p-3">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="font-medium">{finding.title}</div>
                        <div className="mt-1 text-xs text-muted-foreground">
                          {finding.affected_asset ?? "No asset"} · {finding.source}
                        </div>
                      </div>
                      <StatusBadge status={finding.status} />
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </section>

        <Card>
          <CardHeader>
            <CardTitle>Recent activity</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3 md:grid-cols-3">
              {activity.items.slice(0, 6).map((item) => (
                <div key={`${item.type}-${item.entity_id}`} className="rounded-lg border p-3">
                  <Badge variant="secondary">{item.type.replaceAll("_", " ")}</Badge>
                  <p className="mt-2 text-sm font-medium">{item.title}</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {item.category ?? item.routing_team ?? "security operations"}
                  </p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}

function MetricCard({
  title,
  value,
  detail,
  icon,
}: {
  title: string;
  value: number;
  detail: string;
  icon: React.ReactNode;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-3 pb-2">
        <CardTitle className="text-sm text-muted-foreground">{title}</CardTitle>
        <div className="text-muted-foreground">{icon}</div>
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-semibold tracking-tight">{value}</div>
        <p className="mt-1 text-xs text-muted-foreground">{detail}</p>
      </CardContent>
    </Card>
  );
}
