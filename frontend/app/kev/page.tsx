"use client";

import { useQuery } from "@tanstack/react-query";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { AppShell } from "@/components/workspace/app-shell";
import { SeverityBadge } from "@/components/workspace/badge-helpers";
import { PageHeader } from "@/components/workspace/page-header";
import { tracepointApi } from "@/lib/api";
import { demoKevSummary } from "@/lib/demo-data";

export default function KevPage() {
  const kevQuery = useQuery({
    queryKey: ["kev-summary"],
    queryFn: () => tracepointApi.kevSummary(),
  });
  const kev = kevQuery.data ?? demoKevSummary;

  return (
    <AppShell>
      <div className="flex flex-col gap-6">
        <PageHeader
          title="CISA KEV priorities"
          description="Track exploited vulnerabilities by operational deadline, ransomware use, and remediation urgency."
          eyebrow="Threat-informed remediation"
        />

        <section className="grid gap-4 md:grid-cols-4">
          <Metric label="Total KEV" value={kev.total_kev_findings} />
          <Metric label="Overdue" value={kev.overdue} />
          <Metric label="Due soon" value={kev.due_soon} />
          <Metric label="Ransomware linked" value={kev.known_ransomware_use} />
        </section>

        <Card>
          <CardHeader>
            <CardTitle>Urgency queue</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>CVE</TableHead>
                  <TableHead>Product</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Due date</TableHead>
                  <TableHead>Priority reason</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {kev.top_due_items.map((item) => (
                  <TableRow key={item.finding_id}>
                    <TableCell className="font-medium">{item.cve ?? item.title}</TableCell>
                    <TableCell>
                      {item.vendor_project ?? "Unknown"} · {item.product ?? "Unknown"}
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={item.severity} />
                    </TableCell>
                    <TableCell>{item.kev_due_date ?? "No date"}</TableCell>
                    <TableCell className="max-w-md text-sm text-muted-foreground">
                      {item.priority_reason}
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

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm text-muted-foreground">{label}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-semibold">{value}</div>
      </CardContent>
    </Card>
  );
}
