"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { AppShell } from "@/components/workspace/app-shell";
import { SeverityBadge, StatusBadge } from "@/components/workspace/badge-helpers";
import { PageHeader } from "@/components/workspace/page-header";
import { tracepointApi } from "@/lib/api";
import { demoFindingsResponse } from "@/lib/demo-data";

const severities = ["all", "critical", "high", "medium", "low", "unknown"];
const statuses = ["all", "new", "triaged", "needs_human_review", "in_remediation", "closed"];

export default function FindingsPage() {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");

  const findingsQuery = useQuery({
    queryKey: ["findings", severity, status],
    queryFn: () =>
      tracepointApi.findings({
        limit: 100,
        severity: severity === "all" ? undefined : severity,
        status: status === "all" ? undefined : status,
      }),
  });

  const data = findingsQuery.data ?? demoFindingsResponse;
  const filtered = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return data.items;

    return data.items.filter((finding) =>
      [
        finding.title,
        finding.description,
        finding.category,
        finding.affected_asset,
        finding.source,
        finding.reporter,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(normalized),
    );
  }, [data.items, query]);

  return (
    <AppShell>
      <div className="flex flex-col gap-6">
        <PageHeader
          title="Findings"
          description="Search, filter, and prioritize all incoming vulnerability and security signals."
          eyebrow="Operational queue"
        />

        <Card>
          <CardHeader>
            <CardTitle>Queue controls</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-[1fr_180px_220px]">
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search title, asset, source, category, reporter"
            />
            <Select value={severity} onValueChange={setSeverity}>
              <SelectTrigger className="w-full">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  {severities.map((item) => (
                    <SelectItem key={item} value={item}>
                      {item}
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
            <Select value={status} onValueChange={setStatus}>
              <SelectTrigger className="w-full">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  {statuses.map((item) => (
                    <SelectItem key={item} value={item}>
                      {item.replaceAll("_", " ")}
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>{filtered.length} findings</CardTitle>
            {findingsQuery.isError ? <Badge variant="secondary">demo fallback</Badge> : null}
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Finding</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Asset</TableHead>
                  <TableHead>Confidence</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((finding) => (
                  <TableRow key={finding.id}>
                    <TableCell>
                      <Link className="font-medium hover:underline" href={`/findings/${finding.id}`}>
                        {finding.title}
                      </Link>
                      <div className="text-xs text-muted-foreground">
                        {finding.category ?? "uncategorized"}
                      </div>
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={finding.severity} />
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={finding.status} />
                    </TableCell>
                    <TableCell>{finding.source}</TableCell>
                    <TableCell className="max-w-xs truncate">
                      {finding.affected_asset ?? "No asset"}
                    </TableCell>
                    <TableCell>{Math.round(finding.confidence * 100)}%</TableCell>
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
