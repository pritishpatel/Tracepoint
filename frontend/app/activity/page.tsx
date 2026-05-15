"use client";

import { useQuery } from "@tanstack/react-query";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AppShell } from "@/components/workspace/app-shell";
import { PageHeader } from "@/components/workspace/page-header";
import { tracepointApi } from "@/lib/api";
import { demoActivity } from "@/lib/demo-data";

export default function ActivityPage() {
  const activityQuery = useQuery({
    queryKey: ["activity"],
    queryFn: () => tracepointApi.activity(50),
  });
  const activity = activityQuery.data ?? demoActivity;

  return (
    <AppShell>
      <div className="flex flex-col gap-6">
        <PageHeader
          title="Activity"
          description="Analyst actions, triage decisions, imports, workflow changes, and evidence generation."
          eyebrow="Audit timeline"
        />
        <Card>
          <CardHeader>
            <CardTitle>{activity.total} recent events</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {activity.items.map((item) => (
              <div
                key={`${item.type}-${item.entity_id}`}
                className="grid gap-3 rounded-lg border p-4 md:grid-cols-[180px_1fr_220px]"
              >
                <Badge className="w-fit" variant="secondary">
                  {item.type.replaceAll("_", " ")}
                </Badge>
                <div>
                  <div className="font-medium">{item.title}</div>
                  <div className="text-sm text-muted-foreground">
                    {item.category ?? item.routing_team ?? item.source ?? "Tracepoint"}
                  </div>
                </div>
                <div className="text-sm text-muted-foreground">
                  {new Date(item.created_at).toLocaleString()}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
