import { CheckCircle2, CircleDot, GitBranch, ShieldAlert } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AppShell } from "@/components/workspace/app-shell";
import { PageHeader } from "@/components/workspace/page-header";

const stages = [
  { label: "New", detail: "Finding entered intake", icon: CircleDot },
  { label: "Triaged", detail: "Validity, severity, category assigned", icon: ShieldAlert },
  { label: "In remediation", detail: "Owner and SLA clock active", icon: GitBranch },
  { label: "Closed", detail: "Evidence generated and retained", icon: CheckCircle2 },
];

export default function WorkflowPage() {
  return (
    <AppShell>
      <div className="flex flex-col gap-6">
        <PageHeader
          title="Workflow"
          description="Human-controlled status transitions for triage, remediation, acceptance, duplicate closure, and evidence capture."
          eyebrow="Analyst controls"
        />
        <section className="grid gap-4 md:grid-cols-4">
          {stages.map((stage) => {
            const Icon = stage.icon;
            return (
              <Card key={stage.label}>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Icon data-icon="inline-start" />
                    {stage.label}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-muted-foreground">{stage.detail}</p>
                </CardContent>
              </Card>
            );
          })}
        </section>
      </div>
    </AppShell>
  );
}
