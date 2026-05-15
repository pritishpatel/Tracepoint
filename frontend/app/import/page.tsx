"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
import { Upload } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { AppShell } from "@/components/workspace/app-shell";
import { PageHeader } from "@/components/workspace/page-header";
import { tracepointApi } from "@/lib/api";
import type { ImportSummary } from "@/lib/api";

const importSchema = z.object({
  source: z.string().min(2).max(64),
  persist: z.boolean(),
  checkDuplicates: z.boolean(),
  json: z.string().min(10),
});

type ImportForm = z.infer<typeof importSchema>;

const sampleJson = JSON.stringify(
  [
    {
      title: "Exposed API key in GitHub repository",
      description:
        "A secret scanning alert detected an active API key committed to a public repository.",
      category: "exposed_secret",
      affected_asset: "github/example-repo",
      reporter: "secret-scanner",
    },
  ],
  null,
  2,
);

export default function ImportPage() {
  const [summary, setSummary] = useState<ImportSummary | null>(null);
  const form = useForm<ImportForm>({
    resolver: zodResolver(importSchema),
    defaultValues: {
      source: "scanner",
      persist: true,
      checkDuplicates: true,
      json: sampleJson,
    },
  });

  const importMutation = useMutation({
    mutationFn: async (values: ImportForm) => {
      const items = JSON.parse(values.json) as unknown;
      if (!Array.isArray(items)) {
        throw new Error("Import JSON must be an array of finding-like objects.");
      }

      return tracepointApi.importFindings({
        source: values.source,
        persist: values.persist,
        check_duplicates: values.checkDuplicates,
        items,
      });
    },
    onSuccess: setSummary,
  });

  return (
    <AppShell>
      <div className="flex flex-col gap-6">
        <PageHeader
          title="Intake and bulk import"
          description="Validate scanner, bounty, KEV, cloud, identity, and manual reports before they enter the triage workflow."
          eyebrow="Data entry point"
        />

        <section className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
          <Card>
            <CardHeader>
              <CardTitle>Import JSON</CardTitle>
            </CardHeader>
            <CardContent>
              <form
                className="flex flex-col gap-4"
                onSubmit={form.handleSubmit((values) => importMutation.mutate(values))}
              >
                <div className="grid gap-3 md:grid-cols-3">
                  <label className="flex flex-col gap-1 text-sm font-medium">
                    Source
                    <Input {...form.register("source")} />
                  </label>
                  <label className="flex items-center gap-2 text-sm font-medium">
                    <input type="checkbox" {...form.register("persist")} />
                    Persist records
                  </label>
                  <label className="flex items-center gap-2 text-sm font-medium">
                    <input type="checkbox" {...form.register("checkDuplicates")} />
                    Check duplicates
                  </label>
                </div>

                <textarea
                  className="min-h-96 rounded-lg border bg-background p-3 font-mono text-sm outline-none focus:ring-2 focus:ring-ring"
                  {...form.register("json")}
                />

                {form.formState.errors.json ? (
                  <p className="text-sm text-destructive">
                    {form.formState.errors.json.message}
                  </p>
                ) : null}
                {importMutation.error ? (
                  <p className="text-sm text-destructive">
                    {(importMutation.error as Error).message}
                  </p>
                ) : null}

                <Button disabled={importMutation.isPending}>
                  <Upload data-icon="inline-start" />
                  {importMutation.isPending ? "Importing..." : "Run import"}
                </Button>
              </form>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Import summary</CardTitle>
            </CardHeader>
            <CardContent>
              {summary ? (
                <div className="grid gap-3">
                  <SummaryMetric label="Received" value={summary.received} />
                  <SummaryMetric label="Created" value={summary.created} />
                  <SummaryMetric label="Duplicates" value={summary.duplicates} />
                  <SummaryMetric label="Failed" value={summary.failed} />
                  <div className="mt-2 rounded-lg border p-3">
                    <div className="text-sm font-medium">Recent results</div>
                    <div className="mt-2 flex flex-col gap-2">
                      {summary.results.map((result) => (
                        <div key={result.index} className="text-sm">
                          {result.title} · {result.severity} ·{" "}
                          {result.persisted ? "persisted" : "analysis only"}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">
                  Run a dry-run or persisted import to see validation, duplicate, and
                  triage results here.
                </p>
              )}
            </CardContent>
          </Card>
        </section>
      </div>
    </AppShell>
  );
}

function SummaryMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-center justify-between rounded-lg border p-3">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="text-2xl font-semibold">{value}</span>
    </div>
  );
}
