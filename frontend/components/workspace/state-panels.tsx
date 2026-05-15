import { AlertTriangle } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function LoadingPanel({ title = "Loading Tracepoint" }: { title?: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid gap-3 md:grid-cols-3">
          <div className="h-24 rounded-lg bg-muted" />
          <div className="h-24 rounded-lg bg-muted" />
          <div className="h-24 rounded-lg bg-muted" />
        </div>
      </CardContent>
    </Card>
  );
}

export function ErrorPanel({ message }: { message: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <AlertTriangle data-icon="inline-start" />
          API unavailable
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">{message}</p>
        <p className="mt-2 text-sm text-muted-foreground">
          Showing seeded operational data so the workspace remains reviewable.
        </p>
      </CardContent>
    </Card>
  );
}
