import { Badge } from "@/components/ui/badge";

export function SeverityBadge({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase();
  const label = normalized.replaceAll("_", " ").toUpperCase();

  if (normalized === "critical") {
    return <Badge variant="destructive">{label}</Badge>;
  }

  if (normalized === "high") {
    return <Badge>{label}</Badge>;
  }

  return <Badge variant="secondary">{label}</Badge>;
}

export function StatusBadge({ status }: { status: string }) {
  const label = status.replaceAll("_", " ");

  if (["needs_human_review", "new"].includes(status)) {
    return <Badge variant="outline">{label}</Badge>;
  }

  if (["closed", "resolved", "accepted"].includes(status)) {
    return <Badge variant="secondary">{label}</Badge>;
  }

  return <Badge>{label}</Badge>;
}
