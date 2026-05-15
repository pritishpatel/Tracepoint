import { KeyRound, Server, ShieldCheck } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AppShell } from "@/components/workspace/app-shell";
import { PageHeader } from "@/components/workspace/page-header";
import { API_BASE_URL } from "@/lib/api";

export default function SettingsPage() {
  return (
    <AppShell>
      <div className="flex flex-col gap-6">
        <PageHeader
          title="Settings"
          description="Production posture, API connectivity, SSO readiness, and environment metadata."
          eyebrow="Platform operations"
        />
        <section className="grid gap-4 md:grid-cols-3">
          <SettingCard title="API base URL" value={API_BASE_URL} icon={<Server data-icon="inline-start" />} />
          <SettingCard title="Identity provider" value="OIDC / Keycloak ready" icon={<KeyRound data-icon="inline-start" />} />
          <SettingCard title="Authorization model" value="viewer · analyst · admin" icon={<ShieldCheck data-icon="inline-start" />} />
        </section>
      </div>
    </AppShell>
  );
}

function SettingCard({
  title,
  value,
  icon,
}: {
  title: string;
  value: string;
  icon: React.ReactNode;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {icon}
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">{value}</p>
      </CardContent>
    </Card>
  );
}
