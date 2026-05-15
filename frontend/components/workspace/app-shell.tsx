"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  Archive,
  BarChart3,
  Bell,
  FileText,
  Gauge,
  GitBranch,
  Import,
  KeyRound,
  Search,
  Settings,
  ShieldCheck,
  ShieldEllipsis,
  Table2,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const navItems = [
  { href: "/", label: "Overview", icon: Gauge },
  { href: "/findings", label: "Findings", icon: Table2 },
  { href: "/import", label: "Intake / Import", icon: Import },
  { href: "/kev", label: "KEV Priorities", icon: ShieldEllipsis },
  { href: "/risk-sla", label: "Risk & SLA", icon: BarChart3 },
  { href: "/activity", label: "Activity", icon: Activity },
  { href: "/evidence", label: "Evidence", icon: Archive },
  { href: "/workflow", label: "Workflow", icon: GitBranch },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="grid min-h-screen lg:grid-cols-[260px_1fr]">
        <aside className="hidden border-r bg-muted/30 lg:flex lg:flex-col">
          <div className="flex h-16 items-center gap-3 border-b px-5">
            <div className="flex size-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
              <ShieldCheck data-icon="inline-start" />
            </div>
            <div>
              <div className="font-heading text-base font-semibold">Tracepoint</div>
              <div className="text-xs text-muted-foreground">SecOps workspace</div>
            </div>
          </div>

          <nav className="flex flex-1 flex-col gap-1 p-3">
            {navItems.map((item) => {
              const Icon = item.icon;
              const active =
                item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);

              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    "flex h-9 items-center gap-2 rounded-lg px-3 text-sm font-medium text-muted-foreground transition-colors hover:bg-background hover:text-foreground",
                    active && "bg-background text-foreground ring-1 ring-border",
                  )}
                >
                  <Icon data-icon="inline-start" />
                  {item.label}
                </Link>
              );
            })}
          </nav>

          <div className="border-t p-4">
            <div className="rounded-lg border bg-background p-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-muted-foreground">
                  SSO posture
                </span>
                <KeyRound data-icon="inline-end" className="text-muted-foreground" />
              </div>
              <p className="mt-2 text-sm font-medium">OIDC-ready</p>
              <p className="mt-1 text-xs text-muted-foreground">
                Keycloak dev realm planned for Docker Compose.
              </p>
            </div>
          </div>
        </aside>

        <div className="flex min-w-0 flex-col">
          <header className="sticky top-0 z-10 flex h-16 items-center justify-between border-b bg-background/95 px-4 backdrop-blur md:px-6">
            <div className="flex min-w-0 items-center gap-3">
              <div className="lg:hidden">
                <ShieldCheck data-icon="inline-start" />
              </div>
              <div className="hidden h-9 min-w-80 items-center gap-2 rounded-lg border bg-muted/30 px-3 text-sm text-muted-foreground md:flex">
                <Search data-icon="inline-start" />
                Search CVE, asset, reporter, workflow state
              </div>
            </div>

            <div className="flex items-center gap-2">
              <Badge variant="secondary">local</Badge>
              <Button variant="outline" size="icon" aria-label="Notifications">
                <Bell data-icon="inline-start" />
              </Button>
              <Button variant="outline">
                <FileText data-icon="inline-start" />
                Analyst
              </Button>
            </div>
          </header>

          <main className="flex-1 p-4 md:p-6">{children}</main>
        </div>
      </div>
    </div>
  );
}
