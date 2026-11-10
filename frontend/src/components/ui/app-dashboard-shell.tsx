import { useState, type ReactNode } from "react";
import { BookOpen, Boxes, Bug, Eye, Globe, LayoutDashboard, Plug, ShieldAlert, Siren, Users, type LucideIcon } from "lucide-react";

export interface DashboardNavItem {
  id: string;
  label: string;
  short: string;
  badge?: string;
}

export interface AppDashboardShellProps {
  workspace: { name: string; plan: string };
  user: { name: string; email: string; role?: string };
  nav: DashboardNavItem[];
  activeId: string;
  onNavigate: (id: string) => void;
  onLogout: () => void;
  searchValue?: string;
  onSearchChange?: (value: string) => void;
  showSearch?: boolean;
  headerActions?: ReactNode;
  children: ReactNode;
}

const NAV_ICONS: Record<string, LucideIcon> = {
  overview: LayoutDashboard,
  assets: Boxes,
  findings: ShieldAlert,
  vulnerabilities: Bug,
  detections: Eye,
  incidents: Siren,
  integrations: Plug,
  "threat-intel": Globe,
  playbooks: BookOpen,
  users: Users,
};

function NavGlyph({ id }: { id: string }) {
  const Icon = NAV_ICONS[id] ?? ShieldAlert;
  return <Icon size={18} strokeWidth={1.7} aria-hidden="true" />;
}

export function AppDashboardShell({
  workspace, user, nav, activeId, onNavigate, onLogout, searchValue = "",
  onSearchChange, showSearch = false, headerActions, children,
}: AppDashboardShellProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const active = nav.find((item) => item.id === activeId);
  const initials = user.name.trim().split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase() || "OA";

  const sidebar = (
    <aside className={["aegis-sidebar", collapsed ? "is-collapsed" : "", mobileOpen ? "is-mobile-open" : ""].filter(Boolean).join(" ")}>
      <div className="aegis-workspace">
        <div className="aegis-brand-mark" aria-hidden="true">OA</div>
        {!collapsed && <div className="aegis-workspace-copy"><strong>{workspace.name}</strong><span>{workspace.plan}</span></div>}
        <span className="aegis-workspace-chevron" aria-hidden="true">⌄</span>
      </div>
      <nav className="aegis-nav" aria-label="Primary navigation">
        {nav.map((item) => (
          <button key={item.id} type="button" className={["aegis-nav-item", activeId === item.id ? "is-active" : ""].filter(Boolean).join(" ")}
            aria-current={activeId === item.id ? "page" : undefined}
            title={collapsed ? item.label : undefined}
            onClick={() => { onNavigate(item.id); setMobileOpen(false); }}>
            <NavGlyph id={item.id}/>
            {!collapsed && <span className="aegis-nav-label">{item.label}</span>}
            {!collapsed && item.badge && <span className="aegis-nav-badge">{item.badge}</span>}
            {collapsed && item.badge && <span className="aegis-nav-dot" aria-hidden="true"/>}
          </button>
        ))}
      </nav>
      <div className="aegis-sidebar-bottom">
        <div className="aegis-session-status"><span className="aegis-status-dot"/> {!collapsed && <span>Authenticated API session</span>}</div>
        <div className="aegis-user-row">
          <span className="aegis-avatar">{initials}</span>
          {!collapsed && <span className="aegis-user-copy"><strong>{user.name}</strong><small>{user.email}</small></span>}
          <button type="button" className="aegis-logout" onClick={onLogout} aria-label="Sign out" title="Sign out">↗</button>
        </div>
        <button type="button" className="aegis-collapse" onClick={() => setCollapsed((value) => !value)} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
          {collapsed ? "»" : "«"} {!collapsed && <span>Collapse sidebar</span>}
        </button>
      </div>
    </aside>
  );

  return (
    <div className="aegis-shell">
      {sidebar}
      {mobileOpen && <button className="aegis-mobile-backdrop" aria-label="Close navigation" onClick={() => setMobileOpen(false)}/>}
      <div className="aegis-main">
        <header className="aegis-topbar">
          <button type="button" className="aegis-mobile-menu" onClick={() => setMobileOpen(true)} aria-label="Open navigation">☰</button>
          <div className="aegis-breadcrumb"><span>{workspace.name}</span><i>/</i><strong>{active?.label ?? "Overview"}</strong></div>
          <div className="aegis-topbar-actions">
            {showSearch && <label className="aegis-search"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="10.8" cy="10.8" r="6.3"/><path d="m16 16 4.5 4.5"/></svg><input aria-label="Search current records" value={searchValue} onChange={(event) => onSearchChange?.(event.target.value)} placeholder="Search records"/><kbd>/</kbd></label>}
            {headerActions}
          </div>
        </header>
        <main className="aegis-content">
          <div className="aegis-page-heading"><div><h1>{active?.label ?? "Overview"}</h1><p>Security operations · verified records from your connected services</p></div></div>
          {children}
        </main>
      </div>
    </div>
  );
}

export default AppDashboardShell;
