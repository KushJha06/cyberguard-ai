import { Activity, Boxes, Database, FileSearch, Gauge, LayoutDashboard, PlugZap, ScrollText, Settings, ShieldCheck, SlidersHorizontal, UploadCloud } from 'lucide-react'
import type { ReactNode } from 'react'

export type PageId = 'dashboard'|'live'|'incidents'|'upload'|'configuration'|'preflight'|'plugins'|'datasets'|'reports'|'settings'
const nav: Array<[PageId,string,typeof Gauge]> = [
  ['dashboard','Command Center',LayoutDashboard], ['live','Live Systems',Activity], ['incidents','Investigations',FileSearch],
  ['upload','Ingest Telemetry',UploadCloud], ['configuration','Configuration',SlidersHorizontal],
  ['preflight','Preflight',ShieldCheck], ['plugins','Integrations',PlugZap],
  ['datasets','Datasets',Database], ['reports','Reports',ScrollText], ['settings','Settings',Settings],
]
export function Layout({page,setPage,online,children}:{page:PageId;setPage:(p:PageId)=>void;online:boolean;children:ReactNode}) {
  return <div className="shell">
    <aside className="sidebar"><div className="brand"><div className="brand-mark"><Boxes size={20}/></div><div><b>CyberGuard</b><span>ANALYST CONSOLE</span></div></div>
      <nav>{nav.map(([id,label,Icon])=><button key={id} className={page===id?'active':''} onClick={()=>setPage(id)}><Icon size={17}/><span>{label}</span></button>)}</nav>
      <div className="side-foot"><div className={`pulse ${online?'on':''}`}/><div><b>{online?'Platform online':'API offline'}</b><span>LOCAL · ADVISORY</span></div></div>
    </aside>
    <main><div className="topbar"><div className="crumb">Workspace <span>/</span> {nav.find(x=>x[0]===page)?.[1]}</div><div className="analyst"><div className="avatar">AN</div><div><b>Local Analyst</b><span>Read-only session</span></div></div></div><div className="content">{children}</div></main>
  </div>
}
