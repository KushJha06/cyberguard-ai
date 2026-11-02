import { Cpu, HardDrive, MemoryStick, RefreshCw, Server, Wifi, WifiOff } from 'lucide-react'
import { useCallback } from 'react'
import { api } from '../lib/api'
import { usePolling } from '../lib/hooks'
import { Empty, ErrorBanner, Metric, PageHeader, Spinner } from '../components/UI'

export function LiveSystems(){const load=useCallback(()=>api.agents(),[]);const {data,error,loading,refresh}=usePolling(load,5000)
 if(loading)return <Spinner/>;if(error||!data)return <ErrorBanner message={error}/>
 const online=data.filter(x=>x.state==='online').length
 return <><PageHeader eyebrow="Real-time operations" title="Live systems" description="Operating-system health and application readiness refresh automatically every five seconds." action={<button className="ghost" onClick={refresh}><RefreshCw size={15}/>Refresh</button>}/>
 <section className="metric-grid three"><Metric label="Connected systems" value={data.length} detail="Registered host agents"/><Metric label="Online" value={online} detail="Heartbeat is current" tone="green"/><Metric label="Stale" value={data.length-online} detail="Connectivity review required" tone="orange"/></section>
 {data.length===0?<Empty title="No systems connected">Run cyberguard-agent on a host to begin live analysis.</Empty>:<div className="fleet">{data.map(a=>{const h=a.latest_metrics.host_health||{},m=a.latest_metrics.memory_usage||{},d=a.latest_metrics.disk_usage||{};return <article className="host-card" key={a.agent_id}><div className="host-head"><div className="host-symbol"><Server/></div><div><h3>{a.hostname}</h3><p>{a.platform} · Agent {a.agent_version}</p></div><span className={`state ${a.state}`}>{a.state==='online'?<Wifi/>:<WifiOff/>}{a.state}</span></div><div className="host-metrics"><Mini icon={<Cpu/>} label="CPU" value={`${Number(h.cpu_used_percent||0).toFixed(1)}%`}/><Mini icon={<MemoryStick/>} label="Memory" value={`${Number(m.memory_used_percent||0).toFixed(1)}%`}/><Mini icon={<HardDrive/>} label="Disk" value={`${Number(d.disk_used_percent||0).toFixed(1)}%`}/><Mini icon={<ActivityIcon/>} label="Processes" value={String(h.process_count||'—')}/></div><div className="host-foot"><span>Last seen {new Date(a.last_seen).toLocaleTimeString()}</span><b>{a.incident_count} latest findings</b></div>{Boolean(d.projected_minutes_to_full)&&<div className="forecast">Projected capacity exhaustion in {Number(d.projected_minutes_to_full).toFixed(0)} minutes</div>}</article>})}</div>}
 </>}
function Mini({icon,label,value}:{icon:React.ReactNode;label:string;value:string}){return <div className="mini"><i>{icon}</i><span>{label}</span><b>{value}</b></div>}
function ActivityIcon(){return <span className="activity-glyph">⌁</span>}
