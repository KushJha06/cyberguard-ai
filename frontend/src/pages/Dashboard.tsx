import { Activity, ArrowRight, Database, Radar, ShieldAlert } from 'lucide-react'
import { useCallback } from 'react'
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import { api } from '../lib/api'
import { usePolling } from '../lib/hooks'
import type { Health, Incident, Stats } from '../lib/types'
import { ErrorBanner, Metric, PageHeader, SeverityBadge, Spinner } from '../components/UI'

type Data={health:Health;stats:Stats;incidents:Incident[]}
const colors:Record<string,string>={critical:'#ef4444',high:'#f97316',medium:'#f59e0b',low:'#22c55e',info:'#38bdf8'}
export function Dashboard({openIncidents}:{openIncidents:()=>void}){
 const load=useCallback(async()=>{const [health,stats,incidents]=await Promise.all([api.health(),api.stats(),api.incidents(8)]);return{health,stats,incidents}},[])
 const {data,error,loading}=usePolling<Data>(load,10000)
 if(loading)return <Spinner/>; if(error||!data)return <ErrorBanner message={error}/>
 const priority=(data.stats.by_severity.critical||0)+(data.stats.by_severity.high||0)
 const pie=Object.entries(data.stats.by_severity).map(([name,value])=>({name,value}))
 return <><PageHeader eyebrow="Security operations workspace" title="Command center" description="Real-time operational posture, evidence-led incidents, and analyst readiness in one workspace." action={<button className="primary" onClick={openIncidents}>Open queue <ArrowRight size={16}/></button>}/>
 <section className="metric-grid"><Metric label="Open incidents" value={(data.stats.by_status.open||0)+(data.stats.by_status.investigating||0)} detail="Awaiting disposition"/><Metric label="Critical + high" value={priority} detail="Priority investigation queue" tone="orange"/><Metric label="Telemetry events" value={data.stats.events.toLocaleString()} detail="Normalized locally" tone="purple"/><Metric label="Active detections" value={data.health.rules} detail={`${data.health.adapters.length} ingestion adapters`} tone="green"/></section>
 <section className="dashboard-grid"><div className="panel wide"><div className="panel-title"><div><span>LATEST ACTIVITY</span><h3>Incident queue</h3></div><button className="queue-link" onClick={openIncidents}>View investigations <ArrowRight size={14}/></button></div>
 {data.incidents.length===0?<div className="inline-empty">No findings yet. Connect an agent or upload telemetry.</div>:data.incidents.slice(0,5).map(i=><button className="incident-row" key={i.id} onClick={openIncidents}><div className="incident-icon"><ShieldAlert size={18}/></div><div><div className="incident-title"><SeverityBadge value={i.severity}/><b>{i.title}</b></div><p>{i.summary}</p></div><span className="row-meta"><span className={`status ${i.status}`}>{i.status.replace('_',' ')}</span><br/>{i.event_count} signals · {Math.round(i.confidence*100)}% confidence</span></button>)}</div>
 <div className="panel"><div className="panel-title"><div><span>RISK DISTRIBUTION</span><h3>Incident severity</h3></div><Activity size={20}/></div><div className="chart-wrap">{pie.length?<ResponsiveContainer width="100%" height={220}><PieChart><Pie data={pie} dataKey="value" innerRadius={62} outerRadius={88} paddingAngle={4}>{pie.map(x=><Cell key={x.name} fill={colors[x.name]||'#64748b'}/>)}</Pie><Tooltip contentStyle={{background:'#0d1726',border:'1px solid #24364c',borderRadius:10}}/></PieChart></ResponsiveContainer>:<div className="chart-empty">No incident data</div>}<div className="legend">{pie.map(x=><span key={x.name}><i style={{background:colors[x.name]}}/>{x.name}<b>{x.value}</b></span>)}</div></div></div></section>
 <section className="trust-strip"><div><Database/><span><b>Local-first storage</b>Evidence remains on your infrastructure</span></div><div><Activity/><span><b>Live host telemetry</b>Read-only agents with bounded collection</span></div><div><ShieldAlert/><span><b>Advisory by design</b>No autonomous remediation</span></div></section></>
}
