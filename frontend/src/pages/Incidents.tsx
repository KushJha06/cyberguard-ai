import { Search } from 'lucide-react'
import { useCallback, useMemo, useState } from 'react'
import { api } from '../lib/api'
import { usePolling } from '../lib/hooks'
import type { Incident, Severity } from '../lib/types'
import { IncidentDetail } from '../components/IncidentDetail'
import { Empty, ErrorBanner, PageHeader, SeverityBadge, Spinner } from '../components/UI'

export function Incidents(){const load=useCallback(()=>api.incidents(),[]);const{data,error,loading}=usePolling(load,10000);const[selected,setSelected]=useState<Incident|null>(null);const[query,setQuery]=useState('');const[severity,setSeverity]=useState('all')
 const items=useMemo(()=>data?.filter(x=>(severity==='all'||x.severity===severity)&&(`${x.title} ${x.summary} ${x.rule_ids.join(' ')}`.toLowerCase().includes(query.toLowerCase())))||[],[data,query,severity])
 if(loading)return <Spinner/>;if(error||!data)return <ErrorBanner message={error}/>
 if(selected)return <><button className="back" onClick={()=>setSelected(null)}>← Back to queue</button><IncidentDetail incident={selected} onChange={setSelected}/></>
 return <><PageHeader eyebrow="Analyst workspace" title="Investigations" description="Prioritize findings, inspect evidence, and move incidents through a controlled workflow."/><div className="filters"><label className="search"><Search/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search title, summary, or rule ID"/></label><select value={severity} onChange={e=>setSeverity(e.target.value)}><option value="all">All severities</option>{['critical','high','medium','low','info'].map(x=><option key={x}>{x}</option>)}</select><span>{items.length} results</span></div>
 {items.length===0?<Empty title="No matching incidents">Adjust filters or ingest telemetry.</Empty>:<div className="table"><div className="table-head"><span>Incident</span><span>Domain</span><span>Status</span><span>Confidence</span><span>Updated</span></div>{items.map(i=><button className="table-row" key={i.id} onClick={()=>setSelected(i)}><div><SeverityBadge value={i.severity as Severity}/><span><b>{i.title}</b><small>{i.summary}</small></span></div><span>{i.category.replace('_',' ')}</span><span className={`status ${i.status}`}>{i.status.replace('_',' ')}</span><b>{Math.round(i.confidence*100)}%</b><span>{new Date(i.updated_at).toLocaleString()}</span></button>)}</div>}</>
}
