import { CheckCircle2, CircleAlert, ClipboardCheck, Crosshair, Wrench } from 'lucide-react'
import { useState } from 'react'
import { api } from '../lib/api'
import type { Incident, IncidentStatus } from '../lib/types'
import { SeverityBadge } from './UI'

export function IncidentDetail({incident,onChange}:{incident:Incident;onChange:(i:Incident)=>void}) {
  const [tab,setTab]=useState('evidence'); const [saving,setSaving]=useState(false)
  const update=async(status:IncidentStatus)=>{setSaving(true);try{onChange(await api.updateStatus(incident.id,status))}finally{setSaving(false)}}
  const tabs=[['evidence','Evidence'],['checks','Analyst checks'],['response','Safe response'],['validation','Validation'],['limits','Limitations']]
  return <div className="detail">
    <div className="detail-head"><div><SeverityBadge value={incident.severity}/><h2>{incident.title}</h2><p>{incident.summary}</p></div><div className="confidence"><strong>{Math.round(incident.confidence*100)}%</strong><span>confidence</span></div></div>
    <div className="root"><Crosshair size={19}/><div><span>LIKELY ROOT CAUSE</span><p>{incident.root_cause}</p></div></div>
    <div className="workflow"><label>Incident disposition</label><select disabled={saving} value={incident.status} onChange={e=>update(e.target.value as IncidentStatus)}><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select><span>{incident.event_count} evidence items · {incident.rule_ids.join(', ')}</span></div>
    <div className="tabs">{tabs.map(([id,label])=><button className={tab===id?'active':''} onClick={()=>setTab(id)} key={id}>{label}</button>)}</div>
    <div className="tab-content">
      {tab==='evidence' && incident.evidence.map((e,i)=><div className="evidence" key={i}><span>EVIDENCE {String(i+1).padStart(2,'0')}</span><code>{e.summary}</code>{Object.keys(e.details||{}).length>0&&<pre>{JSON.stringify(e.details,null,2)}</pre>}</div>)}
      {tab==='checks' && <List icon={<ClipboardCheck/>} items={incident.analyst_checks}/>} 
      {tab==='response' && <><div className="banner warn"><CircleAlert/><span>Obtain authorization and preserve rollback access before making changes.</span></div><List icon={<Wrench/>} items={incident.remediation}/></>}
      {tab==='validation' && <List icon={<CheckCircle2/>} items={incident.validation}/>} 
      {tab==='limits' && <List icon={<CircleAlert/>} items={incident.limitations}/>} 
    </div>
  </div>
}
function List({items,icon}:{items:string[];icon:React.ReactNode}){return <div className="action-list">{items.map((x,i)=><div key={i}><i>{icon}</i><span>{x}</span></div>)}</div>}
