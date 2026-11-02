import type { ReactNode } from 'react'
import type { Severity } from '../lib/types'

export function Badge({children, tone='blue'}:{children:ReactNode; tone?:string}) { return <span className={`badge ${tone}`}>{children}</span> }
export function SeverityBadge({value}:{value:Severity}) { return <Badge tone={value}>{value}</Badge> }
export function Metric({label,value,detail,tone='cyan'}:{label:string;value:ReactNode;detail:string;tone?:string}) {
  return <div className={`metric ${tone}`}><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>
}
export function Empty({title,children}:{title:string;children:ReactNode}) { return <div className="empty"><div className="empty-icon">◇</div><h3>{title}</h3><p>{children}</p></div> }
export function ErrorBanner({message}:{message:string}) { return <div className="banner error"><b>Connection error</b><span>{message}</span></div> }
export function PageHeader({eyebrow,title,description,action}:{eyebrow:string;title:string;description:string;action?:ReactNode}) {
  return <header className="page-header"><div><span className="eyebrow">{eyebrow}</span><h1>{title}</h1><p>{description}</p></div>{action}</header>
}
export function Spinner() { return <div className="spinner" aria-label="Loading"/> }
