import { AlertTriangle, CheckCircle2, Download, FileCog, FileText, FolderArchive, Info, LoaderCircle, ShieldCheck, UploadCloud } from 'lucide-react'
import { useMemo, useState } from 'react'
import { api } from '../lib/api'
import type { IngestResponse } from '../lib/types'
import { PageHeader, SeverityBadge } from '../components/UI'

const uploadKinds = [
  {id:'ssh',title:'SSH server',files:'/etc/ssh/sshd_config or sshd.conf',detail:'Checks root login, password authentication, empty passwords and legacy protocol settings.'},
  {id:'container',title:'Containers',files:'docker-compose.yml or Kubernetes YAML',detail:'Checks privileged execution, host access, root execution, socket/hostPath mounts and image pinning.'},
  {id:'proxy',title:'Web proxy',files:'nginx.conf or a ZIP containing included .conf files',detail:'Checks server tokens, directory listing, legacy TLS and wildcard CORS.'},
  {id:'application',title:'Application',files:'application.yml, config.toml, app.ini, .env or *.properties',detail:'Checks plaintext credential fields, debug mode, anonymous access and disabled TLS verification.'},
]

export function Configuration(){
  const [file,setFile]=useState<File|null>(null)
  const [busy,setBusy]=useState(false)
  const [result,setResult]=useState<IngestResponse|null>(null)
  const [error,setError]=useState('')
  const [kind,setKind]=useState('application')
  const selected=useMemo(()=>uploadKinds.find(item=>item.id===kind)!,[kind])
  const scan=async()=>{if(!file)return;setBusy(true);setError('');setResult(null);try{setResult(await api.upload(file))}catch(e){setError(e instanceof Error?e.message:'Configuration scan failed')}finally{setBusy(false)}}
  return <><PageHeader eyebrow="Configuration assurance" title="Configuration telemetry" description="Upload a current configuration snapshot—not an executable—to identify exposure, privilege, credential and transport risks before deployment." action={<a className="ghost link-button" href="/examples/configuration-upload-example.yml" download><Download/>Example YAML</a>}/>

  <section className="config-explainer"><Info/><div><b>Configuration vs. operational telemetry</b><p>Use this page for current settings and deployment manifests. Use <strong>Analyze telemetry</strong> for logs, metrics, traces, alerts and event history. Static analysis cannot confirm runtime overrides, so findings include validation steps.</p></div></section>

  <div className="config-kind-grid">{uploadKinds.map(item=><button key={item.id} className={kind===item.id?'active':''} onClick={()=>setKind(item.id)}><FileText/><span><b>{item.title}</b><small>{item.files}</small></span></button>)}</div>

  <div className="config-grid"><section className="upload-panel"><div className="selected-guidance"><span>WHAT TO UPLOAD FOR {selected.title.toUpperCase()}</span><b>{selected.files}</b><p>{selected.detail}</p></div><label className={`dropzone compact ${file?'has-file':''}`}><input type="file" hidden accept=".conf,.config,.yaml,.yml,.toml,.ini,.cfg,.xml,.env,.properties,.zip,.tar,.gz,.tgz" onChange={e=>{setFile(e.target.files?.[0]||null);setResult(null);setError('')}}/>{file?<><FileCog/><h3>{file.name}</h3><p>{(file.size/1024).toFixed(1)} KB · Ready for read-only inspection</p><span className="ghost">Choose a different file</span></>:<><UploadCloud/><h3>Select one configuration or bundle</h3><p>.conf · .config · .yaml · .yml · .toml · .ini · .cfg · .xml · .env · .properties · .zip · .tar.gz</p><span className="ghost">Choose configuration</span></>}</label><button className="primary full" disabled={!file||busy} onClick={scan}>{busy?<LoaderCircle className="spin"/>:<ShieldCheck/>}{busy?'Inspecting configuration…':'Run configuration analysis'}</button></section>

  <section className="guidance"><span className="eyebrow">UPLOAD CHECKLIST</span><h3>Prepare a useful snapshot</h3>{[
    ['Use the effective file','Prefer the configuration read by the running service, including deployment overrides.'],
    ['Keep filenames recognizable','Names such as sshd_config, nginx.conf and docker-compose.yml enable specialized checks.'],
    ['Bundle related includes','ZIP/TAR may contain up to 100 safe files and 50 MB expanded content.'],
    ['Protect sensitive data','Use placeholders where possible. Values are redacted, but private keys should never be uploaded.'],
  ].map(([title,detail])=><div className="guide" key={title}><CheckCircle2/><span><b>{title}</b><small>{detail}</small></span></div>)}<div className="do-not-upload"><AlertTriangle/><span><b>Do not upload</b><small>Executables, private keys, production database dumps, encrypted archives, or files you are not authorized to inspect.</small></span></div></section></div>

  <section className="config-support"><article><FileCog/><b>Structured settings</b><span>YAML, TOML, INI, XML, ENV and properties</span></article><article><ShieldCheck/><b>Specialized checks</b><span>SSH, Docker Compose, Kubernetes and Nginx</span></article><article><FolderArchive/><b>Related bundles</b><span>ZIP, TAR, TAR.GZ and GZIP</span></article></section>

  {error&&<div className="banner error"><AlertTriangle/><span>{error}</span></div>}{result&&<ConfigurationResults result={result}/>}</>
}

function ConfigurationResults({result}:{result:IngestResponse}){const d=result.diagnosis,m=result.manifest;return <section className="results"><div className="result-head"><CheckCircle2/><div><h3>Configuration analysis complete</h3><p>{result.accepted_events} records · {result.incidents.length} findings · {result.processing_ms.toFixed(1)} ms</p></div></div>{m&&<div className="config-manifest"><div><span>Uploaded file</span><b>{m.uploaded_file}</b></div><div><span>Parser selected</span><b>{m.adapter}</b></div><div><span>Files inspected</span><b>{m.files_analyzed.length}</b></div><div><span>Rules evaluated</span><b>{m.rules_evaluated}</b></div><section><b>Inspected paths</b>{m.files_analyzed.map(file=><code key={file}>✓ {file}</code>)}</section></div>}{d&&<div className={`diagnosis ${d.readiness}`}><span>{d.readiness} · {d.primary_issue_area.replaceAll('_',' ')}</span><h3>{d.summary}</h3><div><section><b>Likely causes</b>{d.likely_causes.map(x=><p key={x}>• {x}</p>)}</section><section><b>Recommended checks</b>{d.recommended_actions.map(x=><p key={x}>• {x}</p>)}</section></div></div>}<div className="config-findings">{result.incidents.map(i=><details key={i.id} open><summary><SeverityBadge value={i.severity}/><span><b>{i.title}</b><small>{i.summary}</small></span><strong>{Math.round(i.confidence*100)}%</strong></summary><div className="finding-body"><section><b>Evidence</b>{i.evidence.map((e,index)=><p key={index}>• {e.summary}</p>)}</section><section><b>What to check</b>{i.analyst_checks.map(x=><p key={x}>• {x}</p>)}</section><section><b>Recommended remediation</b>{i.remediation.map(x=><p key={x}>• {x}</p>)}</section><section><b>Validation and limits</b>{[...i.validation,...i.limitations].map(x=><p key={x}>• {x}</p>)}</section></div></details>)}</div>{!result.incidents.length&&<div className="banner warn"><AlertTriangle/><span>No current risk rule matched in the files listed above. Confirm that all included files and runtime overrides were supplied before treating this as a clean result.</span></div>}</section>}
