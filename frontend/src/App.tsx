import { lazy, Suspense, useEffect, useState } from 'react'
import { api } from './lib/api'
import { Layout, type PageId } from './components/Layout'
import { Spinner } from './components/UI'

const Dashboard = lazy(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })))
const LiveSystems = lazy(() => import('./pages/LiveSystems').then(m => ({ default: m.LiveSystems })))
const Incidents = lazy(() => import('./pages/Incidents').then(m => ({ default: m.Incidents })))
const Upload = lazy(() => import('./pages/Upload').then(m => ({ default: m.Upload })))
const Configuration = lazy(() => import('./pages/Configuration').then(m => ({ default: m.Configuration })))
const Preflight = lazy(() => import('./pages/OtherPages').then(m => ({ default: m.Preflight })))
const Plugins = lazy(() => import('./pages/OtherPages').then(m => ({ default: m.Plugins })))
const Datasets = lazy(() => import('./pages/OtherPages').then(m => ({ default: m.Datasets })))
const Reports = lazy(() => import('./pages/OtherPages').then(m => ({ default: m.Reports })))
const Settings = lazy(() => import('./pages/OtherPages').then(m => ({ default: m.Settings })))

function pageFromHash():PageId { const value=location.hash.replace('#/','') as PageId; return ['dashboard','live','incidents','upload','configuration','preflight','plugins','datasets','reports','settings'].includes(value)?value:'dashboard' }
export default function App(){const[page,setPageState]=useState<PageId>(pageFromHash);const[online,setOnline]=useState(false)
 const setPage=(next:PageId)=>{location.hash=`/${next}`;setPageState(next)}
 useEffect(()=>{const onHash=()=>setPageState(pageFromHash());addEventListener('hashchange',onHash);const ping=()=>api.health().then(()=>setOnline(true)).catch(()=>setOnline(false));ping();const id=setInterval(ping,10000);return()=>{removeEventListener('hashchange',onHash);clearInterval(id)}},[])
 let view; switch(page){case'live':view=<LiveSystems/>;break;case'incidents':view=<Incidents/>;break;case'upload':view=<Upload/>;break;case'configuration':view=<Configuration/>;break;case'preflight':view=<Preflight/>;break;case'plugins':view=<Plugins/>;break;case'datasets':view=<Datasets/>;break;case'reports':view=<Reports/>;break;case'settings':view=<Settings/>;break;default:view=<Dashboard openIncidents={()=>setPage('incidents')}/>}
 return <Layout page={page} setPage={setPage} online={online}><Suspense fallback={<Spinner/>}>{view}</Suspense></Layout>}
