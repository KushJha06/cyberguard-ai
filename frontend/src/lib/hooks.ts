import { useCallback, useEffect, useState } from 'react'

export function usePolling<T>(loader:()=>Promise<T>, interval = 0) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const refresh = useCallback(async () => {
    try { setData(await loader()); setError('') }
    catch (e) { setError(e instanceof Error ? e.message : 'Request failed') }
    finally { setLoading(false) }
  }, [loader])
  useEffect(() => { refresh(); if (!interval) return; const id=setInterval(refresh, interval); return()=>clearInterval(id) }, [refresh, interval])
  return { data, error, loading, refresh }
}
