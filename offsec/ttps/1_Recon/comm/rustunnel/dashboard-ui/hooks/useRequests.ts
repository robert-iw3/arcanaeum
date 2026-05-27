'use client';

import { useState, useCallback, useEffect } from 'react';
import type { ApiClient, CapturedRequest } from '@/lib/types';
import { useInterval } from './useInterval';

export function useRequests(api: ApiClient, tunnelId: string | null) {
  const [requests, setRequests] = useState<CapturedRequest[]>([]);

  const poll = useCallback(async () => {
    if (!tunnelId) return;
    try {
      const data = (await api.get(
        `/api/tunnels/${tunnelId}/requests?limit=100`
      )) as CapturedRequest[];
      setRequests(data);
    } catch {
      setRequests([]);
    }
  }, [api, tunnelId]);

  useEffect(() => { poll(); }, [poll]);
  useInterval(poll, 2000);

  return { requests, refresh: poll };
}
