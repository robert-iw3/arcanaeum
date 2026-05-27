'use client';

import { useEffect, useRef } from 'react';

export function useInterval(fn: () => void, ms: number): void {
  const saved = useRef(fn);
  useEffect(() => { saved.current = fn; }, [fn]);
  useEffect(() => {
    const id = setInterval(() => saved.current(), ms);
    return () => clearInterval(id);
  }, [ms]);
}
