import { createContext, useContext } from 'react'

import type { ToastManager } from '../context/ToastContext'

export const ToastContext = createContext<ToastManager | null>(null)

export function useToast() {
  const context = useContext(ToastContext)
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider')
  }
  return context.toast
}