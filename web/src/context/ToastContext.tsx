import { useState, useCallback, type ReactNode } from 'react'
import { Toast, type ToastVariant } from '../components/Toast'
import { ToastContext } from '../hooks/useToast'

let _toastId = 0
function generateId() {
  return `toast-${++_toastId}-${Date.now()}`
}

export interface ToastManager {
  toast: {
    error: (message: string, duration?: number) => void
    success: (message: string, duration?: number) => void
    info: (message: string, duration?: number) => void
  }
  dismiss: (id: string) => void
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Array<{ id: string; message: string; variant: ToastVariant; duration?: number }>>([])

  const addToast = useCallback((variant: ToastVariant, message: string, duration?: number) => {
    const id = generateId()
    setToasts(prev => [...prev.slice(-4), { id, message, variant, duration }])
  }, [])

  const dismissToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  const toast = {
    error: (message: string, duration?: number) => addToast('error', message, duration),
    success: (message: string, duration?: number) => addToast('success', message, duration),
    info: (message: string, duration?: number) => addToast('info', message, duration),
  }

  return (
    <ToastContext.Provider value={{ toast, dismiss: dismissToast }}>
      {children}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </ToastContext.Provider>
  )
}

function ToastContainer({ toasts, onDismiss }: { toasts: Array<{ id: string; message: string; variant: ToastVariant; duration?: number }>; onDismiss: (id: string) => void }) {
  if (toasts.length === 0) return null

  return (
    <div
      style={{
        position: 'fixed',
        top: 24,
        right: 24,
        zIndex: 9999,
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
        pointerEvents: 'none',
      }}
    >
      {toasts.map((t) => (
        <div key={t.id} style={{ pointerEvents: 'auto' }}>
          <Toast
            id={t.id}
            message={t.message}
            variant={t.variant}
            duration={t.duration}
            onDismiss={onDismiss}
          />
        </div>
      ))}
    </div>
  )
}