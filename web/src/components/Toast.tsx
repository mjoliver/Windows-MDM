import { useState, useEffect } from 'react'
import { X, AlertCircle, CheckCircle2, Info } from 'lucide-react'

export type ToastVariant = 'error' | 'success' | 'info'

export interface ToastData {
  id: string
  message: string
  variant: ToastVariant
  duration?: number
}

export interface ToastProps extends ToastData {
  onDismiss: (id: string) => void
}

const VARIANT_CONFIG = {
  error: {
    icon: AlertCircle,
    borderColor: 'var(--md-sys-color-error)',
    bg: 'rgba(242, 184, 181, 0.08)',
    iconColor: 'var(--md-sys-color-error)',
  },
  success: {
    icon: CheckCircle2,
    borderColor: 'var(--md-sys-color-success)',
    bg: 'rgba(180, 225, 151, 0.08)',
    iconColor: 'var(--md-sys-color-success)',
  },
  info: {
    icon: Info,
    borderColor: 'var(--md-sys-color-primary)',
    bg: 'rgba(208, 188, 255, 0.08)',
    iconColor: 'var(--md-sys-color-primary)',
  },
} as const

export function Toast({ message, variant, onDismiss, duration = 4000, id }: ToastProps) {
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    // Trigger enter animation
    requestAnimationFrame(() => setVisible(true))
  }, [])

  useEffect(() => {
    if (duration === 0) return // Don't auto-dismiss if duration is 0
    const timer = setTimeout(() => {
      onDismiss(id)
    }, duration)
    return () => clearTimeout(timer)
  }, [duration, id, onDismiss])


  const config = VARIANT_CONFIG[variant]
  const Icon = config.icon

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: 12,
        padding: '14px 16px',
        background: config.bg,
        border: `1px solid ${config.borderColor}33`,
        borderRadius: 12,
        color: 'var(--md-sys-color-on-surface)',
        fontSize: '0.9rem',
        fontWeight: 500,
        maxWidth: 380,
        minWidth: 280,
        boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
        transform: visible ? 'translateX(0)' : 'translateX(100%)',
        opacity: visible ? 1 : 0,
        transition: 'all 0.2s ease',
        pointerEvents: visible ? 'auto' : 'none',
      }}
    >
      <div style={{ flexShrink: 0, marginTop: 1 }}>
        <Icon size={18} color={config.iconColor} />
      </div>
      <div style={{ flex: 1, lineHeight: 1.5, paddingTop: 1 }}>{message}</div>
      <button
        onClick={() => onDismiss(id)}
        style={{
          background: 'none',
          border: 'none',
          color: 'var(--md-sys-color-on-surface-variant)',
          cursor: 'pointer',
          padding: 4,
          display: 'flex',
          alignItems: 'center',
          opacity: 0.5,
          transition: 'opacity 0.2s',
        }}
        onMouseEnter={(e) => (e.currentTarget.style.opacity = '1')}
        onMouseLeave={(e) => (e.currentTarget.style.opacity = '0.5')}
      >
        <X size={14} />
      </button>
    </div>
  )
}