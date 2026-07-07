import type { ReactNode } from 'react'

export interface ActionButtonProps {
  icon: ReactNode
  label: string
  onClick: () => void
  variant?: 'primary' | 'secondary'
}

/**
 * A pill-shaped button for "New X" actions in page headers and empty states.
 * Uses existing `.btn`, `.btn-primary`, `.btn-secondary` CSS classes.
 */
export function ActionButton({ icon, label, onClick, variant = 'secondary' }: ActionButtonProps) {
  return (
    <button className={`btn btn-${variant}`} onClick={onClick}>
      {icon} {label}
    </button>
  )
}