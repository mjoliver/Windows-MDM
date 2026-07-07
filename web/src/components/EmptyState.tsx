import type { ReactNode } from 'react'

export interface EmptyStateProps {
  icon?: ReactNode
  title: string
  description: string
  action?: ReactNode
  style?: React.CSSProperties
}

/**
 * Renders a centered empty-state message when a list or view has no content.
 * Uses the existing `.empty-state` CSS class from index.css.
 */
export function EmptyState({ icon, title, description, action, style }: EmptyStateProps) {
  return (
    <div className="empty-state" style={style}>
      {icon && <div style={{ marginBottom: 16 }}>{icon}</div>}
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  )
}