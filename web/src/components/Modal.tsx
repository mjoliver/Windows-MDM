import type { ReactNode } from 'react'

export interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  maxWidth?: number
  children: ReactNode
  footer?: ReactNode
  showClose?: boolean
}

/**
 * A React wrapper for the existing `.modal-overlay`, `.modal`, `.modal-header`,
 * `.modal-body`, and `.modal-footer` CSS classes.
 *
 * Handles overlay click-to-close and stopPropagation on the modal content.
 */
export function Modal({ open, onClose, title, maxWidth, children, footer, showClose }: ModalProps) {
  if (!open) return null

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ maxWidth }} onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <span className="modal-title">{title}</span>
          {(showClose ?? true) && (
            <button className="btn btn-icon btn-secondary" onClick={onClose}>
              <CloseIcon />
            </button>
          )}
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  )
}

function CloseIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M1 1L13 13M1 13L13 1" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  )
}