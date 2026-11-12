import { useEffect, useRef, useCallback, type ReactNode } from 'react'

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
 * Returns a list of all focusable elements within a container.
 */
function getFocusableElements(container: HTMLElement): HTMLElement[] {
  const selector = [
    'a[href]',
    'button:not([disabled])',
    'input:not([disabled])',
    'textarea:not([disabled])',
    'select:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
  ].join(', ')
  return Array.from(container.querySelectorAll<HTMLElement>(selector))
}

/**
 * A React wrapper for the existing `.modal-overlay`, `.modal`, `.modal-header`,
 * `.modal-body`, and `.modal-footer` CSS classes.
 *
 * Features:
 * - ARIA attributes (role="dialog", aria-modal, aria-labelledby)
 * - Escape key to close
 * - Focus trap within modal when tabbing
 * - Focus restoration to trigger element on close
 */
export function Modal({ open, onClose, title, maxWidth, children, footer, showClose }: ModalProps) {
  const modalRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLElement | null>(null)
  const onCloseRef = useRef(onClose)

  useEffect(() => {
    onCloseRef.current = onClose
  }, [onClose])

  // Store reference to the element that triggered the modal
  useEffect(() => {
    if (open) {
      triggerRef.current = document.activeElement as HTMLElement
    }
  }, [open])

  // Focus trap and Escape key handling
  useEffect(() => {
    if (!open || !modalRef.current) return

    const container = modalRef.current
    const focusable = getFocusableElements(container)

    // Prefer [autofocus] or the first focusable element inside .modal-body so
    // opening a form modal focuses the first input instead of the Close button.
    const body = container.querySelector<HTMLElement>('.modal-body')
    const autoFocusEl = container.querySelector<HTMLElement>('[autofocus]')
    const bodyFocusable = body ? getFocusableElements(body) : []
    const initialTarget = autoFocusEl ?? bodyFocusable[0] ?? focusable[0]
    initialTarget?.focus()

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onCloseRef.current()
        return
      }

      if (e.key === 'Tab' && modalRef.current) {
        const items = getFocusableElements(modalRef.current)
        if (items.length === 0) return

        const active = document.activeElement as HTMLElement | null
        const currentIndex = active ? items.indexOf(active) : -1
        let nextIndex: number

        if (e.shiftKey) {
          nextIndex = currentIndex > 0 ? currentIndex - 1 : items.length - 1
        } else {
          nextIndex = currentIndex >= 0 && currentIndex < items.length - 1 ? currentIndex + 1 : 0
        }

        items[nextIndex]?.focus()
        e.preventDefault()
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [open])

  // Restore focus when modal closes
  useEffect(() => {
    if (!open && triggerRef.current) {
      triggerRef.current.focus?.()
      triggerRef.current = null
    }
  }, [open])

  const handleOverlayClick = useCallback(() => {
    onClose()
  }, [onClose])

  if (!open) return null

  const modalId = 'modal-dialog'

  return (
    <div className="modal-overlay" onClick={handleOverlayClick} role="presentation">
      <div
        ref={modalRef}
        className="modal"
        style={{ maxWidth }}
        onClick={e => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby={modalId}
      >
        <div className="modal-header">
          <span id={modalId} className="modal-title">{title}</span>
          {(showClose ?? true) && (
            <button className="btn btn-icon btn-secondary" onClick={onClose} aria-label="Close dialog">
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