import { Link } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'

export interface BreadcrumbItem {
  label: string
  /** Omitted for the last item (current page) */
  to?: string
}

interface Props {
  items: BreadcrumbItem[]
}

/**
 * Renders a breadcrumb navigation trail.
 * The last item is displayed as plain text (current page).
 * All preceding items are clickable links.
 */
export function Breadcrumb({ items }: Props) {
  return (
    <nav aria-label="Breadcrumb" style={{ marginBottom: 24 }}>
      <ol
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 4,
          listStyle: 'none',
          margin: 0,
          padding: 0,
          fontSize: '0.875rem',
        }}
      >
        {items.map((item, index) => {
          const isLast = index === items.length - 1
          return (
            <li
              key={index}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 4,
                color: isLast ? 'var(--md-sys-color-on-surface)' : 'var(--md-sys-color-on-surface-variant)',
                opacity: isLast ? 1 : 0.6,
              }}
            >
              {index > 0 && (
                <ChevronRight size={14} style={{ opacity: 0.4, flexShrink: 0 }} />
              )}
              {isLast ? (
                <span style={{ fontWeight: 600 }}>{item.label}</span>
              ) : item.to ? (
                <Link
                  to={item.to}
                  style={{
                    textDecoration: 'none',
                    color: 'inherit',
                    cursor: 'pointer',
                    transition: 'opacity 0.2s',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.opacity = '1')}
                  onMouseLeave={(e) => (e.currentTarget.style.opacity = '0.6')}
                >
                  {item.label}
                </Link>
              ) : (
                <span style={{ fontWeight: 600 }}>{item.label}</span>
              )}
            </li>
          )
        })}
      </ol>
    </nav>
  )
}