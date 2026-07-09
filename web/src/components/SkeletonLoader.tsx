import type { CSSProperties, ReactNode } from 'react'

export interface SkeletonProps {
  /** Override inline style */
  style?: CSSProperties
  /** Optional className */
  className?: string
}

export interface SkeletonLineProps extends SkeletonProps {
  /** Number of lines to render (default 1) */
  count?: number
}

export interface SkeletonBlockProps extends SkeletonProps {
  /** Width in px or % (default '100%') */
  width?: string | number
  /** Height in px or % (default '16px') */
  height?: string | number
  /** Border-radius (default '8px') */
  borderRadius?: string | number
}

/**
 * Animated skeleton placeholder for loading states.
 * Uses CSS keyframe animation for a shimmer effect.
 */
export function Skeleton({ style, className }: SkeletonProps) {
  return (
    <div
      className={`skeleton ${className ?? ''}`}
      style={{
        background: 'var(--md-sys-color-outline)',
        opacity: 0.15,
        borderRadius: 8,
        animation: 'skeleton-pulse 1.5s ease-in-out infinite',
        ...style,
      }}
    />
  )
}

/**
 * Renders multiple skeleton lines with optional gaps.
 */
export function SkeletonLine({ count = 1, style, className }: SkeletonLineProps) {
  const lines = Array.from({ length: count }, (_, i) => (
    <Skeleton
      key={i}
      className={className}
      style={{
        height: 16,
        marginBottom: i === count - 1 ? 0 : (style?.marginBottom ?? 12),
        width: style?.width ?? '100%',
        ...style,
      }}
    />
  ))

  return <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>{lines}</div>
}

/**
 * Renders a skeleton block (rectangular placeholder).
 */
export function SkeletonBlock({
  width = '100%',
  height = 16,
  borderRadius = 8,
  style,
  className,
}: SkeletonBlockProps) {
  return (
    <Skeleton
      className={className}
      style={{
        width: String(width),
        height: String(height),
        borderRadius: String(borderRadius),
        ...style,
      }}
    />
  )
}

/**
 * A pre-built skeleton card that matches the existing `.card` component style.
 */
export function SkeletonCard({
  lines = 3,
  showTitle = false,
  children,
}: {
  lines?: number
  showTitle?: boolean
  children?: ReactNode
}) {
  return (
    <div
      className="card"
      style={{
        padding: 24,
        opacity: 0.5,
        pointerEvents: 'none',
      }}
    >
      {showTitle && (
        <SkeletonBlock width={120} height={18} borderRadius={6} style={{ marginBottom: 20 }} />
      )}
      <SkeletonLine count={lines} />
      {children}
    </div>
  )
}

/**
 * A skeleton table with animated placeholder rows.
 */
export function SkeletonTable({
  rows = 5,
  columns = 4,
}: {
  rows?: number
  columns?: number
}) {
  return (
    <div className="table-wrap" style={{ border: 'none', borderRadius: 0 }}>
      <table
        className="table-static"
        style={{
          opacity: 0.5,
          pointerEvents: 'none',
        }}
      >
        <thead>
          <tr>
            {Array.from({ length: columns }).map((_, i) => (
              <th key={i}>
                <SkeletonBlock width={80} height={14} borderRadius={4} />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: rows }).map((_, i) => (
            <tr key={i}>
              {Array.from({ length: columns }).map((_, j) => (
                <td key={j}>
                  <SkeletonBlock width={100} height={16} borderRadius={4} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}