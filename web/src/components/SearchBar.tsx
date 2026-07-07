import { Search, X } from 'lucide-react'

export interface SearchBarProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  onClear?: () => void
  style?: React.CSSProperties
  className?: string
}

/**
 * A search input with a clear button that appears when value is non-empty.
 * Uses the existing `.input-wrap`, `.input-icon`, and `.input` CSS classes.
 */
export function SearchBar({
  value,
  onChange,
  placeholder = 'Search...',
  onClear,
  style,
  className,
}: SearchBarProps) {
  const hasValue = value.length > 0

  return (
    <div className={`input-wrap${className ? ` ${className}` : ''}`} style={style}>
      <Search size={14} className="input-icon" />
      <input
        className="input input-has-icon"
        placeholder={placeholder}
        value={value}
        onChange={e => onChange(e.target.value)}
      />
      {hasValue && (
        <button
          className="btn btn-icon btn-secondary btn-sm"
          style={{
            position: 'absolute',
            right: 8,
            top: '50%',
            transform: 'translateY(-50%)',
            padding: 4,
            minWidth: 0,
            width: 24,
            height: 24,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
          onClick={() => {
            onChange('')
            onClear?.()
          }}
          aria-label="Clear search"
        >
          <X size={12} />
        </button>
      )}
    </div>
  )
}