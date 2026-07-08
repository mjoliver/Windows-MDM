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
 * Uses flexbox layout to naturally prevent icon/text overlap.
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
    <div 
      className={`search-bar-wrap${className ? ` ${className}` : ''}`} 
      style={{ 
        position: 'relative', 
        display: 'flex', 
        alignItems: 'center', 
        width: '100%',
        ...style 
      }}
    >
      <Search 
        size={16} 
        className="search-icon" 
        style={{
          position: 'absolute',
          left: 12,
          pointerEvents: 'none',
          color: 'var(--md-sys-color-on-surface-variant)',
          opacity: 0.5,
          zIndex: 1,
        }}
      />
      <input
        className="search-input"
        placeholder={placeholder}
        value={value}
        onChange={e => onChange(e.target.value)}
        style={{
          background: 'rgba(0, 0, 0, 0.3)',
          border: '1px solid var(--md-sys-color-outline)',
          borderRadius: 'var(--radius-sm)',
          padding: '12px 16px 12px 38px',
          color: 'white',
          width: '100%',
          transition: 'border-color 0.2s',
          outline: 'none',
          fontFamily: 'inherit',
          fontSize: 'inherit',
        }}
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