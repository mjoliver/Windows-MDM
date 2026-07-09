export interface InfoField {
  label: string
  value?: string | null
  mono?: boolean
}

export interface InfoGridProps {
  fields: InfoField[]
  columns?: number
}

/**
 * Renders key-value pairs using the existing `.info-grid` and `.info-item` CSS.
 * Accepts an array of label/value pairs for clean iteration.
 * Falls back to "Not reported" for empty values.
 */
export function InfoGrid({ fields, columns = 3 }: InfoGridProps) {
  return (
    <div className="info-grid" style={{ gridTemplateColumns: columns > 0 ? `repeat(${columns}, 1fr)` : undefined }}>
      {fields.map(field => (
        <div key={field.label} className="info-item">
          <div className="info-label">{field.label}</div>
          <div
            className="info-value"
            style={{
              fontFamily: field.mono ? 'monospace' : 'inherit',
              wordBreak: 'break-all' as const,
            }}
          >
            {field.value || 'Not reported'}
          </div>
        </div>
      ))}
    </div>
  )
}