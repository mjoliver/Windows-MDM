

const STATUS_MAP: Record<string, { label: string; cls: string }> = {
  compliant:     { label: 'Healthy',    cls: 'badge-success'  },
  non_compliant: { label: 'Warning',    cls: 'badge-danger'   },
  unknown:       { label: 'Unknown',    cls: 'badge-neutral'  },
  pending:       { label: 'Syncing',    cls: 'badge-warning'  },
  failed:        { label: 'Error',      cls: 'badge-danger'   },
  active:        { label: 'Active',     cls: 'badge-success'  },
  inactive:      { label: 'Offline',    cls: 'badge-neutral'  },
  online:        { label: 'Online',     cls: 'badge-success'  },
}

interface Props {
  status: string
  label?: string
  dot?: boolean
}

export function Badge({ status, label, dot = true }: Props) {
  const cfg = STATUS_MAP[status] ?? { label: status, cls: 'badge-neutral' }
  return (
    <span className={`badge ${cfg.cls}`}>
      {dot && <span className="badge-dot" />}
      {label ?? cfg.label}
    </span>
  )
}
