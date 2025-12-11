import type { SeverityLevel, RiskLevel } from '../types';

interface SeverityBadgeProps {
  severity: SeverityLevel | RiskLevel;
  size?: 'sm' | 'md';
}

const badgeClasses: Record<SeverityLevel | RiskLevel, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  safe: 'badge-safe',
  info: 'badge-info',
};

export default function SeverityBadge({ severity, size = 'md' }: SeverityBadgeProps) {
  const sizeClasses = size === 'sm' ? 'text-xs px-2 py-0.5' : 'text-sm px-2.5 py-1';

  return (
    <span className={`badge ${badgeClasses[severity]} ${sizeClasses} uppercase`}>
      {severity}
    </span>
  );
}
