import type { RiskLevel } from '../types';

interface RiskGaugeProps {
  score: number;
  riskLevel: RiskLevel;
  size?: 'sm' | 'md' | 'lg';
}

const riskColors: Record<RiskLevel, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#65a30d',
  safe: '#16a34a',
};

const riskLabels: Record<RiskLevel, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  safe: 'SAFE',
};

export default function RiskGauge({ score, riskLevel, size = 'lg' }: RiskGaugeProps) {
  const dimensions = {
    sm: { width: 120, strokeWidth: 8, fontSize: 24, labelSize: 10 },
    md: { width: 160, strokeWidth: 10, fontSize: 32, labelSize: 12 },
    lg: { width: 200, strokeWidth: 12, fontSize: 40, labelSize: 14 },
  };

  const { width, strokeWidth, fontSize, labelSize } = dimensions[size];
  const radius = (width - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = riskColors[riskLevel];

  return (
    <div className="relative inline-flex flex-col items-center">
      <svg width={width} height={width} className="transform -rotate-90">
        {/* Background circle */}
        <circle
          cx={width / 2}
          cy={width / 2}
          r={radius}
          fill="none"
          stroke="#334155"
          strokeWidth={strokeWidth}
        />
        {/* Progress circle */}
        <circle
          cx={width / 2}
          cy={width / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="gauge-fill transition-all duration-1000"
        />
      </svg>
      {/* Score in center */}
      <div
        className="absolute inset-0 flex flex-col items-center justify-center"
        style={{ color }}
      >
        <span className="font-bold" style={{ fontSize }}>
          {Math.round(score)}
        </span>
        <span
          className="font-semibold uppercase tracking-wide"
          style={{ fontSize: labelSize }}
        >
          {riskLabels[riskLevel]}
        </span>
      </div>
    </div>
  );
}
