import { useState } from 'react';
import { ChevronDown, ChevronUp, AlertTriangle, Shield, Code, Package, Users, FileText, GitBranch, Box, History, Activity, TrendingUp, Brain } from 'lucide-react';
import type { CategoryResult } from '../types';
import FindingItem from './FindingItem';

interface CategoryCardProps {
  result: CategoryResult;
}

const categoryIcons: Record<string, React.ElementType> = {
  vulnerability: AlertTriangle,
  static_code: Code,
  typosquatting: Package,
  supply_chain: Box,
  maintainer: Users,
  metadata: FileText,
  dependency: GitBranch,
  repository: GitBranch,
  version_history: History,
  behavioral: Activity,
  popularity: TrendingUp,
  ml_anomaly: Brain,
};

const categoryLabels: Record<string, string> = {
  vulnerability: 'Vulnerability Analysis',
  static_code: 'Static Code Analysis',
  typosquatting: 'Typosquatting Detection',
  supply_chain: 'Supply Chain Analysis',
  maintainer: 'Maintainer Analysis',
  metadata: 'Metadata Analysis',
  dependency: 'Dependency Analysis',
  repository: 'Repository Analysis',
  version_history: 'Version History Analysis',
  behavioral: 'Behavioral Analysis',
  popularity: 'Popularity Analysis',
  ml_anomaly: 'ML Anomaly Detection',
};

const categoryDescriptions: Record<string, string> = {
  vulnerability: 'Known CVEs and security advisories',
  static_code: 'Obfuscation, dangerous functions, malicious patterns',
  typosquatting: 'Name similarity to popular packages',
  supply_chain: 'Dependency confusion, namespace squatting',
  maintainer: 'Account trust signals and email analysis',
  metadata: 'License, description, URL validation',
  dependency: 'Dependency health and abandonment',
  repository: 'Source repository analysis',
  version_history: 'Release patterns, version jumps, rapid releases',
  behavioral: 'Runtime behavior, import hooks, code execution',
  popularity: 'Community engagement, GitHub activity, downloads',
  ml_anomaly: 'Statistical anomaly detection in package metadata',
};

function getScoreColor(score: number): string {
  if (score >= 80) return 'text-red-400';
  if (score >= 60) return 'text-orange-400';
  if (score >= 40) return 'text-yellow-400';
  if (score >= 20) return 'text-lime-400';
  return 'text-green-400';
}

export default function CategoryCard({ result }: CategoryCardProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const Icon = categoryIcons[result.category] || Shield;
  const label = categoryLabels[result.category] || result.category;
  const description = categoryDescriptions[result.category] || '';

  const hasCriticalOrHigh = result.critical_count > 0 || result.high_count > 0;

  return (
    <div className={`card transition-all ${hasCriticalOrHigh ? 'border-red-800/50' : ''}`}>
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-start gap-4 text-left"
      >
        <div className={`p-2 rounded-lg ${hasCriticalOrHigh ? 'bg-red-900/30' : 'bg-slate-700'}`}>
          <Icon className={`w-6 h-6 ${hasCriticalOrHigh ? 'text-red-400' : 'text-slate-400'}`} />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-1">
            <h3 className="text-white font-semibold">{label}</h3>
            {result.findings_count > 0 && (
              <span className="text-xs text-slate-400 bg-slate-700 px-2 py-0.5 rounded-full">
                {result.findings_count} finding{result.findings_count !== 1 ? 's' : ''}
              </span>
            )}
          </div>
          <p className="text-slate-400 text-sm">{description}</p>

          {/* Severity counts */}
          {result.findings_count > 0 && (
            <div className="flex gap-2 mt-2">
              {result.critical_count > 0 && (
                <span className="text-xs text-red-400">{result.critical_count} critical</span>
              )}
              {result.high_count > 0 && (
                <span className="text-xs text-orange-400">{result.high_count} high</span>
              )}
              {result.medium_count > 0 && (
                <span className="text-xs text-yellow-400">{result.medium_count} medium</span>
              )}
              {result.low_count > 0 && (
                <span className="text-xs text-lime-400">{result.low_count} low</span>
              )}
              {result.info_count > 0 && (
                <span className="text-xs text-blue-400">{result.info_count} info</span>
              )}
            </div>
          )}
        </div>

        <div className="flex items-center gap-4">
          <div className="text-right">
            <div className={`text-2xl font-bold ${getScoreColor(result.score)}`}>
              {Math.round(result.score)}
            </div>
            <div className="text-xs text-slate-500">risk score</div>
          </div>
          {result.findings_count > 0 && (
            isExpanded ? (
              <ChevronUp className="w-5 h-5 text-slate-400" />
            ) : (
              <ChevronDown className="w-5 h-5 text-slate-400" />
            )
          )}
        </div>
      </button>

      {/* Expanded findings */}
      {isExpanded && result.findings.length > 0 && (
        <div className="mt-4 pt-4 border-t border-slate-700 space-y-3">
          {result.findings.map((finding) => (
            <FindingItem key={finding.id} finding={finding} />
          ))}
        </div>
      )}
    </div>
  );
}
