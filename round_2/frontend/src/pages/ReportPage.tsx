import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  Shield, ArrowLeft, Package, User, Clock, ExternalLink,
  AlertTriangle, GitBranch, FileText, Download, Filter, Copy, Check, Info, X
} from 'lucide-react';
import { getAuditReport } from '../services/api';
import type { AuditReport, SeverityLevel } from '../types';
import RiskGauge from '../components/RiskGauge';
import SeverityBadge from '../components/SeverityBadge';
import CategoryCard from '../components/CategoryCard';
import LoadingSkeleton from '../components/LoadingSkeleton';

function TruncatedText({ text, maxLength = 100 }: { text: string; maxLength?: number }) {
  const [isExpanded, setIsExpanded] = useState(false);

  if (text.length <= maxLength) {
    return <span>{text}</span>;
  }

  return (
    <span>
      {isExpanded ? text : `${text.substring(0, maxLength)}...`}
      {' '}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="text-blue-400 hover:text-blue-300 text-xs underline"
      >
        {isExpanded ? 'Show less' : 'Show more'}
      </button>
    </span>
  );
}

export default function ReportPage() {
  const { auditId } = useParams<{ auditId: string }>();
  const [report, setReport] = useState<AuditReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'details'>('overview');
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | 'all'>('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showScoreExplanation, setShowScoreExplanation] = useState(false);

  const copyToClipboard = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  useEffect(() => {
    if (!auditId) return;

    async function fetchReport() {
      try {
        const data = await getAuditReport(auditId!);
        setReport(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load report');
      } finally {
        setLoading(false);
      }
    }

    fetchReport();
  }, [auditId]);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-900">
        {/* Header Skeleton */}
        <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur">
          <div className="container mx-auto px-4 py-4 flex items-center gap-4">
            <div className="h-6 w-20 bg-slate-700 rounded shimmer" />
            <div className="h-6 w-32 bg-slate-700 rounded shimmer" />
            <div className="flex-1" />
            <div className="h-10 w-32 bg-slate-700 rounded shimmer" />
          </div>
        </header>

        <main className="container mx-auto px-4 py-8">
          {/* Package Header Skeleton */}
          <div className="flex flex-col lg:flex-row gap-8 mb-8">
            <div className="flex-1">
              <div className="flex items-start gap-4 mb-4">
                <div className="w-16 h-16 bg-slate-700 rounded-xl shimmer" />
                <div className="flex-1 space-y-2">
                  <div className="h-8 bg-slate-700 rounded w-1/2 shimmer" />
                  <div className="h-4 bg-slate-700 rounded w-1/4 shimmer" />
                  <div className="h-3 bg-slate-700 rounded w-1/3 shimmer" />
                </div>
              </div>
              <div className="space-y-2 mb-4">
                <div className="h-4 bg-slate-700 rounded w-full shimmer" />
                <div className="h-4 bg-slate-700 rounded w-3/4 shimmer" />
              </div>
              <div className="flex gap-4">
                <div className="h-4 w-24 bg-slate-700 rounded shimmer" />
                <div className="h-4 w-24 bg-slate-700 rounded shimmer" />
              </div>
            </div>
            <div className="lg:text-right">
              <div className="inline-block">
                <div className="w-48 h-48 bg-slate-700 rounded-full shimmer" />
              </div>
            </div>
          </div>

          {/* Summary Card Skeleton */}
          <div className="rounded-xl p-6 mb-8 border border-slate-700 bg-slate-800/50">
            <div className="h-6 bg-slate-700 rounded w-3/4 mb-2 shimmer" />
            <div className="h-4 bg-slate-700 rounded w-full shimmer" />
          </div>

          {/* Stats Skeleton */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="card text-center">
                <div className="h-10 bg-slate-700 rounded w-20 mx-auto mb-2 shimmer" />
                <div className="h-3 bg-slate-700 rounded w-24 mx-auto shimmer" />
              </div>
            ))}
          </div>

          {/* Tabs Skeleton */}
          <div className="flex gap-2 mb-6 border-b border-slate-700">
            <div className="h-10 w-24 bg-slate-700 rounded-t shimmer" />
            <div className="h-10 w-32 bg-slate-700 rounded-t shimmer" />
            <div className="h-10 w-32 bg-slate-700 rounded-t shimmer" />
          </div>

          {/* Category Cards Skeleton */}
          <div className="space-y-4">
            <LoadingSkeleton variant="category" count={6} />
          </div>
        </main>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
          <p className="text-red-400 font-medium mb-2">Error loading report</p>
          <p className="text-slate-400 text-sm mb-4">{error || 'Report not found'}</p>
          <Link to="/" className="btn btn-primary">
            Go back
          </Link>
        </div>
      </div>
    );
  }

  const sortedCategories = Object.values(report.categories).sort(
    (a, b) => b.score - a.score
  );

  return (
    <div className="min-h-screen bg-slate-900">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-10">
        <div className="container mx-auto px-4 py-4 flex items-center gap-4">
          <Link to="/" className="flex items-center gap-2 text-slate-400 hover:text-white transition-colors">
            <ArrowLeft className="w-5 h-5" />
            <span>Back</span>
          </Link>
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-blue-500" />
            <span className="text-lg font-bold text-white">PyShield</span>
          </div>
          <div className="flex-1"></div>
          <button
            onClick={() => {
              const data = JSON.stringify(report, null, 2);
              const blob = new Blob([data], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `pyshield-${report.package_name}-${report.package_version}.json`;
              a.click();
              URL.revokeObjectURL(url);
            }}
            className="btn btn-secondary flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            Export JSON
          </button>
          <button
            onClick={async () => {
              try {
                const response = await fetch(`/api/v1/audit/${auditId}/sbom`);
                if (!response.ok) {
                  const error = await response.json().catch(() => ({ detail: 'Failed to generate SBOM' }));
                  throw new Error(error.detail || 'Failed to generate SBOM');
                }
                const sbom = await response.json();
                const blob = new Blob([JSON.stringify(sbom, null, 2)], {
                  type: 'application/vnd.cyclonedx+json'
                });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `pyshield-sbom-${report.package_name}-${report.package_version}.cdx.json`;
                a.click();
                URL.revokeObjectURL(url);
              } catch (err) {
                console.error('SBOM export failed:', err);
                alert(`Failed to export SBOM: ${err instanceof Error ? err.message : 'Unknown error'}`);
              }
            }}
            className="btn btn-secondary flex items-center gap-2"
            title="Export Software Bill of Materials (CycloneDX format)"
          >
            <Download className="w-4 h-4" />
            Export SBOM
          </button>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        {/* Package header */}
        <div className="flex flex-col lg:flex-row gap-8 mb-8">
          {/* Left: Package info */}
          <div className="flex-1">
            <div className="flex items-start gap-4 mb-4">
              <div className="p-3 bg-slate-800 rounded-xl">
                <Package className="w-10 h-10 text-blue-400" />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-3">
                  <h1 className="text-3xl font-bold text-white mb-1">
                    {report.package_name}
                  </h1>
                  <button
                    onClick={() => copyToClipboard(report.package_name, 'package-name')}
                    className="text-slate-400 hover:text-white transition-colors p-1 -m-1"
                    title="Copy package name"
                  >
                    {copiedId === 'package-name' ? (
                      <Check className="w-5 h-5 text-green-400" />
                    ) : (
                      <Copy className="w-5 h-5" />
                    )}
                  </button>
                </div>
                <p className="text-slate-400">
                  Version {report.package_version}
                </p>
                <p className="text-slate-500 text-xs mt-1 font-mono flex items-center gap-2">
                  Audit ID: {report.audit_id}
                  <button
                    onClick={() => copyToClipboard(report.audit_id, 'audit-id')}
                    className="text-slate-500 hover:text-white transition-colors p-1 -m-1"
                    title="Copy audit ID"
                  >
                    {copiedId === 'audit-id' ? (
                      <Check className="w-3 h-3 text-green-400" />
                    ) : (
                      <Copy className="w-3 h-3" />
                    )}
                  </button>
                </p>
              </div>
            </div>

            {report.package_metadata?.summary && (
              <p className="text-slate-300 mb-4">{report.package_metadata.summary}</p>
            )}

            <div className="flex flex-wrap gap-4 text-sm">
              {report.package_metadata?.author && (
                <div className="flex items-center gap-2 text-slate-400">
                  <User className="w-4 h-4" />
                  <span>{report.package_metadata.author}</span>
                </div>
              )}
              {report.package_metadata?.license && (
                <div className="flex items-center gap-2 text-slate-400">
                  <FileText className="w-4 h-4 flex-shrink-0" />
                  <TruncatedText text={report.package_metadata.license} maxLength={150} />
                </div>
              )}
              {report.analysis_duration_ms && (
                <div className="flex items-center gap-2 text-slate-400">
                  <Clock className="w-4 h-4" />
                  <span>Analyzed in {(report.analysis_duration_ms / 1000).toFixed(1)}s</span>
                </div>
              )}
            </div>

            {/* Links */}
            <div className="flex gap-3 mt-4">
              <a
                href={`https://pypi.org/project/${report.package_name}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm text-blue-400 hover:underline flex items-center gap-1"
              >
                PyPI <ExternalLink className="w-3 h-3" />
              </a>
              {report.repository?.url && (
                <div className="flex items-center gap-2 group">
                  <a
                    href={report.repository.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-blue-400 hover:underline flex items-center gap-1"
                  >
                    Repository <ExternalLink className="w-3 h-3" />
                  </a>
                  <button
                    onClick={() => copyToClipboard(report.repository!.url, 'repo-url')}
                    className="text-slate-500 hover:text-white transition-colors opacity-0 group-hover:opacity-100"
                    title="Copy repository URL"
                  >
                    {copiedId === 'repo-url' ? (
                      <Check className="w-3 h-3 text-green-400" />
                    ) : (
                      <Copy className="w-3 h-3" />
                    )}
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Right: Risk score */}
          <div className="lg:text-right">
            <div className="inline-block">
              <RiskGauge score={report.overall_score} riskLevel={report.risk_level} />
              <button
                onClick={() => setShowScoreExplanation(true)}
                className="mt-2 flex items-center gap-2 text-sm text-slate-400 hover:text-white transition-colors mx-auto touch-manipulation"
              >
                <Info className="w-4 h-4" />
                How is this calculated?
              </button>
            </div>
          </div>
        </div>

        {/* Score Explanation Modal */}
        {showScoreExplanation && (
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 sm:p-6" onClick={() => setShowScoreExplanation(false)}>
            <div className="bg-slate-900 rounded-xl max-w-2xl w-full max-h-[90vh] sm:max-h-[80vh] overflow-y-auto border border-slate-700" onClick={(e) => e.stopPropagation()}>
              <div className="sticky top-0 bg-slate-900 border-b border-slate-700 p-4 sm:p-6 flex items-center justify-between">
                <h2 className="text-xl sm:text-2xl font-bold text-white">Risk Score Calculation</h2>
                <button onClick={() => setShowScoreExplanation(false)} className="text-slate-400 hover:text-white">
                  <X className="w-6 h-6" />
                </button>
              </div>
              <div className="p-4 sm:p-6 space-y-4 sm:space-y-6">
                <div>
                  <h3 className="text-lg font-semibold text-white mb-2">Overall Formula</h3>
                  <code className="block bg-slate-800 p-4 rounded-lg text-blue-400 font-mono text-sm">
                    overall_score = Σ(category_score × category_weight)
                  </code>
                </div>

                <div>
                  <h3 className="text-base sm:text-lg font-semibold text-white mb-3">Category Weights</h3>
                  <div className="space-y-2">
                    {[
                      { name: 'Vulnerability', weight: 22 },
                      { name: 'Static Code', weight: 22 },
                      { name: 'Supply Chain', weight: 18 },
                      { name: 'Behavioral', weight: 8 },
                      { name: 'Typosquatting', weight: 8 },
                      { name: 'Maintainer', weight: 6 },
                      { name: 'Version History', weight: 5 },
                      { name: 'Metadata', weight: 4 },
                      { name: 'Dependency', weight: 4 },
                      { name: 'Popularity', weight: 4 },
                      { name: 'ML Anomaly', weight: 3 },
                      { name: 'Repository', weight: 2 },
                    ].map(({ name, weight }) => (
                      <div key={name} className="flex items-center gap-2 sm:gap-4">
                        <span className="text-slate-300 text-sm sm:text-base w-32 sm:w-40 flex-shrink-0">{name}</span>
                        <div className="flex-1 bg-slate-800 rounded-full h-6 relative">
                          <div
                            className="bg-blue-600 h-full rounded-full"
                            style={{ width: `${weight * 4}%` }}
                          />
                        </div>
                        <span className="text-white font-mono text-sm sm:text-base w-10 sm:w-12 text-right flex-shrink-0">{weight}%</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h3 className="text-base sm:text-lg font-semibold text-white mb-2">Risk Levels</h3>
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 sm:gap-3">
                      <span className="w-20 sm:w-24 px-2 sm:px-3 py-1 rounded-full text-xs font-bold text-center bg-red-900 text-red-100 flex-shrink-0">Critical</span>
                      <span className="text-slate-300 text-sm sm:text-base">Score ≥ 80</span>
                    </div>
                    <div className="flex items-center gap-2 sm:gap-3">
                      <span className="w-20 sm:w-24 px-2 sm:px-3 py-1 rounded-full text-xs font-bold text-center bg-orange-900 text-orange-100 flex-shrink-0">High</span>
                      <span className="text-slate-300 text-sm sm:text-base">60 ≤ Score &lt; 80</span>
                    </div>
                    <div className="flex items-center gap-2 sm:gap-3">
                      <span className="w-20 sm:w-24 px-2 sm:px-3 py-1 rounded-full text-xs font-bold text-center bg-yellow-900 text-yellow-100 flex-shrink-0">Medium</span>
                      <span className="text-slate-300 text-sm sm:text-base">40 ≤ Score &lt; 60</span>
                    </div>
                    <div className="flex items-center gap-2 sm:gap-3">
                      <span className="w-20 sm:w-24 px-2 sm:px-3 py-1 rounded-full text-xs font-bold text-center bg-blue-900 text-blue-100 flex-shrink-0">Low</span>
                      <span className="text-slate-300 text-sm sm:text-base">20 ≤ Score &lt; 40</span>
                    </div>
                    <div className="flex items-center gap-2 sm:gap-3">
                      <span className="w-20 sm:w-24 px-2 sm:px-3 py-1 rounded-full text-xs font-bold text-center bg-green-900 text-green-100 flex-shrink-0">Safe</span>
                      <span className="text-slate-300 text-sm sm:text-base">Score &lt; 20</span>
                    </div>
                  </div>
                </div>

                <div className="bg-slate-800 rounded-lg p-4">
                  <p className="text-slate-300 text-sm">
                    <strong className="text-white">Note:</strong> Each category analyzer calculates a score from 0-100 based on findings severity.
                    The overall score is a weighted sum that prioritizes critical security categories like vulnerabilities and static code analysis.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Summary card */}
        <div className={`rounded-xl p-6 mb-8 border fade-in ${
          report.risk_level === 'critical' ? 'bg-red-900/20 border-red-800' :
          report.risk_level === 'high' ? 'bg-orange-900/20 border-orange-800' :
          report.risk_level === 'medium' ? 'bg-yellow-900/20 border-yellow-800' :
          report.risk_level === 'low' ? 'bg-lime-900/20 border-lime-800' :
          'bg-green-900/20 border-green-800'
        }`}>
          <p className="text-lg font-medium text-white mb-2">{report.summary}</p>
          <p className="text-slate-300">{report.recommendation}</p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
          <div className="card text-center fade-in" style={{ animationDelay: '0.1s' }}>
            <div className="text-3xl font-bold text-white mb-1">
              {report.stats.total_findings}
            </div>
            <div className="text-sm text-slate-400">Total Findings</div>
          </div>
          <div className="card text-center fade-in" style={{ animationDelay: '0.15s' }}>
            <div className="text-3xl font-bold text-red-400 mb-1">
              {report.stats.severity_counts.critical}
            </div>
            <div className="text-sm text-slate-400">Critical</div>
          </div>
          <div className="card text-center fade-in" style={{ animationDelay: '0.2s' }}>
            <div className="text-3xl font-bold text-orange-400 mb-1">
              {report.stats.severity_counts.high}
            </div>
            <div className="text-sm text-slate-400">High</div>
          </div>
          <div className="card text-center fade-in" style={{ animationDelay: '0.25s' }}>
            <div className="text-3xl font-bold text-yellow-400 mb-1">
              {report.stats.severity_counts.medium}
            </div>
            <div className="text-sm text-slate-400">Medium</div>
          </div>
          <div className="card text-center fade-in" style={{ animationDelay: '0.3s' }}>
            <div className="text-3xl font-bold text-lime-400 mb-1">
              {report.stats.severity_counts.low + report.stats.severity_counts.info}
            </div>
            <div className="text-sm text-slate-400">Low/Info</div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-6 border-b border-slate-700">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-4 py-2 font-medium transition-colors ${
              activeTab === 'overview'
                ? 'text-blue-400 border-b-2 border-blue-400'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Overview
          </button>
          <button
            onClick={() => setActiveTab('findings')}
            className={`px-4 py-2 font-medium transition-colors ${
              activeTab === 'findings'
                ? 'text-blue-400 border-b-2 border-blue-400'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            All Findings ({report.all_findings.length})
          </button>
          <button
            onClick={() => setActiveTab('details')}
            className={`px-4 py-2 font-medium transition-colors ${
              activeTab === 'details'
                ? 'text-blue-400 border-b-2 border-blue-400'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Package Details
          </button>
        </div>

        {/* Tab content */}
        {activeTab === 'overview' && (
          <div className="space-y-4">
            {sortedCategories.map((category) => (
              <div key={category.category} className="fade-in-stagger">
                <CategoryCard result={category} />
              </div>
            ))}
          </div>
        )}

        {activeTab === 'findings' && (
          <div className="space-y-6">
            {/* Severity Filter */}
            {report.all_findings.length > 0 && (
              <div className="card">
                <div className="flex items-center gap-3 mb-3">
                  <Filter className="w-4 h-4 text-slate-400" />
                  <h3 className="text-white font-medium">Filter by Severity</h3>
                </div>
                <div className="flex flex-wrap gap-2">
                  {(['all', 'critical', 'high', 'medium', 'low', 'info'] as const).map((severity) => {
                    const count = severity === 'all'
                      ? report.all_findings.length
                      : report.all_findings.filter(f => f.severity === severity).length;

                    return (
                      <button
                        key={severity}
                        onClick={() => setSeverityFilter(severity)}
                        className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                          severityFilter === severity
                            ? 'bg-blue-600 text-white'
                            : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                        }`}
                      >
                        {severity.charAt(0).toUpperCase() + severity.slice(1)}
                        <span className="ml-2 text-xs opacity-75">({count})</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {report.all_findings.length === 0 ? (
              <div className="card text-center py-8">
                <Shield className="w-12 h-12 text-green-400 mx-auto mb-3" />
                <p className="text-white font-medium">No security findings!</p>
                <p className="text-slate-400 text-sm">This package passed all security checks.</p>
              </div>
            ) : (
              report.all_findings
                .filter(finding => severityFilter === 'all' || finding.severity === severityFilter)
                .sort((a, b) => {
                  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                  return order[a.severity] - order[b.severity];
                })
                .map((finding, index) => (
                  <div key={finding.id} className="card relative fade-in" style={{ animationDelay: `${index * 0.05}s` }}>
                    <button
                      onClick={() => copyToClipboard(
                        `[${finding.severity.toUpperCase()}] ${finding.title}\n${finding.description}${finding.remediation ? `\nRemediation: ${finding.remediation}` : ''}`,
                        finding.id
                      )}
                      className="absolute top-3 right-3 text-slate-500 hover:text-white transition-colors"
                      title="Copy finding"
                    >
                      {copiedId === finding.id ? (
                        <Check className="w-4 h-4 text-green-400" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </button>
                    <div className="flex items-start gap-3 pr-8">
                      <SeverityBadge severity={finding.severity} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-xs text-slate-500 bg-slate-700 px-2 py-0.5 rounded">
                            {finding.category}
                          </span>
                        </div>
                        <h3 className="text-white font-medium mb-2">{finding.title}</h3>
                        <p className="text-slate-400 text-sm mb-2">{finding.description}</p>
                        {finding.remediation && (
                          <p className="text-blue-400 text-sm">
                            <strong>Remediation:</strong> {finding.remediation}
                          </p>
                        )}
                        {finding.location?.file && (
                          <p className="text-slate-500 text-xs mt-2 flex items-center gap-1">
                            📁
                            {finding.source_url ? (
                              <a
                                href={finding.source_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-blue-400 hover:underline flex items-center gap-1"
                              >
                                {finding.location.file}
                                {finding.location.line && `:${finding.location.line}`}
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            ) : (
                              <span>
                                {finding.location.file}
                                {finding.location.line && `:${finding.location.line}`}
                              </span>
                            )}
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                ))
            )}
          </div>
        )}

        {activeTab === 'details' && (
          <div className="grid md:grid-cols-2 gap-6">
            {/* Package metadata */}
            <div className="card">
              <h3 className="text-lg font-semibold text-white mb-4">Package Information</h3>
              <dl className="space-y-3">
                <div>
                  <dt className="text-xs text-slate-500 uppercase">Name</dt>
                  <dd className="text-white">{report.package_name}</dd>
                </div>
                <div>
                  <dt className="text-xs text-slate-500 uppercase">Version</dt>
                  <dd className="text-white">{report.package_version}</dd>
                </div>
                {report.package_metadata?.author && (
                  <div>
                    <dt className="text-xs text-slate-500 uppercase">Author</dt>
                    <dd className="text-white">{report.package_metadata.author}</dd>
                  </div>
                )}
                {report.package_metadata?.license && (
                  <div>
                    <dt className="text-xs text-slate-500 uppercase">License</dt>
                    <dd className="text-white">
                      <TruncatedText text={report.package_metadata.license} maxLength={150} />
                    </dd>
                  </div>
                )}
                {report.package_metadata?.requires_python && (
                  <div>
                    <dt className="text-xs text-slate-500 uppercase">Python Requirement</dt>
                    <dd className="text-white">{report.package_metadata.requires_python}</dd>
                  </div>
                )}
              </dl>
            </div>

            {/* Dependencies */}
            <div className="card">
              <h3 className="text-lg font-semibold text-white mb-4">
                Dependencies ({report.dependencies.length})
              </h3>
              {report.dependencies.length === 0 ? (
                <p className="text-slate-400">No dependencies</p>
              ) : (
                <ul className="space-y-2 max-h-64 overflow-y-auto">
                  {report.dependencies.map((dep, i) => (
                    <li key={i} className="flex items-center gap-2 text-sm">
                      <GitBranch className="w-4 h-4 text-slate-500" />
                      <span className="text-white">{dep.name}</span>
                      <span className="text-slate-500">{dep.version_spec.split(dep.name)[1]}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Maintainers */}
            <div className="card">
              <h3 className="text-lg font-semibold text-white mb-4">
                Maintainers ({report.maintainers.length})
              </h3>
              {report.maintainers.length === 0 ? (
                <p className="text-slate-400">No maintainer information</p>
              ) : (
                <ul className="space-y-2">
                  {report.maintainers.map((m, i) => (
                    <li key={i} className="flex items-center gap-2">
                      <User className="w-4 h-4 text-slate-500" />
                      <span className="text-white">{m.username}</span>
                      {m.email && (
                        <span className="text-slate-500 text-sm">{m.email}</span>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Repository */}
            {report.repository && (
              <div className="card">
                <h3 className="text-lg font-semibold text-white mb-4">Repository</h3>
                <dl className="space-y-3">
                  <div>
                    <dt className="text-xs text-slate-500 uppercase mb-1">URL</dt>
                    <dd className="flex items-center gap-2 group">
                      <a
                        href={report.repository.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-400 hover:underline flex items-center gap-1 break-all"
                      >
                        {report.repository.url}
                        <ExternalLink className="w-3 h-3 flex-shrink-0" />
                      </a>
                      <button
                        onClick={() => copyToClipboard(report.repository!.url, 'repo-url-details')}
                        className="text-slate-500 hover:text-white transition-colors opacity-0 group-hover:opacity-100 flex-shrink-0"
                        title="Copy repository URL"
                      >
                        {copiedId === 'repo-url-details' ? (
                          <Check className="w-3 h-3 text-green-400" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </dd>
                  </div>
                  <div className="grid grid-cols-3 gap-4 pt-2">
                    <div>
                      <dt className="text-xs text-slate-500 uppercase">Stars</dt>
                      <dd className="text-white font-medium">{report.repository.stars}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-slate-500 uppercase">Forks</dt>
                      <dd className="text-white font-medium">{report.repository.forks}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-slate-500 uppercase">Issues</dt>
                      <dd className="text-white font-medium">{report.repository.open_issues}</dd>
                    </div>
                  </div>
                </dl>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-4 mt-8">
        <div className="container mx-auto px-4 text-center text-slate-500 text-sm">
          PyShield - Security audit tool for PyPI packages
        </div>
      </footer>
    </div>
  );
}
