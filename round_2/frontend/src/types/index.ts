// API Types

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'safe';
export type AuditStatus = 'queued' | 'processing' | 'completed' | 'failed';

export interface Finding {
  id: string;
  category: string;
  severity: SeverityLevel;
  title: string;
  description: string;
  location?: {
    file?: string;
    line?: number;
  };
  remediation?: string;
  references: string[];
  metadata: Record<string, unknown>;
  source_url?: string;
}

export interface CategoryResult {
  category: string;
  score: number;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  findings: Finding[];
  analysis_duration_ms: number;
}

export interface VulnerabilityInfo {
  cve_id?: string;
  osv_id?: string;
  title: string;
  severity: SeverityLevel;
  cvss_score?: number;
  affected_versions: string;
  fixed_version?: string;
  description: string;
  references: string[];
  published_date?: string;
}

export interface DependencyInfo {
  name: string;
  version_spec: string;
  is_direct: boolean;
  vulnerability_count: number;
  risk_level: RiskLevel;
  last_updated?: string;
  is_abandoned: boolean;
}

export interface MaintainerInfo {
  username: string;
  email?: string;
  package_count?: number;
  trust_signals: Record<string, unknown>;
}

export interface RepositoryInfo {
  url: string;
  platform: string;
  stars: number;
  forks: number;
  open_issues: number;
  last_commit?: string;
  contributors_count: number;
  is_archived: boolean;
  matches_package: boolean;
}

export interface PackageMetadata {
  name: string;
  version: string;
  summary?: string;
  author?: string;
  author_email?: string;
  license?: string;
  home_page?: string;
  project_url?: string;
  requires_python?: string;
  classifiers: string[];
  requires_dist: string[];
  release_date?: string;
}

export interface AuditReport {
  audit_id: string;
  package_name: string;
  package_version: string;
  requested_at: string;
  completed_at?: string;
  analysis_duration_ms: number;
  overall_score: number;
  risk_level: RiskLevel;
  summary: string;
  recommendation: string;
  package_metadata?: PackageMetadata;
  categories: Record<string, CategoryResult>;
  vulnerabilities: VulnerabilityInfo[];
  dependencies: DependencyInfo[];
  maintainers: MaintainerInfo[];
  repository?: RepositoryInfo;
  all_findings: Finding[];
  stats: {
    total_findings: number;
    total_duration_ms: number;
    analyzers_run: number;
    severity_counts: Record<SeverityLevel, number>;
  };
}

export interface AuditStatusResponse {
  audit_id: string;
  status: AuditStatus;
  progress: number;
  current_analyzer?: string;
  completed_analyzers: string[];
  error_message?: string;
  risk_level?: RiskLevel;
}

export interface AuditStartResponse {
  audit_id: string;
  status: AuditStatus;
  message: string;
}
