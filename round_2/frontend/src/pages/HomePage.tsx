import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Search, AlertTriangle, Code, Package, Clock } from 'lucide-react';
import { startAudit, getAuditStatus } from '../services/api';

interface RecentAudit {
  packageName: string;
  auditId: string;
  timestamp: number;
  riskLevel?: string;
}

export default function HomePage() {
  const [packageName, setPackageName] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [currentAnalyzer, setCurrentAnalyzer] = useState<string | null>(null);
  const [recentAudits, setRecentAudits] = useState<RecentAudit[]>([]);
  const navigate = useNavigate();

  // Load recent audits from localStorage
  useEffect(() => {
    const stored = localStorage.getItem('pyshield_recent_audits');
    if (stored) {
      try {
        setRecentAudits(JSON.parse(stored));
      } catch (e) {
        // Invalid JSON, ignore
      }
    }
  }, []);

  // Save audit to recent history
  const saveToRecent = (packageName: string, auditId: string, riskLevel?: string) => {
    const newAudit: RecentAudit = {
      packageName,
      auditId,
      timestamp: Date.now(),
      riskLevel,
    };

    const updated = [newAudit, ...recentAudits.filter(a => a.packageName !== packageName)].slice(0, 10);
    setRecentAudits(updated);
    localStorage.setItem('pyshield_recent_audits', JSON.stringify(updated));
  };

  const clearHistory = () => {
    setRecentAudits([]);
    localStorage.removeItem('pyshield_recent_audits');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!packageName.trim()) return;

    setIsLoading(true);
    setError(null);
    setProgress(0);

    try {
      // Start the audit
      const response = await startAudit(packageName.trim());
      const auditId = response.audit_id;

      // Poll for status
      const pollInterval = setInterval(async () => {
        try {
          const status = await getAuditStatus(auditId);
          setProgress(status.progress);
          setCurrentAnalyzer(status.current_analyzer || null);

          if (status.status === 'completed') {
            clearInterval(pollInterval);
            saveToRecent(packageName.trim(), auditId, status.risk_level);
            navigate(`/report/${auditId}`);
          } else if (status.status === 'failed') {
            clearInterval(pollInterval);
            setError(status.error_message || 'Audit failed');
            setIsLoading(false);
          }
        } catch (err) {
          clearInterval(pollInterval);
          setError(err instanceof Error ? err.message : 'Failed to check status');
          setIsLoading(false);
        }
      }, 1000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start audit');
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur">
        <div className="container mx-auto px-4 py-4 flex items-center gap-3">
          <Shield className="w-8 h-8 text-blue-500" />
          <h1 className="text-xl font-bold text-white">PyShield</h1>
          <span className="text-slate-500 text-sm">PyPI Security Audit</span>
        </div>
      </header>

      {/* Main content */}
      <main className="flex-1 flex flex-col items-center justify-center px-4 py-12">
        <div className="w-full max-w-2xl">
          {/* Hero */}
          <div className="text-center mb-12">
            <div className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-blue-500/10 mb-6">
              <Shield className="w-10 h-10 text-blue-500" />
            </div>
            <h2 className="text-3xl sm:text-4xl font-bold text-white mb-4">
              Audit PyPI Packages for Security Risks
            </h2>
            <p className="text-base sm:text-lg text-slate-400 max-w-lg mx-auto">
              Analyze packages for vulnerabilities, typosquatting, malicious code,
              and supply chain risks before you install.
            </p>
          </div>

          {/* Search form */}
          <form onSubmit={handleSubmit} className="relative mb-8">
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="flex-1 relative">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                <input
                  type="text"
                  value={packageName}
                  onChange={(e) => setPackageName(e.target.value)}
                  placeholder="Enter package name (e.g., requests, django, flask)"
                  className="w-full pl-12 pr-4 py-3 sm:py-4 bg-slate-800 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-base sm:text-lg"
                  disabled={isLoading}
                />
              </div>
              <button
                type="submit"
                disabled={isLoading || !packageName.trim()}
                className="px-6 sm:px-8 py-3 sm:py-4 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-colors touch-manipulation"
              >
                {isLoading ? 'Auditing...' : 'Audit'}
              </button>
            </div>
          </form>

          {/* Recent Audits */}
          {recentAudits.length > 0 && !isLoading && (
            <div className="mb-8">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Clock className="w-4 h-4 text-slate-400" />
                  <h3 className="text-sm font-medium text-slate-300">Recent Audits</h3>
                </div>
                <button
                  onClick={clearHistory}
                  className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
                >
                  Clear history
                </button>
              </div>
              <div className="grid gap-2">
                {recentAudits.slice(0, 5).map((audit) => (
                  <button
                    key={audit.auditId}
                    onClick={() => navigate(`/report/${audit.auditId}`)}
                    className="flex items-center justify-between px-4 py-3 bg-slate-800/50 hover:bg-slate-800 border border-slate-700/50 rounded-lg transition-colors text-left group"
                  >
                    <div className="flex items-center gap-3">
                      <Package className="w-4 h-4 text-slate-400 group-hover:text-blue-400 transition-colors" />
                      <span className="text-white font-medium">{audit.packageName}</span>
                      {audit.riskLevel && (
                        <span
                          className={`text-xs px-2 py-0.5 rounded-full ${
                            audit.riskLevel === 'critical'
                              ? 'bg-red-900/30 text-red-400'
                              : audit.riskLevel === 'high'
                              ? 'bg-orange-900/30 text-orange-400'
                              : audit.riskLevel === 'medium'
                              ? 'bg-yellow-900/30 text-yellow-400'
                              : audit.riskLevel === 'low'
                              ? 'bg-lime-900/30 text-lime-400'
                              : 'bg-green-900/30 text-green-400'
                          }`}
                        >
                          {audit.riskLevel}
                        </span>
                      )}
                    </div>
                    <span className="text-xs text-slate-500">
                      {new Date(audit.timestamp).toLocaleDateString()}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Progress */}
          {isLoading && (
            <div className="card mb-8">
              <div className="flex items-center gap-4 mb-4">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
                <div>
                  <p className="text-white font-medium">Analyzing {packageName}...</p>
                  <p className="text-slate-400 text-sm">
                    {currentAnalyzer ? `Running: ${currentAnalyzer}` : 'Starting analysis...'}
                  </p>
                </div>
              </div>
              <div className="w-full bg-slate-700 rounded-full h-2">
                <div
                  className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${progress}%` }}
                ></div>
              </div>
              <p className="text-right text-sm text-slate-400 mt-2">{progress}%</p>
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="bg-red-900/20 border border-red-800 rounded-xl p-4 mb-8 flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-red-400 font-medium">Error</p>
                <p className="text-red-300 text-sm">{error}</p>
              </div>
            </div>
          )}

          {/* Try These */}
          {!isLoading && recentAudits.length === 0 && (
            <div className="mb-8">
              <h3 className="text-sm font-medium text-slate-300 mb-3">Popular Packages to Try:</h3>
              <div className="flex flex-wrap gap-2">
                {['requests', 'flask', 'django', 'numpy', 'pandas', 'pytest'].map((pkg) => (
                  <button
                    key={pkg}
                    onClick={() => setPackageName(pkg)}
                    className="px-4 py-2 bg-slate-800/50 hover:bg-blue-600/20 border border-slate-700 hover:border-blue-600 rounded-lg text-slate-300 hover:text-blue-400 text-sm transition-colors"
                  >
                    {pkg}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Features */}
          <div className="grid sm:grid-cols-2 md:grid-cols-3 gap-4">
            <div className="card fade-in" style={{ animationDelay: '0.1s' }}>
              <AlertTriangle className="w-8 h-8 text-orange-400 mb-3" />
              <h3 className="text-white font-semibold mb-2">12 Security Analyzers</h3>
              <p className="text-slate-400 text-sm">
                Comprehensive analysis including vulnerabilities, typosquatting, behavioral patterns, and ML anomaly detection.
              </p>
            </div>
            <div className="card fade-in" style={{ animationDelay: '0.2s' }}>
              <Code className="w-8 h-8 text-purple-400 mb-3" />
              <h3 className="text-white font-semibold mb-2">AST-Based Analysis</h3>
              <p className="text-slate-400 text-sm">
                Advanced static code analysis detecting obfuscation, dangerous functions, and malicious patterns using AST parsing.
              </p>
            </div>
            <div className="card fade-in sm:col-span-2 md:col-span-1" style={{ animationDelay: '0.3s' }}>
              <Package className="w-8 h-8 text-green-400 mb-3" />
              <h3 className="text-white font-semibold mb-2">Supply Chain Focus</h3>
              <p className="text-slate-400 text-sm">
                Identify dependency confusion, version manipulation, and namespace squatting attacks.
              </p>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-4">
        <div className="container mx-auto px-4 text-center text-slate-500 text-sm">
          PyShield - Security audit tool for PyPI packages
        </div>
      </footer>
    </div>
  );
}
