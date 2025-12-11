import { useState } from 'react';
import { ChevronDown, ChevronUp, FileCode, ExternalLink, Copy, Check } from 'lucide-react';
import type { Finding } from '../types';
import SeverityBadge from './SeverityBadge';

interface FindingItemProps {
  finding: Finding;
}

function formatMetadataValue(value: any): string | null {
  if (value === null || value === undefined) return 'N/A';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'number') {
    // Format numbers with decimals nicely
    if (Number.isInteger(value)) {
      return value.toLocaleString();
    }
    return value.toFixed(4);
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return 'None';
    if (value.length <= 3) return value.join(', ');
    return `${value.slice(0, 3).join(', ')} (+${value.length - 3} more)`;
  }
  if (typeof value === 'object') {
    // Return null to signal that this should be rendered as nested
    return null;
  }
  return String(value);
}

function renderNestedObject(obj: Record<string, any>) {
  return (
    <div className="ml-4 mt-1 space-y-1">
      {Object.entries(obj).map(([nestedKey, nestedValue]) => {
        const formattedValue = formatMetadataValue(nestedValue);
        return (
          <div key={nestedKey} className="flex items-start gap-2">
            <span className="text-slate-500 text-xs">
              {nestedKey.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}:
            </span>
            <span className="text-slate-300 text-xs font-mono">
              {formattedValue !== null ? formattedValue : JSON.stringify(nestedValue)}
            </span>
          </div>
        );
      })}
    </div>
  );
}

export default function FindingItem({ finding }: FindingItemProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyToClipboard = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  return (
    <div className="bg-slate-900/50 rounded-lg border border-slate-700/50 overflow-hidden">
      <div className="p-3">
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="w-full flex items-start gap-3 text-left hover:bg-slate-800/30 transition-colors rounded p-2 -m-2"
        >
          <SeverityBadge severity={finding.severity} size="sm" />
          <div className="flex-1 min-w-0">
            <p className="text-white font-medium text-sm">{finding.title}</p>
          </div>
          {isExpanded ? (
            <ChevronUp className="w-4 h-4 text-slate-400 flex-shrink-0" />
          ) : (
            <ChevronDown className="w-4 h-4 text-slate-400 flex-shrink-0" />
          )}
        </button>

        {finding.location?.file && (
          <div className="text-slate-500 text-xs mt-2 flex items-center gap-1 ml-1">
            <FileCode className="w-3 h-3" />
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
          </div>
        )}
      </div>

      {isExpanded && (
        <div className="px-3 pb-3 space-y-3">
          {/* Description */}
          <div>
            <h4 className="text-xs font-semibold text-slate-400 uppercase mb-1">Description</h4>
            <p className="text-sm text-slate-300">{finding.description}</p>
          </div>

          {/* Remediation */}
          {finding.remediation && (
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase mb-1">Remediation</h4>
              <p className="text-sm text-slate-300">{finding.remediation}</p>
            </div>
          )}

          {/* References */}
          {finding.references.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase mb-1">References</h4>
              <ul className="space-y-1">
                {finding.references.slice(0, 3).map((ref, i) => {
                  const cveMatch = ref.match(/CVE-\d{4}-\d+/);
                  const copyId = `ref-${finding.id}-${i}`;

                  return (
                    <li key={i} className="flex items-center gap-2 group">
                      <a
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-blue-400 hover:underline flex items-center gap-1 flex-1 min-w-0"
                      >
                        {ref.length > 60 ? `${ref.substring(0, 60)}...` : ref}
                        <ExternalLink className="w-3 h-3 flex-shrink-0" />
                      </a>
                      {cveMatch && (
                        <button
                          onClick={() => copyToClipboard(cveMatch[0], `cve-${copyId}`)}
                          className="text-slate-500 hover:text-white transition-colors opacity-0 group-hover:opacity-100 flex-shrink-0"
                          title={`Copy ${cveMatch[0]}`}
                        >
                          {copiedId === `cve-${copyId}` ? (
                            <Check className="w-3 h-3 text-green-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      )}
                      <button
                        onClick={() => copyToClipboard(ref, copyId)}
                        className="text-slate-500 hover:text-white transition-colors opacity-0 group-hover:opacity-100 flex-shrink-0"
                        title="Copy URL"
                      >
                        {copiedId === copyId ? (
                          <Check className="w-3 h-3 text-green-400" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}

          {/* Metadata */}
          {Object.keys(finding.metadata).length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase mb-1">Details</h4>
              <div className="bg-slate-800 rounded p-2 space-y-1">
                {Object.entries(finding.metadata).map(([key, value]) => {
                  // Special handling for vulnerability_ids
                  if (key === 'vulnerability_ids' && Array.isArray(value)) {
                    return (
                      <div key={key} className="text-xs">
                        <div className="flex items-start gap-2">
                          <span className="text-slate-400 font-medium min-w-[120px]">
                            Vulnerability IDs:
                          </span>
                          <div className="flex-1">
                            <div className="flex flex-wrap gap-2">
                              {value.map((id: string, idx: number) => {
                                const copyId = `vuln-${finding.id}-${idx}`;
                                // Create OSV.dev URL for the vulnerability
                                const osvUrl = `https://osv.dev/vulnerability/${id}`;
                                return (
                                  <div key={idx} className="flex items-center gap-1 group">
                                    <a
                                      href={osvUrl}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-blue-400 hover:underline font-mono text-xs flex items-center gap-1"
                                      title={`View ${id} on OSV.dev`}
                                    >
                                      {id}
                                      <ExternalLink className="w-3 h-3" />
                                    </a>
                                    <button
                                      onClick={() => copyToClipboard(id, copyId)}
                                      className="text-slate-500 hover:text-white transition-colors opacity-0 group-hover:opacity-100"
                                      title={`Copy ${id}`}
                                    >
                                      {copiedId === copyId ? (
                                        <Check className="w-3 h-3 text-green-400" />
                                      ) : (
                                        <Copy className="w-3 h-3" />
                                      )}
                                    </button>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  }

                  // Default handling for other metadata
                  const formattedValue = formatMetadataValue(value);
                  return (
                    <div key={key} className="text-xs">
                      <div className="flex items-start gap-2">
                        <span className="text-slate-400 font-medium min-w-[120px]">
                          {key.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}:
                        </span>
                        {formattedValue !== null ? (
                          <span className="text-slate-300 flex-1">
                            {formattedValue}
                          </span>
                        ) : (
                          <span className="text-slate-300 flex-1">
                            {/* Render nested object */}
                            {typeof value === 'object' && value !== null && !Array.isArray(value) ? (
                              renderNestedObject(value)
                            ) : (
                              JSON.stringify(value)
                            )}
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
