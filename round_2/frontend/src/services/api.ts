import type { AuditStartResponse, AuditStatusResponse, AuditReport } from '../types';

const API_BASE = '/api/v1';

export async function startAudit(packageName: string, version?: string): Promise<AuditStartResponse> {
  const response = await fetch(`${API_BASE}/audit`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      package_name: packageName,
      version: version || null,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(error.detail || 'Failed to start audit');
  }

  return response.json();
}

export async function getAuditStatus(auditId: string): Promise<AuditStatusResponse> {
  const response = await fetch(`${API_BASE}/audit/${auditId}`);

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(error.detail || 'Failed to get audit status');
  }

  return response.json();
}

export async function getAuditReport(auditId: string): Promise<AuditReport> {
  const response = await fetch(`${API_BASE}/audit/${auditId}/report`);

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(error.detail || 'Failed to get audit report');
  }

  return response.json();
}

export async function getAuditSBOM(auditId: string): Promise<any> {
  const response = await fetch(`${API_BASE}/audit/${auditId}/sbom`);

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(error.detail || 'Failed to get SBOM');
  }

  return response.json();
}

export async function checkHealth(): Promise<boolean> {
  try {
    const response = await fetch(`${API_BASE}/health`);
    return response.ok;
  } catch {
    return false;
  }
}
