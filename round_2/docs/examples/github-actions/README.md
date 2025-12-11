# PyShield GitHub Actions Integration

Integrate PyShield security scanning into your CI/CD pipeline to catch vulnerabilities before they reach production.

## Overview

The PyShield GitHub Actions integration provides automated security scanning for Python dependencies in your repository. It scans packages listed in `requirements.txt` and fails the build if vulnerabilities exceed your configured threshold.

**Features:**
- Automated scanning on every push and pull request
- Configurable severity thresholds (critical, high, medium, low)
- Detailed scan results as downloadable artifacts
- Clear, actionable output in CI logs
- Support for both public PyShield service and self-hosted instances

## Quick Start

### 1. Add the Workflow to Your Repository

Copy the example workflow file to your repository:

```bash
mkdir -p .github/workflows
curl -o .github/workflows/pyshield-scan.yml \
  https://raw.githubusercontent.com/your-org/pyshield/main/docs/examples/github-actions/pyshield-scan.yml
```

Or manually create `.github/workflows/pyshield-scan.yml` with the [example workflow](pyshield-scan.yml).

### 2. Configure (Optional)

Edit the workflow file to customize:

```yaml
env:
  # Update for self-hosted PyShield instance
  PYSHIELD_API: "https://api.pyshield.dev/api/v1"

  # Minimum severity to fail CI
  SEVERITY_THRESHOLD: "high"  # Options: critical, high, medium, low
```

### 3. Commit and Push

```bash
git add .github/workflows/pyshield-scan.yml
git commit -m "Add PyShield security scanning"
git push
```

The workflow will run automatically on:
- Every push to `main` or `master` branch
- Every pull request to `main` or `master` branch

## Configuration Options

### Environment Variables

#### `PYSHIELD_API`
- **Description**: Base URL of PyShield API endpoint (including `/api/v1` suffix)
- **Default**: `https://api.pyshield.dev/api/v1` (public service)
- **Self-hosted**: Update to your instance URL (e.g., `https://pyshield.yourcompany.com/api/v1`)

#### `SEVERITY_THRESHOLD`
- **Description**: Minimum severity level to fail CI
- **Options**: `critical`, `high`, `medium`, `low`
- **Default**: `high`
- **Behavior**:
  - `critical`: Only fail on critical vulnerabilities
  - `high`: Fail on high or critical vulnerabilities (recommended)
  - `medium`: Fail on medium, high, or critical vulnerabilities
  - `low`: Fail on any vulnerability (strictest)

### Python Version Matrix

To test across multiple Python versions, modify the workflow:

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.11', '3.12', '3.13']

    steps:
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      # ... rest of steps
```

## Understanding Scan Output

### Success Output

```
Scanning 5 packages from requirements.txt...

[1/5] Scanning requests...
  → SAFE (Score: 5/100)
[2/5] Scanning flask...
  → LOW RISK (Score: 15/100)
[3/5] Scanning django...
  → SAFE (Score: 8/100)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PyShield Security Scan Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ requests@2.31.0 - SAFE (Score: 5/100)
✅ flask@3.0.0 - LOW RISK (Score: 15/100)
   1 finding(s)
✅ django@5.0.0 - SAFE (Score: 8/100)

Summary: 3 package(s) scanned
  ✓ Safe/Low: 3

Threshold: high

Result: PASSED ✅

All packages meet security threshold.
```

### Failure Output

```
[4/5] Scanning pillow...
  → HIGH RISK (Score: 75/100)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PyShield Security Scan Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

❌ pillow@8.0.0 - HIGH RISK (Score: 75/100)
   4 finding(s)

Summary: 1 package(s) scanned
  ✗ High/Critical: 1

Threshold: high

Result: FAILED ❌

Packages exceeding threshold:
  - pillow@8.0.0 (HIGH RISK)

Review findings and update dependencies before merging.
```

## Advanced Usage

### Scan Only Changed Dependencies

To optimize CI time, scan only dependencies that changed in a PR:

```yaml
- name: Get changed files
  id: changed-files
  uses: tj-actions/changed-files@v41
  with:
    files: requirements.txt

- name: Scan dependencies
  if: steps.changed-files.outputs.any_changed == 'true'
  run: |
    python scan.py requirements.txt --threshold ${{ env.SEVERITY_THRESHOLD }}
```

### Custom Threshold Per Package

Create a configuration file `.pyshield.yml`:

```yaml
thresholds:
  default: high
  exceptions:
    pillow: critical  # Only fail on critical for pillow
    django: medium    # Stricter for django
```

Modify the scan script to read this configuration.

### Generate SBOM in CI

Add SBOM generation step:

```yaml
- name: Generate SBOMs for all packages
  run: |
    mkdir -p sboms
    for package in $(python -c "import sys; [print(line.split('==')[0]) for line in open('requirements.txt') if line.strip() and not line.startswith('#')]"); do
      echo "Generating SBOM for $package..."
      # Start audit and get SBOM
      curl -X POST "${{ env.PYSHIELD_API }}/api/v1/audit" \
        -H "Content-Type: application/json" \
        -d "{\"package_name\": \"$package\"}" \
        -o audit.json

      audit_id=$(jq -r '.audit_id' audit.json)

      # Wait for completion
      sleep 30

      # Download SBOM
      curl "${{ env.PYSHIELD_API }}/api/v1/audit/$audit_id/sbom" \
        -o "sboms/${package}.cdx.json"
    done

- name: Upload SBOMs
  uses: actions/upload-artifact@v4
  with:
    name: sbom-collection
    path: sboms/
    retention-days: 90
```

### Post PR Comments with Results

Requires repository write permissions:

```yaml
permissions:
  contents: read
  pull-requests: write

# ... after scan step

- name: Post PR comment with results
  if: github.event_name == 'pull_request' && always()
  uses: actions/github-script@v7
  with:
    script: |
      const fs = require('fs');
      const files = fs.readdirSync('.')
                     .filter(f => f.startsWith('pyshield-scan-'));

      if (files.length === 0) return;

      const data = JSON.parse(fs.readFileSync(files[0], 'utf8'));

      // Format results
      let comment = '## 🛡️ PyShield Security Scan Results\n\n';

      const results = data.results || [];
      const passed = results.filter(r => r.status === 'success' &&
                                    r.report.risk_level.toLowerCase() !== 'high' &&
                                    r.report.risk_level.toLowerCase() !== 'critical');
      const failed = results.filter(r => r.status === 'success' &&
                                   (r.report.risk_level.toLowerCase() === 'high' ||
                                    r.report.risk_level.toLowerCase() === 'critical'));

      if (failed.length > 0) {
        comment += '### ❌ Failed\n\n';
        failed.forEach(r => {
          comment += `- **${r.report.package_name}@${r.report.package_version}**: ${r.report.risk_level.toUpperCase()} RISK (Score: ${r.report.overall_score}/100)\n`;
        });
        comment += '\n';
      }

      if (passed.length > 0) {
        comment += `### ✅ Passed (${passed.length} packages)\n\n`;
      }

      comment += `**Threshold**: ${data.threshold}\n`;
      comment += `**Total Packages**: ${results.length}\n`;

      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: comment
      });
```

## Troubleshooting

### Rate Limiting

**Issue**: PyShield public API has rate limits (10 audits/hour/IP by default).

**Solutions**:
1. **Self-host PyShield**: Deploy your own instance with custom rate limits
2. **Cache results**: Store scan results and only re-scan when dependencies change
3. **Batch scanning**: Use the batch API endpoint if available (future feature)

**Example with caching**:

```yaml
- name: Cache scan results
  uses: actions/cache@v3
  with:
    path: .pyshield-cache
    key: pyshield-${{ hashFiles('requirements.txt') }}

- name: Scan with cache
  run: |
    if [ -f .pyshield-cache/results.json ]; then
      echo "Using cached results"
      cp .pyshield-cache/results.json ./pyshield-scan-results.json
    else
      python scan.py requirements.txt
      mkdir -p .pyshield-cache
      cp pyshield-scan-*.json .pyshield-cache/results.json
    fi
```

### Private Dependencies

**Issue**: PyShield only scans public PyPI packages.

**Behavior**: Private packages are skipped with a warning:

```
[3/5] Scanning my-private-package...
  → ERROR: Package not found on PyPI
```

**Solutions**:
1. Exclude private packages from scanning
2. Self-host PyShield with access to your private PyPI index
3. Scan only public dependencies

### API Unavailable

**Issue**: PyShield API is unreachable or down.

**Error**:
```
Error starting audit for requests: Connection refused
```

**Solutions**:
1. Check `PYSHIELD_API` URL is correct
2. Verify network access from GitHub Actions runners
3. Add retry logic with exponential backoff
4. Use `continue-on-error: true` to make scan non-blocking

**Example with retries**:

```yaml
- name: Scan with retries
  uses: nick-fields/retry@v2
  with:
    timeout_minutes: 10
    max_attempts: 3
    retry_wait_seconds: 30
    command: python scan.py requirements.txt --threshold ${{ env.SEVERITY_THRESHOLD }}
```

### Scan Timeout

**Issue**: Large dependency lists take too long to scan.

**Solutions**:
1. Increase `--max-wait` parameter: `python scan.py requirements.txt --max-wait 300`
2. Scan in parallel (modify scan.py to use threading)
3. Split into multiple jobs

### No requirements.txt Found

**Issue**: Repository doesn't use `requirements.txt`.

**Solutions**:

For `pyproject.toml`:
```yaml
- name: Extract dependencies
  run: |
    pip install toml
    python -c "import toml; deps = toml.load('pyproject.toml')['project']['dependencies']; open('requirements.txt', 'w').write('\n'.join(deps))"

- name: Scan dependencies
  run: python scan.py requirements.txt
```

For `Pipfile`:
```yaml
- name: Generate requirements.txt
  run: |
    pip install pipenv
    pipenv requirements > requirements.txt

- name: Scan dependencies
  run: python scan.py requirements.txt
```

## Security Considerations

### API Token Management

If PyShield requires authentication (self-hosted with auth):

```yaml
env:
  PYSHIELD_API: "https://your-pyshield.com/api/v1"
  PYSHIELD_TOKEN: ${{ secrets.PYSHIELD_TOKEN }}

# Modify scan script to include token in requests
```

**Never commit tokens to repository**. Use GitHub Secrets:
1. Go to repository Settings → Secrets and variables → Actions
2. Add `PYSHIELD_TOKEN` secret
3. Reference in workflow with `${{ secrets.PYSHIELD_TOKEN }}`

### Self-Hosted vs Public Service

**Public Service** (api.pyshield.dev):
- ✅ No setup required
- ✅ Always up-to-date
- ❌ Rate limits
- ❌ Data sent to external service
- ❌ Internet access required

**Self-Hosted**:
- ✅ No rate limits (configurable)
- ✅ Data stays internal
- ✅ Custom configuration
- ✅ Works in air-gapped environments
- ❌ Requires setup and maintenance
- ❌ Must keep updated

**Recommendation**: Use public service for open-source projects, self-host for enterprise/private projects.

### Workflow Permissions

Minimal required permissions:

```yaml
permissions:
  contents: read  # Required to checkout code
```

Additional permissions for PR comments:

```yaml
permissions:
  contents: read
  pull-requests: write  # Required to post comments
```

### Handling Secrets in Dependencies

**Issue**: Scanning might expose private package names or versions.

**Mitigation**:
1. Use self-hosted PyShield with restricted access
2. Redact package names in logs if needed
3. Store scan results artifacts with limited retention

## Example Workflows

### Basic Workflow

Scan on every push and PR, fail on high/critical:

```yaml
name: PyShield Security Scan

on: [push, pull_request]

env:
  PYSHIELD_API: "https://api.pyshield.dev/api/v1"
  SEVERITY_THRESHOLD: "high"

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install requests packaging
      - run: curl -O https://raw.githubusercontent.com/your-org/pyshield/main/docs/examples/github-actions/scan.py
      - run: python scan.py requirements.txt --threshold ${{ env.SEVERITY_THRESHOLD }}
```

### Scheduled Weekly Scan

Scan dependencies weekly even without code changes:

```yaml
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 9 * * 1'  # Every Monday at 9 AM UTC
```

### Multi-Project Monorepo

Scan multiple sub-projects:

```yaml
jobs:
  scan-backend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan backend
        run: python scan.py backend/requirements.txt

  scan-frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan frontend (if using Python deps)
        run: python scan.py frontend/requirements.txt
```

## Integration with Other Tools

### Dependency Update PRs (Dependabot/Renovate)

PyShield scans automatically run on Dependabot/Renovate PRs, providing security validation before merging dependency updates.

### Slack Notifications

Add Slack notification on failure:

```yaml
- name: Notify Slack on failure
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    webhook-url: ${{ secrets.SLACK_WEBHOOK }}
    payload: |
      {
        "text": "PyShield scan failed for ${{ github.repository }}",
        "blocks": [
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "❌ *PyShield Security Scan Failed*\n*Repository:* ${{ github.repository }}\n*Branch:* ${{ github.ref }}\n*Commit:* ${{ github.sha }}\n\n<${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View Details>"
            }
          }
        ]
      }
```

### SBOM Management Tools

Upload generated SBOMs to tools like DependencyTrack:

```yaml
- name: Upload to DependencyTrack
  run: |
    curl -X POST "https://dependencytrack.yourcompany.com/api/v1/bom" \
      -H "X-API-Key: ${{ secrets.DTRACK_API_KEY }}" \
      -H "Content-Type: multipart/form-data" \
      -F "project=${{ github.repository }}" \
      -F "bom=@pyshield-sbom-${package}.cdx.json"
```

## Support

For issues with the GitHub Actions integration:

1. Check [Troubleshooting](#troubleshooting) section
2. Review workflow logs in Actions tab
3. Open issue at https://github.com/your-org/pyshield/issues
4. Include:
   - Workflow file
   - Error messages
   - Scan script version
   - PyShield API version (self-hosted)

## License

This example integration is provided as-is under the same license as PyShield.
