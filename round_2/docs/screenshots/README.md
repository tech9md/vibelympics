# Screenshots Guide

This folder contains screenshots for the PyShield documentation.

## Required Screenshots

To complete the documentation, capture the following screenshots:

### 1. Homepage (`homepage.png`)
- Show the main landing page with:
  - PyShield logo/title
  - Search input box
  - Popular package suggestions
  - Feature cards

**Recommended size:** 1920x1080 or 1280x720

### 2. Search with Suggestions (`search-suggestions.png`)
- Show the search box with:
  - User typing a package name
  - Auto-complete suggestions appearing
  - Recent search history

### 3. Analysis Progress (`analysis-progress.png`)
- Show the progress screen during analysis:
  - Loading spinner/animation
  - Progress percentage
  - Status messages ("Analyzing vulnerabilities...", etc.)

### 4. Report Overview (`report-overview.png`)
- Show the top portion of a completed report:
  - Package name and version
  - Overall risk score gauge
  - Risk level badge (Critical/High/Medium/Low/Safe)
  - Summary text

### 5. Category Cards (`category-cards.png`)
- Show the category breakdown:
  - Multiple category cards (Vulnerability, Static Code, etc.)
  - Scores for each category
  - Finding counts with severity badges

### 6. Finding Details (`finding-details.png`)
- Show individual findings:
  - Severity badge
  - Finding title and description
  - Remediation advice
  - References/links

### 7. Severity Filters (`severity-filters.png`)
- Show the severity filter UI:
  - Filter buttons (All, Critical, High, Medium, Low, Info)
  - Live count badges on each button
  - Active filter highlighted

### 8. Risk Score Explanation Modal (`risk-score-modal.png`)
- Show the modal explaining risk calculation:
  - Formula display
  - Category weights with progress bars
  - Risk level thresholds

## Capture Instructions

1. **Start the application:**
   ```bash
   docker-compose up --build
   ```

2. **Open browser:**
   - Navigate to http://localhost:3000

3. **Capture screenshots:**
   - Use full browser window (1920x1080 recommended)
   - Hide browser UI for cleaner screenshots (F11 fullscreen)
   - Use a package with interesting results (e.g., "requests", "flask", or a suspicious package)

4. **Screenshot tools:**
   - **Windows:** Snipping Tool, Win+Shift+S
   - **Mac:** Cmd+Shift+4
   - **Linux:** gnome-screenshot, Flameshot

5. **Save files:**
   - Use the exact filenames listed above
   - Save as PNG format
   - Optimize/compress images if over 500KB each

## Example Packages for Screenshots

- **Good package (Low risk):** `requests`, `flask`, `numpy`
- **Package with findings:** Try various packages to get interesting results
- **For filter demo:** Use a package with multiple severity levels

## After Capturing

Once screenshots are saved in this folder, they will automatically be referenced in the main README.md.
