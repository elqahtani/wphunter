#!/bin/bash
# =============================================================================
# wphunter Docker Test — Full Command Reference
# =============================================================================
#
# This script documents all commands used to test wphunter with a real
# WordPress instance running in Docker. Includes both CLEAN and INFECTED
# scenarios for judol (gambling spam) detection testing.
#
# Prerequisites:
#   - Docker Desktop running
#   - Python 3.9+ with requirements installed (pip install -r requirements.txt)
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$SCRIPT_DIR"

# ═══════════════════════════════════════════════════════════════════════════════
# PART 1: SETUP
# ═══════════════════════════════════════════════════════════════════════════════

echo "============================================="
echo " Step 1: Start Docker containers"
echo "============================================="

docker compose up -d db wordpress

# Wait for WordPress to be ready
echo "Waiting for WordPress to start..."
sleep 5

echo "============================================="
echo " Step 2: Install WordPress"
echo "============================================="

docker compose run --rm wpcli core install \
  --url=http://localhost:8888 \
  --title="Test Site" \
  --admin_user=admin \
  --admin_password=admin123 \
  --admin_email=admin@test.local \
  --skip-email

echo "============================================="
echo " Step 3: Install vulnerable plugins"
echo "============================================="
# NOTE: Some old versions may no longer be available on wordpress.org.
# If a version fails, try without --version to install latest.

docker compose run --rm wpcli plugin install elementor --version=3.6.0 --activate
docker compose run --rm wpcli plugin install woocommerce --version=6.0.0 --activate
docker compose run --rm wpcli plugin install updraftplus --version=1.22.24 --activate
docker compose run --rm wpcli plugin install really-simple-ssl --version=6.0.0 --activate

echo "============================================="
echo " Step 4: Export plugin/theme lists & WP version"
echo "============================================="

docker compose run --rm wpcli plugin list --format=csv \
  2>/dev/null | grep -v "^Warning\|^PHP:" > live-plugins.csv

docker compose run --rm wpcli theme list --format=csv \
  2>/dev/null | grep -v "^Warning\|^PHP:" > live-themes.csv

docker compose run --rm wpcli core version \
  2>/dev/null | grep -v "^Warning\|^PHP:" | tr -d '\r' > wp-version.txt

echo ""
echo "Exported files:"
echo "  live-plugins.csv  — $(wc -l < live-plugins.csv) lines"
echo "  live-themes.csv   — $(wc -l < live-themes.csv) lines"
echo "  wp-version.txt    — $(cat wp-version.txt)"
echo ""

cat live-plugins.csv

# ═══════════════════════════════════════════════════════════════════════════════
# PART 2: OFFLINE SCANNING (from exported lists)
# ═══════════════════════════════════════════════════════════════════════════════

WP_VER=$(cat wp-version.txt)

echo ""
echo "============================================="
echo " Step 5: Offline scan — plugins + core"
echo "============================================="

python3 "$PROJECT_DIR/scanner.py" \
  -i live-plugins.csv \
  --wp-version "$WP_VER" \
  --no-enrich \
  || echo "Exit code: $? (expected 1 = vulns found)"

echo ""
echo "============================================="
echo " Step 6: Offline scan — themes"
echo "============================================="

python3 "$PROJECT_DIR/scanner.py" \
  -i live-themes.csv \
  --type theme \
  --no-enrich \
  || true

echo ""
echo "============================================="
echo " Step 7: Offline scan — severity filter (CI/CD mode)"
echo "============================================="

python3 "$PROJECT_DIR/scanner.py" \
  -i live-plugins.csv \
  --wp-version "$WP_VER" \
  --min-severity high \
  --no-enrich \
  --no-banner \
  || echo "Exit code: $? (expected 1 = vulns found)"

echo ""
echo "============================================="
echo " Step 8: Offline scan — JSON output"
echo "============================================="

python3 "$PROJECT_DIR/scanner.py" \
  -i live-plugins.csv \
  --wp-version "$WP_VER" \
  --no-enrich \
  --no-banner \
  -f json \
  -o scan-report.json \
  || true

echo "JSON saved to scan-report.json ($(wc -c < scan-report.json) bytes)"

# ═══════════════════════════════════════════════════════════════════════════════
# PART 3: REMOTE SCANNING (from URL) — CLEAN SITE
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo "============================================="
echo " Step 9: Remote scan — passive fingerprint"
echo "============================================="

python3 "$PROJECT_DIR/scanner.py" \
  --url http://localhost:8888 \
  --no-enrich \
  --yes \
  || echo "Exit code: $?"

echo ""
echo "============================================="
echo " Step 10: Remote scan — aggressive mode"
echo "============================================="

python3 "$PROJECT_DIR/scanner.py" \
  --url http://localhost:8888 \
  --aggressive \
  --delay 50 \
  --min-severity high \
  --no-enrich \
  --no-banner \
  --yes \
  || echo "Exit code: $? (expected 1 = vulns found)"

echo ""
echo "============================================="
echo " Step 11: Remote scan — judol detection (CLEAN)"
echo "============================================="
echo "Testing on a clean WordPress site — should report CLEAN"

python3 "$PROJECT_DIR/scanner.py" \
  --url http://localhost:8888 \
  --detect-judol \
  --no-enrich \
  --no-banner \
  --yes \
  || echo "Exit code: $? (expected 0 or 1, NOT 2)"

# ═══════════════════════════════════════════════════════════════════════════════
# PART 4: JUDOL INJECTION (simulate real attack)
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo "============================================="
echo " Step 12: Inject judol (gambling spam) malware"
echo "============================================="
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  DISCLAIMER: This is for TESTING PURPOSES ONLY.               ║"
echo "║  The judol-infection.php file simulates a real gambling spam   ║"
echo "║  injection attack. It injects hidden gambling content into     ║"
echo "║  WordPress pages using techniques real attackers use:          ║"
echo "║                                                                ║"
echo "║  • Hidden divs (display:none, position:absolute off-screen)   ║"
echo "║  • Zero font-size / opacity tricks                            ║"
echo "║  • SEO cloaking (different content for Googlebot vs humans)   ║"
echo "║  • External script injection from gambling domains            ║"
echo "║  • Suspicious outbound links to gambling sites                ║"
echo "║                                                                ║"
echo "║  The malware is deployed as a mu-plugin (must-use plugin),    ║"
echo "║  which auto-loads without activation — just like real attacks. ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Create mu-plugins directory and inject the test malware
docker compose exec wordpress bash -c "mkdir -p /var/www/html/wp-content/mu-plugins"
docker compose cp judol-infection.php \
  wordpress:/var/www/html/wp-content/mu-plugins/judol-infection.php

echo "Judol malware injected as mu-plugin."

# Verify: human visitor sees hidden content
echo ""
echo "--- Verifying injection (human view) ---"
HUMAN_HITS=$(curl -s http://localhost:8888/ | grep -c "slot gacor\|togel\|judi online\|slot88" || true)
echo "Gambling keywords found in HTML: $HUMAN_HITS"

# Verify: Googlebot sees extra cloaked content
echo ""
echo "--- Verifying cloaking (Googlebot view) ---"
BOT_HITS=$(curl -s \
  -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" \
  http://localhost:8888/ | grep -c "slot gacor\|togel\|judi online\|slot88" || true)
echo "Gambling keywords found (Googlebot): $BOT_HITS"
echo ""

if [ "$BOT_HITS" -gt "$HUMAN_HITS" ]; then
  echo "CLOAKING CONFIRMED: Googlebot sees more gambling content than humans"
else
  echo "Hidden content present but no cloaking differential detected"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PART 5: JUDOL DETECTION (scan infected site)
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo "============================================="
echo " Step 13: Judol detection — scan INFECTED site"
echo "============================================="
echo "Running wphunter judol detection on the infected site..."
echo ""

python3 "$PROJECT_DIR/scanner.py" \
  --url http://localhost:8888 \
  --detect-judol \
  --min-severity high \
  --no-enrich \
  --yes \
  || echo "Exit code: $? (expected 2 = judol infected)"

echo ""
echo "============================================="
echo " Step 14: Infected site — JSON report"
echo "============================================="

python3 "$PROJECT_DIR/scanner.py" \
  --url http://localhost:8888 \
  --detect-judol \
  --min-severity high \
  --no-enrich \
  --no-banner \
  --yes \
  -f json \
  -o infected-scan-report.json \
  || true

echo "JSON saved to infected-scan-report.json"
echo ""

# Show summary from JSON
python3 -c "
import json
with open('infected-scan-report.json') as f:
    d = json.load(f)
j = d.get('judol', {})
c = j.get('content', {})
print('=== Judol Detection Summary ===')
print(f'  Infected:     {j.get(\"is_infected\")}')
print(f'  Type:         {j.get(\"infection_type\")}')
print(f'  Severity:     {j.get(\"severity\")}')
print(f'  Confidence:   {j.get(\"confidence\")}')
print(f'  Hidden elems: {len(c.get(\"hidden_elements\", []))}')
print(f'  Susp. links:  {len(c.get(\"suspicious_links\", []))}')
print(f'  Susp. scripts:{len(c.get(\"suspicious_scripts\", []))}')
print()
print('  Hidden element methods:')
for h in c.get('hidden_elements', []):
    print(f'    - {h[\"method\"]}: {h[\"text\"][:60]}...')
print()
print('  Gambling domains found:')
for l in c.get('suspicious_links', [])[:5]:
    print(f'    - {l[\"domain\"]} ({l[\"anchor\"]})')
print()
print('  Injected scripts:')
for s in set(c.get('suspicious_scripts', [])):
    print(f'    - {s}')
"

echo ""
echo "============================================="
echo " Step 15: AI analysis (requires ANTHROPIC_API_KEY)"
echo "============================================="

if [ -n "$ANTHROPIC_API_KEY" ]; then
  echo "API key found. Running AI analysis on infected site..."
  python3 "$PROJECT_DIR/scanner.py" \
    --url http://localhost:8888 \
    --detect-judol \
    --ai \
    --no-enrich \
    --no-banner \
    --yes \
    || echo "Exit code: $?"
else
  echo "ANTHROPIC_API_KEY not set — skipping AI analysis."
  echo ""
  echo "To test AI analysis:"
  echo "  export ANTHROPIC_API_KEY=\"sk-ant-api03-...\""
  echo "  # or"
  echo "  python3 scanner.py connect"
  echo ""
  echo "Then re-run this step:"
  echo "  python3 scanner.py --url http://localhost:8888 --detect-judol --ai --yes"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PART 6: AUTH SUBCOMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo "============================================="
echo " Step 16: Auth subcommands"
echo "============================================="

echo "--- auth-status ---"
python3 "$PROJECT_DIR/scanner.py" auth-status

echo ""
echo "--- disconnect ---"
python3 "$PROJECT_DIR/scanner.py" disconnect

# ═══════════════════════════════════════════════════════════════════════════════
# PART 7: CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo "============================================="
echo " Step 17: Cleanup"
echo "============================================="

echo "Stopping Docker containers..."
docker compose down -v

echo ""
echo "============================================="
echo " Done! All tests completed."
echo "============================================="
echo ""
echo "Summary:"
echo "  - Offline scan:   plugins + themes + core vulnerability scanning"
echo "  - Remote scan:    passive + aggressive fingerprinting"
echo "  - Judol (clean):  correctly identified clean site"
echo "  - Judol (infect): injected mu-plugin with hidden gambling spam"
echo "  - Judol (detect): scanner detected infection with full details"
echo "  - Auth system:    connect / auth-status / disconnect"
echo ""
