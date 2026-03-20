# Instagram Caption — wphunter v2

---

## Caption (copy-paste ready)

8 plugins. 93 vulnerabilities. 2 of them CRITICAL.

That's what I found when I audited my own WordPress site. Old plugins I forgot to update turned out to have security holes that could let a stranger become admin on my website.

The problem? I didn't want to scan the live site — didn't want to trigger the WAF, didn't want to mess with production. I just needed to know: "which of my installed plugins have known CVEs?"

I tried WPScan — needs a live URL.
I tried Wordfence CLI — needs filesystem access.
Trivy, Snyk, osv-scanner — don't support WordPress at all.

Not a single tool could scan from just a plugin list.

So I built my own.

wphunter — export your plugin list with wp-cli, copy the CSV file, run the scanner on your laptop. Done. Full report with CVE IDs, CVSS scores, severity levels, and fix versions.

But I didn't stop there. Version 2 adds:

Remote scanning — just give it a URL and it fingerprints plugins, themes, and WP version automatically.

Judol detection — detects hidden Indonesian gambling spam injected into WordPress sites. Checks for SEO cloaking, hidden CSS elements, suspicious links, and gambling keywords.

AI analysis — optional Claude AI integration for deeper security insights.

The most dangerous findings from my scan:

CVE-2023-48777 — Elementor 3.6.0
CVSS 9.9. A contributor can upload arbitrary files and get Remote Code Execution.

CVE-2024-10924 — Really Simple SSL 6.0.0
CVSS 9.8. Authentication bypass. Anyone can become admin.

The vulnerability database is free from WPVulnerability.net — aggregating 6 sources: CVE, WPScan, Wordfence, Patchstack, EUVD, and JVN. No API key needed. No payment required.

Open source on GitHub — link in bio.

If you manage WordPress sites and haven't audited your plugins yet, now might be the right time.

.
.
.

#WordPress #CyberSecurity #CVE #InfoSec #VulnerabilityScanning #OpenSource #Python #DevSecOps #WPScan #WebSecurity #ThreatHunting #EthicalHacking #BugBounty #SecurityAudit #PenTesting #OWASP #GamblingSpam #Judol #SEOSpam #AppSec #CyberSecurityTools #InfoSecCommunity

---

## Slide suggestions (for your design)

Slide 1 (Hook):
"I scanned 8 WordPress plugins.
Found 93 vulnerabilities."

Slide 2 (Problem):
"No tool could scan WordPress plugins from just a list."
- WPScan -> needs live URL
- Wordfence -> needs filesystem
- Trivy/Snyk -> don't support WordPress

Slide 3 (Solution):
"So I built my own: wphunter"
Export plugin list -> Transfer CSV -> Scan offline -> Done.

Slide 4 (v2 Features):
"Now with remote scanning & judol detection"
- Fingerprint plugins from URL
- Detect gambling spam injection
- AI-powered analysis
- 3-phase detection: SERP + cloaking + content

Slide 5 (Proof - screenshot scan results):
93 vulns found across 6 plugins + core
- elementor: 31
- woocommerce: 35
- updraftplus: 12
- wordpress-core 6.4.3: 11

Slide 6 (Critical findings):
2 CRITICAL found:
- Elementor 3.6.0 -> CVSS 9.9 (RCE)
- Really Simple SSL 6.0.0 -> CVSS 9.8 (Auth Bypass)

Slide 7 (Remote scan demo):
`python scanner.py --url https://target.com --detect-judol --ai`
- Auto-detects WP version, plugins, themes
- Checks for gambling injection
- AI-powered analysis

Slide 8 (CTA):
"Free. Open source. No API key needed."
GitHub: github.com/elqahtani/wphunter
