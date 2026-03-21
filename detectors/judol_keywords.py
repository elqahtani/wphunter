"""Judol (Indonesian gambling spam) keyword and pattern database.

Sources:
  - Sucuri security research (slot gacor spam campaigns)
  - Malanta APT research (328,000+ domain gambling network)
  - Indonesian police Garuda Website raid (5 operators)
  - GitHub blocklists: BrigsLabs/judol, arfshl/anti-gambling-domains
  - cyberhexs.com hacker victim database analysis
  - hagezi DNS blocklists
"""
import re


# ── Content Keywords (matched against page HTML) ─────────────────────────────
# Organized by confidence level for scoring

GAMBLING_KEYWORDS = {
    "high": [
        # Indonesian gambling terms
        "slot gacor", "slot88", "slot777", "togel", "togel hongkong",
        "togel singapore", "togel sydney", "bandar togel", "judi online",
        "judi bola", "sbobet", "sbobet88", "rtp live", "rtp slot",
        "bocoran rtp", "maxwin", "scatter hitam", "deposit pulsa",
        "slot deposit", "daftar slot", "link alternatif", "situs gacor",
        "slot terpercaya", "judi slot", "agen slot", "pragmatic play",
        "pg soft", "habanero slot", "bonus new member", "slot online",
        "casino online", "poker online", "dominoqq", "bandarqq",
        "pkv games", "slot dana", "slot gopay", "slot ovo",
        # International gambling terms
        "online casino", "live casino", "sports betting", "online gambling",
        # Multilingual
        "kasyno", "kasino", "ruletka",  # Polish
    ],
    "medium": [
        "jackpot", "bonus deposit", "freebet", "freespin", "free spin",
        "bet online", "taruhan", "bandar", "agen bola", "parlay",
        "mix parlay", "handicap", "over under", "livescore",
        "withdraw", "turnover", "rollover",
    ],
    "low": [
        "gacor", "scatter", "wild", "rtp",
        "deposit", "bonus", "promo", "daftar",
    ],
}


# ── Known Judol Operator Brands ──────────────────────────────────────────────
# These are brand names of gambling sites injected into hacked WordPress sites.
# Matched as high-confidence keywords AND URL patterns.
#
# Sources:
#   - cyberhexs.com victim database (wdbos, arena303)
#   - Indonesian police Garuda Website raid (masterslot, cm8, dv188, slot88, aw88)
#   - Sucuri/Malanta research
#   - GitHub blocklists (BrigsLabs/judol, arfshl/anti-gambling-domains)

JUDOL_OPERATOR_BRANDS = [
    # ── Slot brands (-88 suffix) ──
    "slot88", "gacor88", "hoki88", "tokyo88", "bola88", "poker88",
    "togel88", "asianslot88", "asialive88", "homebet88", "hokibet88",
    "dewaraja88", "deltaslot88", "empire88", "bosgacor88", "mamaslot88",
    "gamewin88", "livebet88", "mpobet88", "mpo88", "super88",
    "xlslot88", "koko88", "mansion88",
    # ── Slot brands (-303 suffix) ──
    "arena303", "judol303", "garuda303", "roket303", "hoki303",
    "madu303", "slot303",
    # ── Slot brands (-138 suffix) ──
    "slot138", "gacor138", "naga138", "cuan138", "cuan128",
    "hoki138", "ryu138", "yuki138", "lego138", "garuda138",
    "epicwin138", "bonus138", "cuanwin138", "merdeka138",
    # ── Slot brands (-168 suffix) ──
    "dinasti168", "bosswin168", "jayaplay168", "kedai168",
    # ── Slot brands (-777 suffix) ──
    "slot777", "oyo777",
    # ── Slot brands (-77 suffix) ──
    "gacor77", "dewanaga77", "kilat77", "dewa77", "dewaslot77",
    # ── 4D togel brands ──
    "raja4d", "ayam4d", "bata4d", "mas4d", "mona4d", "ondel4d",
    "pop4d", "raden4d", "baris4d", "vios4d", "sis4d", "bumi4d",
    "asian4d", "garwa4d", "bibit4d", "ratuking4d", "suara4d",
    "melati4d", "nenektogel4d",
    # ── Other numbered brands ──
    "getar69", "langit69", "eropa99", "kera99", "838win",
    "888slot", "918kiss", "enjoy123", "jago33", "jumbo33",
    "ibet44", "rajaslot44", "exbet66", "526bet", "188bet",
    # ── Named operators (dewa/raja/sultan themed) ──
    "dewabet", "dewatogel", "dewanaga", "dewaslot", "dewaraja",
    "rajadewa", "rajabet", "rajazeus", "rajatogel", "rajaslot",
    "sultangacor", "presidenslot",
    # ── Named operators (hoki/lucky themed) ──
    "hokibet", "hokitoto", "nagahoki", "bighoki", "hoki178",
    # ── Named operators (boss/win/cuan themed) ──
    "wdbos", "bosgacor", "akunbos", "cuanwin",
    # ── Named operators (animal themed) ──
    "nagahoki", "garuda303", "garuda138", "capung",
    # ── Togel/lottery brands ──
    "dolantogel", "alitoto", "dentoto", "fusototo", "gigitoto",
    "hajitoto", "inatogel", "sritoto", "suntoto", "tempototo",
    "setantoto", "kangtoto", "ziatogel", "tototogel", "togel178",
    "togelon", "jackpottoto", "borutoto", "bettogel", "danatoto",
    "watitoto", "mulyatoto", "manggatoto", "platinumtoto",
    "ometoto", "koitoto", "warkoptoto2",
    # ── Sportsbook/international brands ──
    "vavada", "1xbet", "mostbet", "melbet", "betway", "bet365",
    "1win", "pin-up", "bk8", "m88", "w88", "aw8", "we88",
    "eu9", "md88", "hao788", "indoxbet", "indomaxbet",
    # ── Confirmed by law enforcement (Garuda Website raid) ──
    "masterslot", "cm8", "dv188", "aw88",
    # ── Misc ──
    "imbaslot", "imbajp", "desabet", "eropabet", "ayoslot88",
    "judolbet88", "gbowin",
]


# ── URL/Slug Keywords ────────────────────────────────────────────────────────
# Used for detecting gambling-related URLs in sitemaps.
# Broader than content keywords — includes generic terms that indicate gambling
# when found in a URL path.

GAMBLING_URL_KEYWORDS = [
    # Generic gambling terms
    "slot", "togel", "judi", "casino", "poker", "sbobet", "gambling",
    "betting", "gacor", "maxwin", "judol", "bandar", "toto",
    "roulette", "blackjack", "baccarat",
    # Multilingual
    "kasyno",
    # International brands
    "vavada", "1xbet", "mostbet", "melbet",
    # Known operators (short/unique enough for URL matching)
    "wdbos", "arena303", "gacor88", "slot138", "mpo88",
    "dewabet", "rajabet", "hokibet", "indoxbet",
]


# ── Domain Patterns ──────────────────────────────────────────────────────────
# Regex patterns for detecting gambling-related external domains in links/scripts.

GAMBLING_DOMAIN_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"slot\d*", r"togel", r"judi", r"casino", r"poker",
        r"sbobet", r"gacor", r"bet\d+", r"judol",
        r"pragmatic", r"maxwin", r"toto\d*", r"bandar",
        r"vavada", r"1xbet", r"mostbet", r"melbet", r"pin-?up",
        r"kasyno", r"gambling", r"roulette", r"baccarat",
        r"wdbos", r"arena303", r"cyberhexs",
        r"hoki\d+", r"cuan\d+", r"naga\d+", r"dewa\w*",
        r"raja\w*", r"sultan", r"mpo\d*", r"indoxbet",
    ]
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".online", ".site",
    ".fun", ".bid", ".win", ".vip", ".club",
}


# ── Hacker Infrastructure ────────────────────────────────────────────────────
# Known C2 domains and hacker tools used in judol injection campaigns.

HACKER_DOMAINS = [
    "cyberhexs.com",        # Victim database / credential storage
    "browsec.xyz",          # C2 domain for dynamic casino spam loading (Sucuri)
    "surfatech-tis.com",    # Gambling redirect destination (Sucuri)
]

HACKER_TOOLS = [
    "indoxploit",           # Indonesian webshell toolkit for WP compromise
]


# ── Hidden CSS Patterns ──────────────────────────────────────────────────────
# CSS techniques used to hide injected gambling content from human visitors.

HIDDEN_CSS_PATTERNS = [
    (r"display\s*:\s*none", "display:none"),
    (r"visibility\s*:\s*hidden", "visibility:hidden"),
    (r"position\s*:\s*absolute[^;]*left\s*:\s*-\d+", "position:absolute+left:-9999px"),
    (r"font-size\s*:\s*0", "font-size:0"),
    (r"z-index\s*:\s*-\d+", "z-index:-1"),
    (r"opacity\s*:\s*0(?:[;\s]|$)", "opacity:0"),
    (r"overflow\s*:\s*hidden[^;]*(?:height|width)\s*:\s*0", "overflow:hidden+size:0"),
    (r"text-indent\s*:\s*-\d{4,}", "text-indent:-9999"),
    (r"color\s*:\s*(?:white|#fff(?:fff)?|rgb\(255)", "color:white"),
]


# ── Spam Directories ─────────────────────────────────────────────────────────
# Common directories created by attackers on compromised WordPress sites.

SPAM_DIRS = [
    "/docs/", "/go/", "/link/", "/out/", "/redirect/",
    "/slot/", "/judi/", "/togel/", "/casino/", "/sbobet/",
]


# ── SERP Search Queries ──────────────────────────────────────────────────────
# Queries used to check Google for indexed gambling content on target domains.

SERP_QUERIES = [
    "slot gacor", "togel", "judi online", "casino online",
    "sbobet", "rtp live", "poker online",
]
