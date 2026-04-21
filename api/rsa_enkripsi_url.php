<?php
// ============================================================
// RSA ENCRYPTION ALGORITHM - Based on:
// "Penerapan Algoritma RSA pada Enkripsi URL Website"
// EULER: Jurnal Ilmiah Matematika, Sains dan Teknologi
// Vol. 11, No. 2, pp. 205-215, Desember 2023
// ============================================================

// ---- STEP 1: Compute GCD (for verification) ----
function gcd($a, $b) {
    while ($b !== 0) { $t = $b; $b = $a % $b; $a = $t; }
    return $a;
}

// ---- STEP 2: Compute phi(n) = (p-1)(q-1) ----
function compute_phi($p, $q) {
    return ($p - 1) * ($q - 1);
}

// ---- STEP 3: Generate all valid public keys h ----
function generate_public_keys($phi_n) {
    $keys = [];
    for ($h = 2; $h < $phi_n; $h++) {
        if (gcd($h, $phi_n) === 1) $keys[] = $h;
    }
    return $keys;
}

// ---- STEP 4: Fast Modular Exponentiation (as in article's PHP code) ----
// Replicates the exp_count() function from rsa.php in the article
function exp_count($c, $n, $d) {
    if ($d % 2 == 0) $g = 1; else $g = $c;
    for ($i = 1; $i <= intval($d / 2); $i++) {
        $f = ($c * $c) % $n;
        $g = ($f * $g) % $n;
    }
    return $g;
}

// ---- STEP 5: RSA Encrypt function (replicates RSA_Encrypt() from article) ----
function RSA_Encrypt($data, $N, $public_key) {
    $enc_val = [];
    $ascii_val = str_split($data);
    for ($i = 0; $i < count($ascii_val); $i++) {
        $enc_val[$i] = chr(exp_count(ord($ascii_val[$i]), $N, $public_key));
    }
    $acc = implode('', $enc_val);
    $fin = bin2hex($acc);
    return $fin;
}

// ---- STEP 6: Manual step-by-step encryption (for visualization) ----
function RSA_Encrypt_Steps($data, $p, $q, $n, $phi_n, $public_key) {
    $steps = [];
    $chars = str_split($data);
    foreach ($chars as $char) {
        $m = ord($char);
        $c_raw = exp_count($m, $n, $public_key); // c = m^h mod n
        $c_mod = $c_raw % 256;                   // mod 256 for ASCII-256
        $hex   = sprintf('%02x', $c_mod);
        $steps[] = [
            'char'   => $char,
            'ascii'  => $m,
            'c_raw'  => $c_raw,
            'c_mod'  => $c_mod,
            'hex'    => $hex,
        ];
    }
    return $steps;
}

// ---- DEFAULTS (from the article: p=151, q=173, h=16397) ----
$default_p   = 151;
$default_q   = 173;
$default_h   = 16397;
$default_msg = 'customer';

// ---- HANDLE FORM SUBMISSION ----
$result      = null;
$error       = null;
$steps       = [];
$pub_keys_sample = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $p      = intval($_POST['p']   ?? $default_p);
    $q      = intval($_POST['q']   ?? $default_q);
    $h      = intval($_POST['h']   ?? $default_h);
    $msg    = trim($_POST['msg']   ?? $default_msg);

    // Validations
    if ($p < 2 || $q < 2) {
        $error = "Nilai p dan q harus bilangan prima yang lebih besar dari 1.";
    } elseif ($p === $q) {
        $error = "Nilai p dan q tidak boleh sama.";
    } elseif (empty($msg)) {
        $error = "Plainteks tidak boleh kosong.";
    } else {
        $n     = $p * $q;
        $phi_n = compute_phi($p, $q);

        if ($h <= 1 || $h >= $phi_n) {
            $error = "Kunci publik h harus berada dalam interval (1, φ(n)) = (1, $phi_n).";
        } elseif (gcd($h, $phi_n) !== 1) {
            $error = "Kunci publik h = $h tidak relatif prima terhadap φ(n) = $phi_n. Pilih nilai h lain.";
        } else {
            $ciphertext = RSA_Encrypt($msg, $n, $h);
            $steps      = RSA_Encrypt_Steps($msg, $p, $q, $n, $phi_n, $h);

            // Count valid public keys (sample only for display performance)
            $key_count = 0;
            for ($hh = 2; $hh < $phi_n; $hh++) {
                if (gcd($hh, $phi_n) === 1) $key_count++;
            }

            $result = [
                'p'          => $p,
                'q'          => $q,
                'n'          => $n,
                'phi_n'      => $phi_n,
                'h'          => $h,
                'msg'        => $msg,
                'ciphertext' => $ciphertext,
                'key_count'  => $key_count,
                'gcd_check'  => gcd($h, $phi_n),
            ];
        }
    }
} else {
    // Default values on first load
    $p     = $default_p;
    $q     = $default_q;
    $h     = $default_h;
    $msg   = $default_msg;
    $n     = $p * $q;
    $phi_n = compute_phi($p, $q);
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RSA URL Encryptor — Algoritma RSA untuk Enkripsi URL Website</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
/* ========================================================
   DESIGN SYSTEM — Cyberpunk Terminal Aesthetic
   Dark teal/green on near-black with neon amber accents
   ======================================================== */
:root {
  --bg:        #050c0f;
  --surface:   #0b1a1f;
  --panel:     #0e2229;
  --border:    #1a4050;
  --border2:   #0d2d3a;
  --neon:      #00e5ff;
  --neon2:     #00ff9d;
  --amber:     #ffb700;
  --red:       #ff3e5e;
  --muted:     #3a6070;
  --text:      #c8eaf0;
  --text2:     #7aabb8;
  --mono:      'Space Mono', monospace;
  --sans:      'Syne', sans-serif;
  --glow:      0 0 18px rgba(0,229,255,0.35);
  --glow2:     0 0 14px rgba(0,255,157,0.3);
  --glow-amb:  0 0 18px rgba(255,183,0,0.35);
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html { scroll-behavior: smooth; }

body {
  font-family: var(--sans);
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  overflow-x: hidden;
  position: relative;
}

/* --- Animated grid background --- */
body::before {
  content: '';
  position: fixed;
  inset: 0;
  background-image:
    linear-gradient(rgba(0,229,255,0.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,229,255,0.03) 1px, transparent 1px);
  background-size: 40px 40px;
  animation: gridScroll 20s linear infinite;
  pointer-events: none;
  z-index: 0;
}
body::after {
  content: '';
  position: fixed;
  inset: 0;
  background: radial-gradient(ellipse 80% 60% at 50% 0%, rgba(0,229,255,0.07) 0%, transparent 70%);
  pointer-events: none;
  z-index: 0;
}
@keyframes gridScroll {
  0%   { background-position: 0 0; }
  100% { background-position: 40px 40px; }
}

/* ---- Layout ---- */
.wrapper {
  max-width: 1100px;
  margin: 0 auto;
  padding: 0 24px 80px;
  position: relative;
  z-index: 1;
}

/* ---- Header ---- */
header {
  padding: 56px 0 40px;
  text-align: center;
}
.badge {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  background: rgba(0,229,255,0.08);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 5px 14px;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--neon);
  letter-spacing: 1.5px;
  text-transform: uppercase;
  margin-bottom: 24px;
  animation: fadeDown 0.6s ease both;
}
.badge::before {
  content: '';
  width: 6px; height: 6px;
  border-radius: 50%;
  background: var(--neon2);
  box-shadow: var(--glow2);
  animation: pulse 1.8s ease-in-out infinite;
}
@keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.5;transform:scale(1.4)} }

h1 {
  font-size: clamp(28px, 5vw, 52px);
  font-weight: 800;
  line-height: 1.1;
  letter-spacing: -1px;
  animation: fadeDown 0.7s 0.1s ease both;
}
h1 .accent { color: var(--neon); text-shadow: var(--glow); }
h1 .accent2 { color: var(--amber); text-shadow: var(--glow-amb); }

.subtitle {
  font-family: var(--mono);
  font-size: 13px;
  color: var(--text2);
  margin-top: 14px;
  line-height: 1.7;
  animation: fadeDown 0.7s 0.2s ease both;
}

@keyframes fadeDown {
  from { opacity: 0; transform: translateY(-18px); }
  to   { opacity: 1; transform: translateY(0); }
}

/* ---- Info strip ---- */
.info-strip {
  display: flex;
  gap: 12px;
  justify-content: center;
  flex-wrap: wrap;
  margin: 28px 0 48px;
  animation: fadeDown 0.7s 0.3s ease both;
}
.chip {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 7px 14px;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text2);
}
.chip span { color: var(--neon); font-weight: 700; }

/* ---- Section titles ---- */
.section-title {
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--neon);
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 10px;
}
.section-title::after {
  content: '';
  flex: 1;
  height: 1px;
  background: linear-gradient(90deg, var(--border), transparent);
}

/* ---- Cards / Panels ---- */
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 28px;
  position: relative;
  overflow: hidden;
  transition: border-color 0.3s;
}
.card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, var(--neon), transparent);
  opacity: 0.5;
}
.card:hover { border-color: rgba(0,229,255,0.4); }

/* ---- Form ---- */
.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}
.form-group { display: flex; flex-direction: column; gap: 8px; }
.form-group.full { grid-column: 1/-1; }
label {
  font-family: var(--mono);
  font-size: 11px;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: var(--text2);
}
label .hint { color: var(--muted); font-size: 10px; margin-left: 8px; }
input[type="number"],
input[type="text"] {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 12px 16px;
  color: var(--text);
  font-family: var(--mono);
  font-size: 14px;
  outline: none;
  transition: border-color 0.25s, box-shadow 0.25s;
  width: 100%;
}
input:focus {
  border-color: var(--neon);
  box-shadow: 0 0 0 3px rgba(0,229,255,0.12);
}

.btn {
  width: 100%;
  padding: 15px;
  background: linear-gradient(135deg, rgba(0,229,255,0.15), rgba(0,255,157,0.08));
  border: 1px solid var(--neon);
  border-radius: 12px;
  color: var(--neon);
  font-family: var(--sans);
  font-size: 15px;
  font-weight: 700;
  letter-spacing: 1px;
  cursor: pointer;
  position: relative;
  overflow: hidden;
  transition: all 0.3s;
  margin-top: 8px;
}
.btn::before {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(135deg, rgba(0,229,255,0.2), rgba(0,255,157,0.1));
  opacity: 0;
  transition: opacity 0.3s;
}
.btn:hover { box-shadow: var(--glow); transform: translateY(-1px); }
.btn:hover::before { opacity: 1; }
.btn:active { transform: translateY(0); }

/* --- Quick fill buttons --- */
.quick-fill {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 20px;
  flex-wrap: wrap;
}
.qbtn {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--text2);
  font-family: var(--mono);
  font-size: 11px;
  padding: 6px 12px;
  cursor: pointer;
  transition: all 0.2s;
}
.qbtn:hover { border-color: var(--amber); color: var(--amber); }
.qlabel { font-family: var(--mono); font-size: 10px; color: var(--muted); letter-spacing: 1px; }

/* ---- Error ---- */
.error-box {
  background: rgba(255,62,94,0.1);
  border: 1px solid rgba(255,62,94,0.4);
  border-radius: 10px;
  padding: 14px 18px;
  color: var(--red);
  font-family: var(--mono);
  font-size: 13px;
  margin-bottom: 24px;
  display: flex;
  gap: 10px;
  align-items: flex-start;
  animation: shake 0.4s ease;
}
@keyframes shake {
  0%,100%{transform:translateX(0)}
  25%{transform:translateX(-6px)}
  75%{transform:translateX(6px)}
}

/* ---- Result section ---- */
.result-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 28px;
}
.stat-card {
  background: var(--panel);
  border: 1px solid var(--border2);
  border-radius: 12px;
  padding: 18px;
  position: relative;
  animation: popIn 0.4s ease both;
}
@keyframes popIn {
  from { opacity:0; transform:scale(0.94) translateY(10px); }
  to   { opacity:1; transform:scale(1) translateY(0); }
}
.stat-card:nth-child(2) { animation-delay: 0.05s; }
.stat-card:nth-child(3) { animation-delay: 0.1s; }
.stat-card:nth-child(4) { animation-delay: 0.15s; }
.stat-card:nth-child(5) { animation-delay: 0.2s; }
.stat-label {
  font-family: var(--mono);
  font-size: 10px;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: var(--muted);
  margin-bottom: 8px;
}
.stat-value {
  font-family: var(--mono);
  font-size: 22px;
  font-weight: 700;
  color: var(--neon);
  text-shadow: var(--glow);
}
.stat-value.amber { color: var(--amber); text-shadow: var(--glow-amb); }
.stat-value.green { color: var(--neon2); text-shadow: var(--glow2); }

/* ---- Ciphertext display ---- */
.cipher-display {
  background: var(--panel);
  border: 1px solid var(--neon);
  border-radius: 14px;
  padding: 24px;
  margin-bottom: 28px;
  position: relative;
  box-shadow: var(--glow);
  animation: popIn 0.5s 0.1s ease both;
}
.cipher-label {
  font-family: var(--mono);
  font-size: 10px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--text2);
  margin-bottom: 6px;
}
.cipher-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
}
.cipher-text {
  font-family: var(--mono);
  font-size: clamp(18px, 4vw, 32px);
  font-weight: 700;
  color: var(--neon2);
  text-shadow: var(--glow2);
  letter-spacing: 2px;
  word-break: break-all;
}
.arrow-wrap {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.plain-text {
  font-family: var(--mono);
  font-size: 18px;
  color: var(--amber);
  text-shadow: var(--glow-amb);
}
.arrow { color: var(--muted); font-size: 24px; }

/* URL simulation */
.url-bar {
  background: #0a1820;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 10px 14px;
  font-family: var(--mono);
  font-size: 12px;
  color: var(--text2);
  margin-top: 14px;
  word-break: break-all;
  line-height: 1.6;
}
.url-bar .url-scheme { color: var(--neon2); }
.url-bar .url-domain { color: var(--text); }
.url-bar .url-path   { color: var(--text2); }
.url-bar .url-param  { color: var(--muted); }
.url-bar .url-value  { color: var(--neon); animation: textGlow 2s ease-in-out infinite alternate; }
@keyframes textGlow {
  from { text-shadow: none; }
  to   { text-shadow: 0 0 10px rgba(0,229,255,0.8); }
}

/* ---- Step-by-step table ---- */
.steps-card { animation: popIn 0.5s 0.2s ease both; }
.table-wrap { overflow-x: auto; }
table {
  width: 100%;
  border-collapse: collapse;
  font-family: var(--mono);
  font-size: 13px;
}
thead tr {
  background: rgba(0,229,255,0.06);
  border-bottom: 1px solid var(--border);
}
th {
  padding: 12px 14px;
  text-align: left;
  font-size: 10px;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: var(--text2);
  white-space: nowrap;
}
tbody tr {
  border-bottom: 1px solid var(--border2);
  transition: background 0.2s;
}
tbody tr:hover { background: rgba(0,229,255,0.04); }
td {
  padding: 11px 14px;
  color: var(--text);
}
td.char-col  { color: var(--amber); font-size: 16px; font-weight: 700; text-shadow: var(--glow-amb); }
td.ascii-col { color: var(--text2); }
td.raw-col   { color: var(--text); }
td.mod-col   { color: var(--text2); }
td.hex-col   { color: var(--neon); font-weight: 700; text-shadow: var(--glow); }
.formula-small { font-size: 10px; color: var(--muted); margin-top: 3px; }

/* ---- Algorithm explanation ---- */
.algo-steps {
  counter-reset: step;
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.algo-step {
  display: flex;
  gap: 16px;
  align-items: flex-start;
  padding: 16px;
  background: var(--panel);
  border: 1px solid var(--border2);
  border-radius: 12px;
  transition: border-color 0.25s;
  animation: popIn 0.4s ease both;
}
.algo-step:hover { border-color: var(--border); }
.step-num {
  flex-shrink: 0;
  width: 32px; height: 32px;
  background: rgba(0,229,255,0.1);
  border: 1px solid rgba(0,229,255,0.3);
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 700;
  color: var(--neon);
}
.step-content { flex: 1; }
.step-title { font-size: 14px; font-weight: 700; color: var(--text); margin-bottom: 4px; }
.step-desc { font-family: var(--mono); font-size: 12px; color: var(--text2); line-height: 1.6; }
.step-desc code {
  background: rgba(0,229,255,0.08);
  border-radius: 4px;
  padding: 1px 6px;
  color: var(--neon);
  font-size: 11px;
}
.step-desc .val { color: var(--amber); font-weight: 700; }

/* ---- Key count visualization ---- */
.key-vis {
  background: var(--panel);
  border: 1px solid var(--border2);
  border-radius: 12px;
  padding: 20px;
  margin-top: 16px;
}
.key-bar-wrap { display: flex; align-items: center; gap: 12px; margin-top: 12px; }
.key-bar {
  flex: 1;
  height: 8px;
  background: var(--border2);
  border-radius: 4px;
  overflow: hidden;
}
.key-bar-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--neon), var(--neon2));
  border-radius: 4px;
  animation: barFill 1.2s cubic-bezier(0.22,1,0.36,1) both;
  animation-delay: 0.4s;
}
@keyframes barFill {
  from { width: 0; }
}
.key-bar-label { font-family: var(--mono); font-size: 12px; color: var(--neon); white-space: nowrap; }

/* ---- Reference panel ---- */
.ref-panel {
  background: rgba(255,183,0,0.04);
  border: 1px solid rgba(255,183,0,0.2);
  border-radius: 12px;
  padding: 18px 22px;
  margin-top: 36px;
  font-family: var(--mono);
  font-size: 12px;
  color: var(--text2);
  line-height: 1.7;
}
.ref-panel strong { color: var(--amber); }
.ref-panel a { color: var(--neon); text-decoration: none; }
.ref-panel a:hover { text-decoration: underline; }

/* ---- Responsive ---- */
@media (max-width: 640px) {
  .form-grid { grid-template-columns: 1fr; }
  .form-group.full { grid-column: 1; }
  .result-grid { grid-template-columns: 1fr 1fr; }
  th, td { font-size: 11px; padding: 9px 10px; }
}

/* ---- Animated particles ---- */
.particles { position: fixed; inset: 0; pointer-events: none; z-index: 0; overflow: hidden; }
.particle {
  position: absolute;
  width: 2px; height: 2px;
  background: var(--neon);
  border-radius: 50%;
  opacity: 0;
  animation: float var(--dur) var(--delay) ease-in-out infinite;
}
@keyframes float {
  0%   { opacity: 0; transform: translateY(100vh) translateX(0); }
  10%  { opacity: 0.6; }
  90%  { opacity: 0.3; }
  100% { opacity: 0; transform: translateY(-10vh) translateX(var(--drift)); }
}

/* ---- Copy button ---- */
.copy-btn {
  background: rgba(0,229,255,0.1);
  border: 1px solid rgba(0,229,255,0.3);
  border-radius: 8px;
  color: var(--neon);
  font-family: var(--mono);
  font-size: 11px;
  padding: 6px 12px;
  cursor: pointer;
  transition: all 0.2s;
  white-space: nowrap;
}
.copy-btn:hover { background: rgba(0,229,255,0.2); }
.copy-btn.copied { color: var(--neon2); border-color: var(--neon2); }
</style>
</head>
<body>

<!-- Floating particles -->
<div class="particles" id="particles"></div>

<div class="wrapper">

  <!-- ===== HEADER ===== -->
  <header>
    <div class="badge">RSA Algorithm · URL Encryption</div>
    <h1>
      Enkripsi <span class="accent">URL</span> Website<br>
      dengan Algoritma <span class="accent2">RSA</span>
    </h1>
    <p class="subtitle">
      Implementasi Algoritma Rivest-Shamir-Adleman (RSA) untuk mengenkripsi parameter GET pada URL bar<br>
      Berdasarkan: EULER Jurnal Ilmiah Matematika, Vol. 11, No. 2, 2023 — Trisnawati et al.
    </p>

    <div class="info-strip">
      <div class="chip">Asimetrik · <span>Public Key</span></div>
      <div class="chip">Modular Exponentiation · <span>Fast</span></div>
      <div class="chip">ASCII-256 · <span>Hex Output</span></div>
      <div class="chip">Kunci Publik · <span>gcd(h, φ(n)) = 1</span></div>
    </div>
  </header>

  <!-- ===== ALGORITHM STEPS (static) ===== -->
  <div class="section-title">Algoritma RSA — Langkah-Langkah</div>
  <div class="card" style="margin-bottom:32px;">
    <div class="algo-steps">
      <div class="algo-step" style="animation-delay:0.05s">
        <div class="step-num">1</div>
        <div class="step-content">
          <div class="step-title">Pilih dua bilangan prima p dan q</div>
          <div class="step-desc">Pilih <code>p</code> dan <code>q</code> yang merupakan bilangan prima dengan nilai lebih besar dari 100. <span class="val">Contoh: p=151, q=173</span></div>
        </div>
      </div>
      <div class="algo-step" style="animation-delay:0.1s">
        <div class="step-num">2</div>
        <div class="step-content">
          <div class="step-title">Hitung n = p × q</div>
          <div class="step-desc">Hitung nilai <code>n = p × q</code>. <span class="val">Contoh: n = 151 × 173 = 26.123</span></div>
        </div>
      </div>
      <div class="algo-step" style="animation-delay:0.15s">
        <div class="step-num">3</div>
        <div class="step-content">
          <div class="step-title">Hitung φ(n) = (p−1)(q−1)</div>
          <div class="step-desc">Fungsi Euler totient. <span class="val">Contoh: φ(n) = (151−1)(173−1) = 25.800</span></div>
        </div>
      </div>
      <div class="algo-step" style="animation-delay:0.2s">
        <div class="step-num">4</div>
        <div class="step-content">
          <div class="step-title">Pilih kunci publik h</div>
          <div class="step-desc">Pilih <code>h</code> dengan syarat: <code>gcd(h, φ(n)) = 1</code> dan <code>1 &lt; h &lt; φ(n)</code>. <span class="val">Contoh: h = 16.397</span></div>
        </div>
      </div>
      <div class="algo-step" style="animation-delay:0.25s">
        <div class="step-num">5</div>
        <div class="step-content">
          <div class="step-title">Konversi plainteks ke desimal ASCII</div>
          <div class="step-desc">Setiap karakter dikonversi ke nilai desimal ASCII. <span class="val">Contoh: 'c'→99, 'u'→117, 's'→115, ...</span></div>
        </div>
      </div>
      <div class="algo-step" style="animation-delay:0.3s">
        <div class="step-num">6</div>
        <div class="step-content">
          <div class="step-title">Enkripsi: cᵢ = mᵢʰ mod n</div>
          <div class="step-desc">Setiap blok <code>mᵢ</code> dienkripsi menjadi <code>cᵢ = mᵢ<sup>h</sup> mod n</code> menggunakan fast modular exponentiation.</div>
        </div>
      </div>
      <div class="algo-step" style="animation-delay:0.35s">
        <div class="step-num">7</div>
        <div class="step-content">
          <div class="step-title">Konversi ke heksadesimal ASCII</div>
          <div class="step-desc">Karena ASCII 256-bit, cipherteks dimodulokan dengan 256 lalu dikonversi ke hex. <span class="val">Contoh: 90→'5a', 156→'9c', ...</span></div>
        </div>
      </div>
    </div>
  </div>

  <!-- ===== FORM ===== -->
  <div class="section-title">Kalkulator Enkripsi RSA</div>
  <div class="card" style="margin-bottom:32px;">

    <?php if ($error): ?>
    <div class="error-box">
      <span>⚠</span>
      <span><?= htmlspecialchars($error) ?></span>
    </div>
    <?php endif; ?>

    <div class="quick-fill">
      <span class="qlabel">PRESET :</span>
      <button type="button" class="qbtn" onclick="fillArticle()">📄 Nilai dari Artikel (p=151, q=173, h=16397)</button>
      <button type="button" class="qbtn" onclick="fillCustom()">🔐 Contoh Lain (p=107, q=149)</button>
    </div>

    <form method="POST" action="" id="rsa-form">
      <div class="form-grid">

        <div class="form-group">
          <label>Bilangan Prima p <span class="hint">prima &gt; 2</span></label>
          <input type="number" name="p" id="inp-p" value="<?= htmlspecialchars($_POST['p'] ?? $default_p) ?>" min="3" required>
        </div>

        <div class="form-group">
          <label>Bilangan Prima q <span class="hint">prima &gt; 2, q ≠ p</span></label>
          <input type="number" name="q" id="inp-q" value="<?= htmlspecialchars($_POST['q'] ?? $default_q) ?>" min="3" required>
        </div>

        <div class="form-group">
          <label>Kunci Publik h <span class="hint">gcd(h, φ(n)) = 1</span></label>
          <input type="number" name="h" id="inp-h" value="<?= htmlspecialchars($_POST['h'] ?? $default_h) ?>" min="2" required>
        </div>

        <div class="form-group">
          <label>Plainteks <span class="hint">pesan yang akan dienkripsi</span></label>
          <input type="text" name="msg" id="inp-msg" value="<?= htmlspecialchars($_POST['msg'] ?? $default_msg) ?>" placeholder="customer" required>
        </div>

        <div class="form-group full">
          <button type="submit" class="btn">⚡ ENKRIPSI SEKARANG</button>
        </div>

      </div>
    </form>
  </div>

  <?php if ($result): ?>

  <!-- ===== RESULT ===== -->
  <div class="section-title">Hasil Enkripsi</div>

  <!-- Key parameters -->
  <div class="result-grid" style="margin-bottom:24px;">
    <div class="stat-card">
      <div class="stat-label">Bilangan Prima p</div>
      <div class="stat-value"><?= $result['p'] ?></div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Bilangan Prima q</div>
      <div class="stat-value"><?= $result['q'] ?></div>
    </div>
    <div class="stat-card">
      <div class="stat-label">n = p × q</div>
      <div class="stat-value amber"><?= number_format($result['n']) ?></div>
    </div>
    <div class="stat-card">
      <div class="stat-label">φ(n) = (p−1)(q−1)</div>
      <div class="stat-value amber"><?= number_format($result['phi_n']) ?></div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Kunci Publik h</div>
      <div class="stat-value green"><?= number_format($result['h']) ?></div>
    </div>
    <div class="stat-card">
      <div class="stat-label">gcd(h, φ(n))</div>
      <div class="stat-value green"><?= $result['gcd_check'] ?> ✓</div>
    </div>
  </div>

  <!-- Ciphertext -->
  <div class="cipher-display">
    <div class="cipher-label">HASIL ENKRIPSI (CIPHERTEKS)</div>
    <div class="cipher-row">
      <div class="arrow-wrap">
        <div class="plain-text"><?= htmlspecialchars($result['msg']) ?></div>
        <div class="arrow">→</div>
        <div class="cipher-text" id="cipher-out"><?= htmlspecialchars($result['ciphertext']) ?></div>
      </div>
      <button class="copy-btn" onclick="copyCipher(this)">SALIN</button>
    </div>

    <!-- URL simulation -->
    <div class="url-bar">
      <span class="url-scheme">https://</span><span class="url-domain">rsg.rudysgasindoutama.com</span><span class="url-path">/med.php</span><span class="url-param">?id=</span><span class="url-value"><?= htmlspecialchars($result['ciphertext']) ?></span>
    </div>
    <div style="margin-top:10px;font-family:var(--mono);font-size:11px;color:var(--muted);">
      ↑ Simulasi URL bar setelah enkripsi RSA diterapkan — parameter GET tidak lagi terbaca oleh pihak ketiga
    </div>
  </div>

  <!-- Number of public keys -->
  <div class="key-vis" style="margin-bottom:28px;">
    <div style="font-family:var(--mono);font-size:11px;color:var(--text2);letter-spacing:1px;text-transform:uppercase;">
      Total Kunci Publik Valid yang Terbentuk
    </div>
    <div style="font-family:var(--mono);font-size:28px;font-weight:700;color:var(--neon);text-shadow:var(--glow);margin:8px 0;">
      <?= number_format($result['key_count']) ?>
    </div>
    <div style="font-family:var(--mono);font-size:11px;color:var(--muted);">
      Setiap kunci publik menghasilkan cipherteks yang berbeda — total <?= number_format($result['key_count']) ?> kombinasi enkripsi
    </div>
    <div class="key-bar-wrap">
      <div class="key-bar">
        <div class="key-bar-fill" style="width:<?= min(100, round($result['key_count'] / $result['phi_n'] * 100)) ?>%"></div>
      </div>
      <div class="key-bar-label"><?= round($result['key_count'] / $result['phi_n'] * 100, 1) ?>% dari φ(n)</div>
    </div>
  </div>

  <!-- Step-by-step table -->
  <div class="section-title">Proses Enkripsi Per-Karakter</div>
  <div class="card steps-card">
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Karakter</th>
            <th>Desimal ASCII (mᵢ)</th>
            <th>cᵢ = mᵢʰ mod n</th>
            <th>cᵢ mod 256</th>
            <th>Heksadesimal</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($steps as $i => $s): ?>
          <tr>
            <td style="color:var(--muted)"><?= $i + 1 ?></td>
            <td class="char-col"><?= htmlspecialchars($s['char']) ?></td>
            <td class="ascii-col"><?= $s['ascii'] ?></td>
            <td class="raw-col">
              <?= number_format($s['c_raw']) ?>
              <div class="formula-small"><?= $s['ascii'] ?><sup><?= $result['h'] ?></sup> mod <?= $result['n'] ?></div>
            </td>
            <td class="mod-col"><?= $s['c_mod'] ?></td>
            <td class="hex-col"><?= $s['hex'] ?></td>
          </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>

    <div style="margin-top:16px;padding:14px;background:var(--panel);border-radius:10px;border:1px solid var(--border2);">
      <div style="font-family:var(--mono);font-size:11px;color:var(--text2);margin-bottom:8px;letter-spacing:1px;">RANGKAIAN HEKSADESIMAL</div>
      <div style="font-family:var(--mono);font-size:15px;color:var(--neon);display:flex;flex-wrap:wrap;gap:6px;">
        <?php foreach ($steps as $s): ?>
        <span style="background:rgba(0,229,255,0.08);border:1px solid rgba(0,229,255,0.2);border-radius:5px;padding:3px 8px;"><?= $s['hex'] ?></span>
        <?php endforeach; ?>
        <span style="color:var(--text2);align-self:center;">= <strong style="color:var(--neon2)"><?= htmlspecialchars($result['ciphertext']) ?></strong></span>
      </div>
    </div>

    <div style="margin-top:16px;font-family:var(--mono);font-size:12px;color:var(--muted);line-height:1.8;">
      Plainteks: <strong style="color:var(--amber)"><?= htmlspecialchars($result['msg']) ?></strong>
      &nbsp;→&nbsp;
      Cipherteks: <strong style="color:var(--neon)"><?= htmlspecialchars($result['ciphertext']) ?></strong>
      &nbsp;·&nbsp;
      Menggunakan kunci publik h = <strong style="color:var(--neon2)"><?= $result['h'] ?></strong>
    </div>
  </div>

  <?php endif; ?>

  <!-- ===== REFERENCE ===== -->
  <div class="ref-panel">
    <strong>📄 Referensi Jurnal:</strong><br>
    Trisnawati, T.T., Yurinanda, S., Syafmen, W., &amp; Multahadah, C. (2023).
    <em>Penerapan Algoritma Rivest-Shamir-Adleman (RSA) pada Enkripsi Uniform Resource Locator (URL) Website untuk Keamanan Data.</em>
    EULER: Jurnal Ilmiah Matematika, Sains dan Teknologi, 11(2), 205–215.
    <a href="https://doi.org/10.37905/euler.v11i2.21169" target="_blank">doi:10.37905/euler.v11i2.21169</a>
  </div>

</div><!-- /wrapper -->

<script>
// ---- Floating particles ----
(function(){
  const c = document.getElementById('particles');
  for(let i=0;i<25;i++){
    const p = document.createElement('div');
    p.className = 'particle';
    const x = Math.random()*100;
    const dur = 8+Math.random()*14;
    const del = Math.random()*-20;
    const drift = (Math.random()-0.5)*120+'px';
    p.style.cssText = `left:${x}%;--dur:${dur}s;--delay:${del}s;--drift:${drift};opacity:${Math.random()*0.6}`;
    c.appendChild(p);
  }
})();

// ---- Quick fill presets ----
function fillArticle(){
  document.getElementById('inp-p').value   = 151;
  document.getElementById('inp-q').value   = 173;
  document.getElementById('inp-h').value   = 16397;
  document.getElementById('inp-msg').value = 'customer';
}
function fillCustom(){
  document.getElementById('inp-p').value   = 107;
  document.getElementById('inp-q').value   = 149;
  document.getElementById('inp-h').value   = 5081;
  document.getElementById('inp-msg').value = 'admin';
}

// ---- Copy cipher ----
function copyCipher(btn){
  const txt = document.getElementById('cipher-out').textContent;
  navigator.clipboard.writeText(txt).then(()=>{
    btn.textContent = 'TERSALIN ✓';
    btn.classList.add('copied');
    setTimeout(()=>{ btn.textContent='SALIN'; btn.classList.remove('copied'); }, 2000);
  });
}

// ---- Form submit animation ----
document.getElementById('rsa-form').addEventListener('submit', function(){
  const btn = this.querySelector('.btn');
  btn.textContent = '⏳ MEMPROSES...';
  btn.disabled = true;
});
</script>
</body>
</html>
