from flask import Flask, jsonify, abort, send_from_directory, request
from pathlib import Path
import json
import urllib.request
import urllib.error

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────
#  ACADEMY CONTENT LAYER  (NEW — thin, generic, data-driven)
#  Nothing about specific modules/lessons is hardcoded here.
# ─────────────────────────────────────────────────────────────
ACADEMY_DIR = Path(__file__).parent / "academy"
MODULES_DIR = ACADEMY_DIR / "modules"


def _read_json(path: Path):
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


@app.route("/api/academy/modules")
def api_modules():
    """Master index of all modules. Add a module by editing academy/modules.json."""
    data = _read_json(ACADEMY_DIR / "modules.json")
    if data is None:
        return jsonify({"modules": []})
    return jsonify(data)


@app.route("/api/academy/modules/<slug>")
def api_module(slug):
    """A single module's metadata + ordered lesson list."""
    # slug hardening: no path traversal
    if "/" in slug or "\\" in slug or slug.startswith("."):
        abort(400)
    data = _read_json(MODULES_DIR / slug / "module.json")
    if data is None:
        abort(404)
    return jsonify(data)


@app.route("/api/academy/modules/<slug>/lessons/<lesson>")
def api_lesson(slug, lesson):
    """A single lesson's content (placeholders only)."""
    for part in (slug, lesson):
        if "/" in part or "\\" in part or part.startswith("."):
            abort(400)
    data = _read_json(MODULES_DIR / slug / "lessons" / f"{lesson}.json")
    if data is None:
        abort(404)
    return jsonify(data)


@app.route("/academy/assets/<path:filename>")
def academy_assets(filename):
    """Serve lesson images/diagrams."""
    return send_from_directory(ACADEMY_DIR / "assets", filename)


# ─────────────────────────────────────────────────────────────
#  FRONTEND  (your existing SPA — design system preserved,
#  only the marked regions changed)
# ─────────────────────────────────────────────────────────────
HUB = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnVerse AI Security Academy</title>
<script src="https://unpkg.com/lucide@latest"></script>
<script src="https://unpkg.com/mermaid/dist/mermaid.min.js"></script>
<script>if(window.mermaid){mermaid.initialize({startOnLoad:false,theme:"dark"});}</script>
<link rel="stylesheet" href="https://unpkg.com/@highlightjs/cdn-assets@11.9.0/styles/atom-one-dark.min.css">
<script src="https://unpkg.com/@highlightjs/cdn-assets@11.9.0/highlight.min.js"></script>
<style>

.markdown-body table{
  width:100%;border-collapse:collapse;margin:16px 0;
  background:var(--bg-2);border:1px solid var(--border);border-radius:8px;overflow:hidden;
}
.markdown-body th, .markdown-body td{
  padding:10px 14px;text-align:left;border-bottom:1px solid var(--border);font-size:13.5px;
}
.markdown-body th{
  background:var(--panel-2);color:var(--text);font-weight:650;
  font-size:12px;text-transform:uppercase;letter-spacing:.4px;
}
.markdown-body td{color:var(--text-2)}
.markdown-body tr:last-child td{border-bottom:none}
.markdown-body td code{font-size:12px}
.markdown-body blockquote{
  border-left:3px solid var(--blue);
  background:var(--bg-2);
  padding:10px 16px;
  margin:12px 0;
  border-radius:0 8px 8px 0;
  color:var(--text-2);
  font-size:13.5px;
  font-family:"JetBrains Mono",monospace;
}
:root{
  --bg:#0b0e14; --bg-2:#0f131c; --panel:#141926; --panel-2:#1a2130;
  --border:#232c3d; --border-2:#2c3550; --border-hi:#33415a;   /* FIX: was "#2c real" (invalid) */
  --text:#e6ebf2; --text-2:#a7b1c2; --text-3:#6b7688;
  --blue:#4f8cff; --blue-2:#3a6fd8; --purple:#a855f7; --purple-2:#8b3fe0;
  --green:#22c55e; --amber:#f59e0b; --red:#ef4444; --cyan:#38bdf8;
  --shadow:0 10px 30px -12px rgba(0,0,0,.6);
  --radius:14px;
  --nav-bg:rgba(15,19,28,.82);
}
body.light-theme{
  --bg:#f4f6fb; --bg-2:#eef1f8; --panel:#ffffff; --panel-2:#f2f4fa;
  --border:#e1e5f0; --border-2:#d3d9ea; --border-hi:#c3cbe0;
  --text:#151a26; --text-2:#4b5568; --text-3:#8791a6;
  --nav-bg:rgba(255,255,255,.82);
  --shadow:0 10px 30px -12px rgba(80,90,120,.18);
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{
  font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
  background:radial-gradient(1200px 600px at 15% -10%,rgba(79,140,255,.08),transparent),
             radial-gradient(1000px 500px at 90% 0%,rgba(168,85,247,.07),transparent),
             var(--bg);
  color:var(--text); line-height:1.55; min-height:100vh; letter-spacing:.1px;
}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:var(--bg-2)}
::-webkit-scrollbar-thumb{background:var(--border-hi);border-radius:6px}
::-webkit-scrollbar-thumb:hover{background:#43536f}
a{text-decoration:none;color:inherit}
.icon{width:18px;height:18px;stroke-width:2}

/* ===== TOP NAV ===== */
.nav{
  position:sticky;top:0;z-index:100;
  display:flex;align-items:center;gap:28px;
  padding:0 28px;height:64px;
  background:var(--nav-bg);backdrop-filter:blur(14px);
  border-bottom:1px solid var(--border);
}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;letter-spacing:.2px;cursor:pointer}
.brand .logo{
  width:34px;height:34px;border-radius:9px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--blue),var(--purple));
  box-shadow:0 4px 14px -4px rgba(79,140,255,.6);
}
.brand .logo .icon{width:20px;height:20px;color:#fff}
.brand span b{background:linear-gradient(90deg,var(--blue),var(--purple));-webkit-background-clip:text;background-clip:text;color:transparent}
.navlinks{display:flex;gap:4px;margin-left:8px}
.navlinks a{
  display:flex;align-items:center;gap:8px;padding:8px 14px;border-radius:9px;
  color:var(--text-2);font-size:14px;font-weight:500;cursor:pointer;transition:.18s;
}
.navlinks a .icon{width:16px;height:16px}
.navlinks a:hover{color:var(--text);background:var(--panel)}
.navlinks a.active{color:var(--text);background:var(--panel-2);box-shadow:inset 0 0 0 1px var(--border-hi)}
.nav-right{margin-left:auto;display:flex;align-items:center;gap:14px}
.search{
  display:flex;align-items:center;gap:9px;background:var(--panel);
  border:1px solid var(--border);border-radius:10px;padding:8px 12px;width:260px;transition:.18s;
}
.search:focus-within{border-color:var(--blue);box-shadow:0 0 0 3px rgba(79,140,255,.12)}
.search .icon{width:16px;height:16px;color:var(--text-3)}
.search input{background:none;border:none;outline:none;color:var(--text);font-size:13px;width:100%}
.search input::placeholder{color:var(--text-3)}
.profile{
  width:38px;height:38px;border-radius:10px;display:grid;place-items:center;cursor:pointer;
  background:linear-gradient(135deg,var(--panel-2),var(--panel));border:1px solid var(--border-hi);
  font-weight:600;font-size:13px;color:var(--text);transition:.18s;
}
.profile:hover{border-color:var(--blue)}

/* ===== LAYOUT ===== */
.wrap{max-width:1320px;margin:0 auto;padding:40px 28px 80px}
.view{display:none;animation:fade .4s ease}
.view.active{display:block}
@keyframes fade{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

/* ===== HERO ===== */
.hero{
  position:relative;overflow:hidden;border-radius:20px;padding:56px 48px;margin-bottom:44px;
  background:linear-gradient(135deg,rgba(79,140,255,.13),rgba(168,85,247,.10)),var(--panel);
  border:1px solid var(--border-hi);box-shadow:var(--shadow);
}
.hero::before{content:"";position:absolute;inset:0;
  background:radial-gradient(600px 300px at 85% 20%,rgba(168,85,247,.16),transparent);}
.hero-eyebrow{display:inline-flex;align-items:center;gap:8px;font-size:12px;font-weight:600;
  letter-spacing:1.4px;text-transform:uppercase;color:var(--cyan);margin-bottom:18px;position:relative}
.hero-eyebrow .icon{width:14px;height:14px}
.hero h1{font-size:44px;line-height:1.1;font-weight:800;letter-spacing:-1px;position:relative;max-width:760px}
.hero h1 em{font-style:normal;background:linear-gradient(90deg,var(--blue),var(--purple));-webkit-background-clip:text;background-clip:text;color:transparent}
.hero p.sub{font-size:17px;color:var(--text-2);margin-top:16px;max-width:620px;position:relative}
.flow{display:flex;flex-wrap:wrap;gap:10px;margin-top:30px;position:relative}
.flow .step{display:flex;align-items:center;gap:9px;background:rgba(255,255,255,.03);
  border:1px solid var(--border);border-radius:30px;padding:8px 16px;font-size:13px;font-weight:500}
.flow .step .icon{width:15px;height:15px;color:var(--blue)}
.flow .arrow{display:grid;place-items:center;color:var(--text-3)}
.flow .arrow .icon{width:16px;height:16px}

/* ===== SECTION HEADERS ===== */
.sec-head{display:flex;align-items:flex-end;justify-content:space-between;margin:8px 0 24px}
.sec-head .t{display:flex;align-items:center;gap:12px}
.sec-head .t .badge-ic{width:40px;height:40px;border-radius:11px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--blue),var(--purple));box-shadow:0 6px 18px -8px rgba(79,140,255,.7)}
.sec-head .t .badge-ic .icon{color:#fff}
.sec-head h2{font-size:24px;font-weight:700;letter-spacing:-.4px}
.sec-head p{color:var(--text-3);font-size:14px;margin-top:2px}
.sec-count{font-size:13px;color:var(--text-3);font-weight:500}

/* ===== MODULE GRID ===== */
.mod-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:20px}
.mod{
  position:relative;background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);
  padding:24px;cursor:pointer;transition:.22s cubic-bezier(.2,.7,.3,1);overflow:hidden;
}
.mod::after{content:"";position:absolute;left:0;top:0;height:3px;width:100%;
  background:linear-gradient(90deg,var(--blue),var(--purple));opacity:0;transition:.22s}
.mod:hover{transform:translateY(-4px);border-color:var(--border-hi);box-shadow:var(--shadow)}
.mod:hover::after{opacity:1}
.mod-top{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:16px}
.mod-ic{width:46px;height:46px;border-radius:12px;display:grid;place-items:center;
  background:var(--panel-2);border:1px solid var(--border-hi);transition:.22s}
.mod:hover .mod-ic{background:linear-gradient(135deg,rgba(79,140,255,.2),rgba(168,85,247,.16));border-color:var(--blue)}
.mod-ic .icon{width:22px;height:22px;color:var(--blue)}
.mod-num{font-size:13px;font-weight:700;color:var(--text-3);font-variant-numeric:tabular-nums}
.mod h3{font-size:16.5px;font-weight:650;margin-bottom:8px;letter-spacing:-.2px}
.mod .desc{font-size:13.5px;color:var(--text-2);min-height:40px}
.mod-meta{display:flex;align-items:center;gap:14px;margin-top:18px;padding-top:16px;border-top:1px solid var(--border)}
.diff{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;font-weight:600;
  padding:4px 10px;border-radius:20px;letter-spacing:.3px}
.diff.beg{background:rgba(34,197,94,.14);color:#4ade80}
.diff.int{background:rgba(245,158,11,.14);color:#fbbf24}
.diff.adv{background:rgba(239,68,68,.14);color:#f87171}
.dur{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;color:var(--text-3)}
.dur .icon{width:14px;height:14px}
.mod-cta{margin-top:16px;display:flex;align-items:center;gap:7px;font-size:13.5px;font-weight:600;color:var(--blue)}
.mod-cta .icon{width:16px;height:16px;transition:.22s}
.mod:hover .mod-cta .icon{transform:translateX(4px)}

/* ===== MODULE DETAIL (shared hero) ===== */
.back{display:inline-flex;align-items:center;gap:8px;color:var(--text-2);font-size:13.5px;
  font-weight:500;cursor:pointer;margin-bottom:24px;transition:.18s}
.back:hover{color:var(--text)}
.back .icon{width:16px;height:16px}
.detail-hero{background:linear-gradient(135deg,var(--panel),var(--panel-2));border:1px solid var(--border-hi);
  border-radius:18px;padding:36px 40px;margin-bottom:28px;position:relative;overflow:hidden;box-shadow:var(--shadow)}
.detail-hero::before{content:"";position:absolute;right:-40px;top:-40px;width:220px;height:220px;
  background:radial-gradient(circle,rgba(168,85,247,.18),transparent 70%)}
.detail-hero .row{display:flex;align-items:center;gap:18px;position:relative}
.detail-hero .big-ic{width:60px;height:60px;border-radius:15px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--blue),var(--purple));box-shadow:0 10px 26px -10px rgba(79,140,255,.7)}
.detail-hero .big-ic .icon{width:30px;height:30px;color:#fff}
.detail-hero h1{font-size:28px;font-weight:750;letter-spacing:-.5px}
.detail-hero .meta{display:flex;gap:12px;margin-top:10px;flex-wrap:wrap;align-items:center}
.detail-hero .long{color:var(--text-2);font-size:15px;margin-top:20px;max-width:820px;position:relative}
/* module-level progress bar in hero */
.hero-progress{margin-top:22px;position:relative;max-width:560px}
.hero-progress .track{height:8px;border-radius:20px;background:var(--panel-2);overflow:hidden;border:1px solid var(--border)}
.hero-progress .fill{height:100%;border-radius:20px;background:linear-gradient(90deg,var(--blue),var(--purple));transition:width .4s ease}
.hero-progress .lbl{font-size:12px;color:var(--text-3);margin-top:8px;display:flex;justify-content:space-between}

/* ===== COURSE TWO-PANE (NEW) ===== */
.course{display:grid;grid-template-columns:290px 1fr;gap:26px;align-items:start}
/* --- left rail --- */
.lesson-nav{position:sticky;top:88px;background:var(--panel);border:1px solid var(--border);
  border-radius:var(--radius);padding:14px;max-height:calc(100vh - 120px);overflow:auto}
.lesson-nav .rail-title{font-size:11px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;
  color:var(--text-3);padding:6px 10px 12px}
.lesson-item{display:flex;align-items:center;gap:11px;padding:9px 11px;border-radius:9px;
  cursor:pointer;transition:.16s;color:var(--text-2);font-size:13.5px;font-weight:500;margin-bottom:2px}
.lesson-item:hover{background:var(--panel-2);color:var(--text)}
.lesson-item.active{background:var(--panel-2);color:var(--text);box-shadow:inset 0 0 0 1px var(--border-hi)}
.lesson-item.active .li-num{background:linear-gradient(135deg,var(--blue),var(--purple));color:#fff;border-color:transparent}
.li-num{width:26px;height:26px;flex-shrink:0;border-radius:7px;display:grid;place-items:center;
  font-size:11px;font-weight:700;background:var(--bg-2);border:1px solid var(--border);
  color:var(--text-3);font-variant-numeric:tabular-nums}
.lesson-item.done .li-num{background:rgba(34,197,94,.16);border-color:rgba(34,197,94,.3);color:#4ade80}
.li-txt{flex:1;line-height:1.3}
.li-mark{width:15px;height:15px;color:var(--green);flex-shrink:0}
.lesson-item .li-type{width:14px;height:14px;color:var(--text-3);flex-shrink:0}
.rail-foot{margin-top:14px;padding:12px 11px;border-top:1px solid var(--border)}
.rail-foot .track{height:6px;border-radius:20px;background:var(--bg-2);overflow:hidden}
.rail-foot .fill{height:100%;background:linear-gradient(90deg,var(--blue),var(--purple));transition:width .4s}
.rail-foot .lbl{font-size:11.5px;color:var(--text-3);margin-top:8px}

/* --- right pane --- */
.lesson-pane{min-width:0}
.crumb{display:flex;align-items:center;gap:8px;font-size:12.5px;color:var(--text-3);margin-bottom:16px;flex-wrap:wrap}
.crumb a{cursor:pointer;transition:.16s}.crumb a:hover{color:var(--text-2)}
.crumb .sep{width:13px;height:13px}
.crumb .cur{color:var(--text-2)}
.lesson-head h1{font-size:26px;font-weight:750;letter-spacing:-.5px;margin-bottom:14px}
.lesson-meta{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:24px}
.chip{display:inline-flex;align-items:center;gap:7px;font-size:12px;font-weight:600;
  padding:5px 11px;border-radius:20px;background:var(--panel);border:1px solid var(--border);color:var(--text-2)}
.chip .icon{width:14px;height:14px;color:var(--text-3)}

/* placeholder blocks */
.ph{background:var(--panel);border:1px solid var(--border);border-radius:12px;
  padding:24px 26px;margin-bottom:20px}
.ph.dashed{border-style:dashed}
.ph-label{display:flex;align-items:center;gap:9px;font-size:12px;font-weight:700;
  letter-spacing:.6px;text-transform:uppercase;color:var(--text-3);margin-bottom:14px}
.ph-label .icon{width:15px;height:15px;color:var(--purple)}
.ph-body{color:var(--text-3);font-size:13.5px}
.skeleton{display:grid;gap:10px}
.sk-line{height:12px;border-radius:6px;background:linear-gradient(90deg,var(--panel-2),var(--bg-2),var(--panel-2));
  background-size:200% 100%;animation:shimmer 1.6s infinite}
.sk-line.w90{width:90%}.sk-line.w75{width:75%}.sk-line.w60{width:60%}.sk-line.w45{width:45%}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
.ph.diagram .canvas{height:200px;border-radius:10px;border:1px dashed var(--border-hi);
  display:grid;place-items:center;color:var(--text-3);background:
    repeating-linear-gradient(45deg,transparent,transparent 12px,rgba(255,255,255,.015) 12px,rgba(255,255,255,.015) 24px)}
.ph.diagram .canvas .icon{width:30px;height:30px;margin-bottom:8px;color:var(--text-3)}
.ph.image .canvas{height:180px;border-radius:10px;border:1px dashed var(--border-hi);
  display:grid;place-items:center;color:var(--text-3);background:var(--bg-2)}
.ph.image .canvas .icon{width:28px;height:28px}
.ph.code{background:#11151f;border-color:#232c3d}
.ph.code pre{font-family:"JetBrains Mono",monospace;font-size:12.5px;
  white-space:pre-wrap;line-height:1.7;background:transparent!important}
.ph.code pre code.hljs{background:transparent!important;padding:0!important;color:#e6ebf2}
.ph.code .ph-label{color:#8b96ab}
.ph.note{border-left:3px solid var(--amber);background:linear-gradient(90deg,rgba(245,158,11,.06),var(--panel))}
.ph.note .ph-label .icon{color:var(--amber)}
.q-explain{display:none;margin-top:10px;padding:12px 14px;border-radius:8px;background:var(--bg-2);
  border:1px solid var(--border);font-size:13px;color:var(--text-2);line-height:1.6}

/* diagrams render with mermaid's dark theme regardless of site theme,
   so keep the surrounding canvas dark to match */
.ph.diagram{background:#11151f;border-color:#232c3d}
.ph.diagram .ph-label{color:#8b96ab}
.ph.diagram pre.mermaid{background:transparent}

/* prev / next */
.lesson-foot{display:flex;justify-content:space-between;gap:14px;margin-top:34px}
.nav-btn{flex:1;display:flex;align-items:center;gap:12px;background:var(--panel);
  border:1px solid var(--border);border-radius:12px;padding:16px 18px;cursor:pointer;transition:.18s}
.nav-btn:hover{border-color:var(--border-hi);transform:translateY(-2px);box-shadow:var(--shadow)}
.nav-btn.disabled{opacity:.4;pointer-events:none}
.nav-btn.next{justify-content:flex-end;text-align:right}
.nav-btn .icon{width:20px;height:20px;color:var(--blue);flex-shrink:0}
.nav-btn .lbl{font-size:11px;color:var(--text-3);text-transform:uppercase;letter-spacing:.6px}
.nav-btn .ttl{font-size:14px;font-weight:600;margin-top:2px}

/* ===== QUIZ (frontend only) ===== */
.quiz-card{background:var(--panel);border:1px solid var(--border);border-radius:14px;
  padding:24px 26px;margin-bottom:16px}
.quiz-card .q-num{font-size:11px;font-weight:700;letter-spacing:.8px;color:var(--blue);margin-bottom:10px}
.quiz-card .q-text{font-size:15px;font-weight:600;color:var(--text-2);margin-bottom:18px}
.quiz-opt{display:flex;align-items:center;gap:12px;padding:13px 15px;border-radius:10px;
  border:1px solid var(--border);background:var(--bg-2);margin-bottom:10px;cursor:pointer;transition:.16s}
.quiz-opt:hover{border-color:var(--border-hi)}
.quiz-opt.sel{border-color:var(--blue);background:rgba(79,140,255,.08)}
.quiz-opt .dot{width:18px;height:18px;border-radius:50%;border:2px solid var(--border-hi);flex-shrink:0;transition:.16s}
.quiz-opt.sel .dot{border-color:var(--blue);background:var(--blue);box-shadow:inset 0 0 0 3px var(--bg-2)}
.quiz-opt.correct{border-color:var(--green)!important;background:rgba(34,197,94,.10)!important}
.quiz-opt.wrong{border-color:var(--red)!important;background:rgba(239,68,68,.10)!important}
.quiz-opt .txt{font-size:13.5px;color:var(--text-2)}
.quiz-actions{display:flex;gap:12px;margin-top:8px}
.btn-primary{display:inline-flex;align-items:center;gap:8px;padding:11px 20px;border-radius:10px;
  font-size:14px;font-weight:600;color:#fff;cursor:pointer;border:none;
  background:linear-gradient(135deg,var(--blue),var(--blue-2));transition:.18s}
.btn-primary:hover{box-shadow:0 6px 16px -6px rgba(79,140,255,.7);transform:translateY(-1px)}
.btn-primary .icon{width:16px;height:16px}
.btn-ghost{display:inline-flex;align-items:center;gap:8px;padding:11px 20px;border-radius:10px;
  font-size:14px;font-weight:600;color:var(--text-2);cursor:pointer;
  background:var(--panel);border:1px solid var(--border);transition:.18s}
.btn-ghost:hover{border-color:var(--border-hi);color:var(--text)}
.btn-ghost .icon{width:16px;height:16px}

/* ===== LAB CARDS ===== */
.lab-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:18px}
.lab{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);
  padding:22px;display:flex;flex-direction:column;transition:.2s}
.lab:hover{border-color:var(--border-hi);box-shadow:var(--shadow);transform:translateY(-3px)}
.lab-head{display:flex;align-items:center;gap:12px;margin-bottom:12px}
.lab-ic{width:40px;height:40px;border-radius:10px;display:grid;place-items:center;
  background:var(--panel-2);border:1px solid var(--border-hi)}
.lab-ic .icon{width:19px;height:19px;color:var(--cyan)}
.lab h4{font-size:15px;font-weight:640;letter-spacing:-.2px}
.lab .port{font-size:11.5px;color:var(--text-3);font-family:"JetBrains Mono",monospace}
.lab .lab-desc{font-size:13px;color:var(--text-2);flex-grow:1}
.lab .topics{margin-top:12px;display:flex;flex-wrap:wrap;gap:6px}
.lab .topics .tag{font-size:11px;color:var(--text-3);background:var(--panel-2);
  border:1px solid var(--border);border-radius:20px;padding:3px 9px}
.lab-foot{display:flex;align-items:center;justify-content:space-between;margin-top:18px;
  padding-top:16px;border-top:1px solid var(--border)}
.mode-pills{display:flex;gap:5px}
.pill{font-size:9.5px;font-weight:700;padding:3px 7px;border-radius:5px;letter-spacing:.4px}
.pill.v{background:rgba(239,68,68,.16);color:#f87171}
.pill.h{background:rgba(245,158,11,.16);color:#fbbf24}
.pill.g{background:rgba(34,197,94,.16);color:#4ade80}
.launch{display:inline-flex;align-items:center;gap:7px;font-size:13px;font-weight:600;
  padding:8px 15px;border-radius:9px;color:#fff;
  background:linear-gradient(135deg,var(--blue),var(--blue-2));transition:.18s}
.launch:hover{box-shadow:0 6px 16px -6px rgba(79,140,255,.7);transform:translateY(-1px)}
.launch .icon{width:15px;height:15px}
.no-lab{color:var(--text-3);font-size:14px;background:var(--panel);border:1px dashed var(--border-hi);
  border-radius:12px;padding:26px;text-align:center}
.no-lab .icon{width:26px;height:26px;color:var(--text-3);margin-bottom:8px}

/* ===== DOCS / SETTINGS ===== */
.doc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:18px}
.doc{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:22px;transition:.2s}
.doc:hover{border-color:var(--border-hi);transform:translateY(-2px)}
.doc .icon{width:22px;height:22px;color:var(--blue);margin-bottom:12px}
.doc h4{font-size:15px;font-weight:620;margin-bottom:6px}
.doc p{font-size:13px;color:var(--text-2)}
.doc code{font-family:"JetBrains Mono",monospace;font-size:12px;background:var(--bg-2);
  border:1px solid var(--border);border-radius:6px;padding:2px 7px;color:var(--cyan)}
.set-card{background:var(--panel);border:1px solid var(--border);border-radius:12px;
  padding:20px 24px;margin-bottom:14px;display:flex;align-items:center;justify-content:space-between}
.set-card .l{display:flex;align-items:center;gap:14px}
.set-card .l .icon{width:20px;height:20px;color:var(--text-2)}
.set-card h4{font-size:14.5px;font-weight:600}
.set-card p{font-size:12.5px;color:var(--text-3)}
.toggle{width:44px;height:24px;border-radius:20px;background:var(--panel-2);border:1px solid var(--border-hi);
  position:relative;cursor:pointer;transition:.2s}
.toggle.on{background:var(--blue);border-color:var(--blue)}
.toggle::after{content:"";position:absolute;top:2px;left:2px;width:18px;height:18px;border-radius:50%;
  background:#fff;transition:.2s}
.toggle.on::after{left:22px}

/* ===== DASHBOARD STATS ===== */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:18px;margin-bottom:40px}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:22px}
.stat .icon{width:22px;height:22px;color:var(--blue);margin-bottom:14px}
.stat .num{font-size:30px;font-weight:750;letter-spacing:-1px}
.stat .lbl{font-size:13px;color:var(--text-3);margin-top:2px}

.empty-search{text-align:center;padding:60px;color:var(--text-3)}
.empty-search .icon{width:30px;height:30px;margin-bottom:10px}

@media(max-width:1000px){
  .stats,.learn-flow{grid-template-columns:repeat(2,1fr)}
  .navlinks{display:none}.search{width:180px}
  .hero h1{font-size:32px}.hero{padding:38px 26px}
  .course{grid-template-columns:1fr}                 /* NEW: stack lesson nav on mobile */
  .lesson-nav{position:static;max-height:none}
}
@media(max-width:600px){
  .stats,.learn-flow{grid-template-columns:1fr}.search{display:none}
  .lesson-foot{flex-direction:column}
}
.markdown-body{margin-bottom:14px}
.markdown-body:last-child{margin-bottom:0}
.markdown-body h1,.markdown-body h2,.markdown-body h3{margin-top:22px;margin-bottom:10px}
.markdown-body hr{border:none;border-top:1px solid var(--border);margin:20px 0}
.markdown-body p{margin-bottom:12px}
.markdown-body p:last-child{margin-bottom:0}

/* ===== ASK AI ===== */
.ask-ai-btn{
  display:flex;align-items:center;gap:8px;padding:8px 16px;border-radius:9px;cursor:pointer;
  color:#fff;font-size:14px;font-weight:600;transition:.18s;
  background:linear-gradient(135deg,var(--blue),var(--purple));
  box-shadow:0 4px 14px -4px rgba(79,140,255,.5);border:none;
}
.ask-ai-btn:hover{box-shadow:0 6px 18px -6px rgba(168,85,247,.7);transform:translateY(-1px)}
.ask-ai-btn .icon{width:16px;height:16px}

.ai-overlay{
  position:fixed;inset:0;z-index:1000;background:rgba(6,8,14,.6);backdrop-filter:blur(3px);
  display:none;align-items:stretch;justify-content:flex-end;
}
.ai-overlay.open{display:flex}
.ai-panel{
  width:min(460px,100vw);height:100vh;background:var(--bg-2);border-left:1px solid var(--border-hi);
  display:flex;flex-direction:column;box-shadow:-20px 0 50px -20px rgba(0,0,0,.7);
  animation:slideIn .22s ease;
}
@keyframes slideIn{from{transform:translateX(24px);opacity:.5}to{transform:none;opacity:1}}
.ai-head{
  display:flex;align-items:center;gap:12px;padding:18px 20px;border-bottom:1px solid var(--border);
  background:var(--panel);
}
.ai-head .ic{width:38px;height:38px;border-radius:10px;display:grid;place-items:center;flex-shrink:0;
  background:linear-gradient(135deg,var(--blue),var(--purple))}
.ai-head .ic .icon{color:#fff;width:19px;height:19px}
.ai-head .ttl{font-size:14.5px;font-weight:650}
.ai-head .sub{font-size:11.5px;color:var(--text-3)}
.ai-head-actions{margin-left:auto;display:flex;gap:6px}
.ai-icon-btn{
  width:32px;height:32px;border-radius:8px;display:grid;place-items:center;cursor:pointer;
  background:var(--panel-2);border:1px solid var(--border);color:var(--text-2);transition:.16s;
}
.ai-icon-btn:hover{border-color:var(--border-hi);color:var(--text)}
.ai-icon-btn .icon{width:16px;height:16px}

.ai-body{flex:1;overflow-y:auto;padding:18px 20px;display:flex;flex-direction:column;gap:14px}
.ai-msg{max-width:88%;padding:11px 14px;border-radius:12px;font-size:13.5px;line-height:1.55;white-space:pre-wrap}
.ai-msg.user{align-self:flex-end;background:linear-gradient(135deg,var(--blue),var(--blue-2));color:#fff;border-bottom-right-radius:4px}
.ai-msg.assistant{align-self:flex-start;background:var(--panel);border:1px solid var(--border);color:var(--text);border-bottom-left-radius:4px}
.ai-msg.system-note{align-self:center;background:transparent;color:var(--text-3);font-size:12px;text-align:center;max-width:100%}
.ai-msg code{font-family:"JetBrains Mono",monospace;background:var(--bg-2);padding:1px 5px;border-radius:4px;font-size:12.5px}
.ai-msg.assistant.thinking{color:var(--text-3);font-style:italic}
.ai-empty{margin:auto;text-align:center;color:var(--text-3);padding:20px}
.ai-empty .icon{width:34px;height:34px;margin-bottom:10px;color:var(--text-3)}
.ai-empty .t{font-size:14px;font-weight:600;color:var(--text-2);margin-bottom:6px}
.ai-empty .d{font-size:12.5px;max-width:280px;margin:0 auto}
.ai-chips{display:flex;flex-wrap:wrap;gap:6px;justify-content:center;margin-top:14px}
.ai-chip{font-size:11.5px;padding:6px 11px;border-radius:20px;background:var(--panel);border:1px solid var(--border);
  color:var(--text-2);cursor:pointer;transition:.16s}
.ai-chip:hover{border-color:var(--blue);color:var(--text)}

.ai-input-row{display:flex;gap:10px;padding:14px 16px;border-top:1px solid var(--border);background:var(--panel)}
.ai-input-row textarea{
  flex:1;resize:none;background:var(--bg-2);border:1px solid var(--border);border-radius:10px;
  color:var(--text);font-size:13.5px;padding:11px 13px;font-family:inherit;max-height:120px;
}
.ai-input-row textarea:focus{outline:none;border-color:var(--blue)}
.ai-send{
  width:42px;height:42px;border-radius:10px;display:grid;place-items:center;cursor:pointer;flex-shrink:0;
  background:linear-gradient(135deg,var(--blue),var(--blue-2));border:none;color:#fff;transition:.18s;
}
.ai-send:hover{box-shadow:0 6px 16px -6px rgba(79,140,255,.7)}
.ai-send:disabled{opacity:.4;pointer-events:none}
.ai-send .icon{width:18px;height:18px}
.ai-context-bar{padding:9px 16px;font-size:11px;color:var(--text-3);border-top:1px solid var(--border);
  display:flex;align-items:center;gap:7px;background:var(--panel)}
.ai-context-bar .icon{width:13px;height:13px}
.ai-context-bar b{color:var(--text-2)}

/* ---- API key modal ---- */
.ai-modal-overlay{
  position:fixed;inset:0;z-index:1100;background:rgba(6,8,14,.7);backdrop-filter:blur(3px);
  display:none;align-items:center;justify-content:center;padding:20px;
}
.ai-modal-overlay.open{display:flex}
.ai-modal{
  width:min(440px,100%);background:var(--panel);border:1px solid var(--border-hi);border-radius:16px;
  padding:26px;box-shadow:var(--shadow);
}
.ai-modal h3{font-size:17px;font-weight:700;margin-bottom:4px}
.ai-modal .sub{font-size:12.5px;color:var(--text-3);margin-bottom:20px}
.ai-field{margin-bottom:14px}
.ai-field label{display:block;font-size:12.5px;font-weight:600;color:var(--text-2);margin-bottom:7px}
.ai-provider-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:16px}
.ai-provider-opt{
  display:flex;flex-direction:column;align-items:center;gap:6px;padding:12px 6px;border-radius:10px;
  border:1px solid var(--border);background:var(--bg-2);cursor:pointer;transition:.16s;font-size:11px;color:var(--text-2);
}
.ai-provider-opt .icon{width:18px;height:18px}
.ai-provider-opt.sel{border-color:var(--blue);background:rgba(79,140,255,.1);color:var(--text)}
.ai-modal input, .ai-modal select{
  width:100%;background:var(--bg-2);border:1px solid var(--border);border-radius:9px;
  color:var(--text);font-size:13.5px;padding:10px 12px;font-family:inherit;
}
.ai-modal input:focus, .ai-modal select:focus{outline:none;border-color:var(--blue)}
.ai-modal .hint{font-size:11.5px;color:var(--text-3);margin-top:6px;line-height:1.5}
.ai-modal-actions{display:flex;gap:10px;margin-top:22px}
.ai-modal-actions .btn-primary, .ai-modal-actions .btn-ghost{flex:1;justify-content:center}
.ai-key-status{
  display:flex;align-items:center;gap:8px;font-size:12px;padding:9px 12px;border-radius:8px;
  background:rgba(34,197,94,.1);color:#4ade80;margin-bottom:16px;border:1px solid rgba(34,197,94,.25);
}
.ai-key-status .icon{width:14px;height:14px}

@media(max-width:600px){
  .ai-panel{width:100vw}
  .ai-provider-grid{grid-template-columns:repeat(2,1fr)}
}
</style>
</head>
<body>

<!-- ===== NAV ===== -->
<nav class="nav">
  <div class="brand" id="brand">
    <div class="logo"><i data-lucide="shield-half"></i></div>
    <span>VulnVerse <b>AI Security Academy</b></span>
  </div>
  <div class="navlinks" id="navlinks">
    <a data-view="dashboard"><i data-lucide="layout-dashboard"></i>Dashboard</a>
    <a data-view="academy" class="active"><i data-lucide="graduation-cap"></i>Academy</a>
    <a data-view="alllabs"><i data-lucide="flask-conical"></i>All Labs</a>
    <a data-view="docs"><i data-lucide="book-open"></i>Documentation</a>
    <a data-view="settings"><i data-lucide="settings"></i>Settings</a>
  </div>
  <div class="nav-right">
    <button class="ask-ai-btn" id="askAiBtn" type="button"><i data-lucide="sparkles"></i>Ask AI</button>
    <div class="search">
      <i data-lucide="search"></i>
      <input id="searchInput" placeholder="Search modules & labs...">
    </div>
    <div class="profile"><i data-lucide="user" class="icon"></i></div>
  </div>
</nav>

<div class="wrap">

<!-- ================= ACADEMY (HOME) ================= -->
<section class="view active" id="view-academy">
  <div class="hero" id="heroBanner">
    <div class="hero-eyebrow"><i data-lucide="sparkles"></i>Enterprise AI Security Learning Platform</div>
    <h1>Master AI Security from <em>Fundamentals</em> to Advanced <em>AI Red Teaming</em></h1>
    <p class="sub">A structured, hands-on curriculum. Learn the theory, visualize the attack, then practice inside real vulnerable AI applications.</p>
    <div class="flow">
      <div class="step"><i data-lucide="book-open"></i>Learn</div>
      <div class="arrow"><i data-lucide="arrow-right"></i></div>
      <div class="step"><i data-lucide="lightbulb"></i>Understand</div>
      <div class="arrow"><i data-lucide="arrow-right"></i></div>
      <div class="step"><i data-lucide="search-code"></i>Analyze</div>
      <div class="arrow"><i data-lucide="arrow-right"></i></div>
      <div class="step"><i data-lucide="bug"></i>Exploit</div>
      <div class="arrow"><i data-lucide="arrow-right"></i></div>
      <div class="step"><i data-lucide="radar"></i>Detect</div>
      <div class="arrow"><i data-lucide="arrow-right"></i></div>
      <div class="step"><i data-lucide="shield-check"></i>Mitigate</div>
      <div class="arrow"><i data-lucide="arrow-right"></i></div>
      <div class="step"><i data-lucide="terminal"></i>Practice</div>
    </div>
  </div>

  <div class="sec-head">
    <div class="t">
      <div class="badge-ic"><i data-lucide="library"></i></div>
      <div><h2>AI Security Academy</h2><p>14 structured modules · Beginner to Advanced</p></div>
    </div>
    <span class="sec-count" id="modCount">13 modules</span>
  </div>

  <div class="mod-grid" id="modGrid"></div>
</section>

<!-- ================= MODULE DETAIL (course view) ================= -->
<section class="view" id="view-module"></section>

<!-- ================= DASHBOARD ================= -->
<section class="view" id="view-dashboard">
  <div class="sec-head"><div class="t">
    <div class="badge-ic"><i data-lucide="layout-dashboard"></i></div>
    <div><h2>Dashboard</h2><p>Your learning environment at a glance</p></div>
  </div></div>
  <div class="stats" id="statsGrid"></div>
  <div class="sec-head"><div class="t">
    <div class="badge-ic"><i data-lucide="rocket"></i></div>
    <div><h2>Continue Learning</h2><p>Jump back into the curriculum</p></div>
  </div></div>
  <div class="mod-grid" id="dashModGrid"></div>
</section>

<!-- ================= ALL LABS ================= -->
<section class="view" id="view-alllabs">
  <div class="sec-head">
    <div class="t">
      <div class="badge-ic" style="background:linear-gradient(135deg,#ff3d8a,#a855f7)"><i data-lucide="flask-conical"></i></div>
      <div><h2>All Labs</h2><p>Every hands-on lab across all modules, in one place</p></div>
    </div>
    <span class="sec-count" id="allLabsCount"></span>
  </div>
  <div class="lab-grid" id="allLabsGrid"></div>
</section>

<!-- ================= DOCS ================= -->
<section class="view" id="view-docs">
  <div class="sec-head"><div class="t">
    <div class="badge-ic"><i data-lucide="book-open"></i></div>
    <div><h2>Documentation</h2><p>Guides, references, and tooling</p></div>
  </div></div>
  <div class="doc-grid">
    <div class="doc"><i data-lucide="file-text"></i><h4>Lab Guides</h4><p>Step-by-step walkthroughs for each module, including the full RAG pipeline lab guide.</p></div>
    <div class="doc"><i data-lucide="graduation-cap"></i><h4>Theory Library</h4><p>Conceptual background on evasion attacks, adversarial ML, and LLM threat surfaces.</p></div>
    <div class="doc"><i data-lucide="list-checks"></i><h4>Attack Scenarios</h4><p>Realistic scenario write-ups mapping attacks to MITRE ATLAS techniques.</p></div>
    <div class="doc"><i data-lucide="terminal-square"></i><h4>garak Setup</h4>
      <p>Install: <code>pip install garak</code><br><br>Scan Ollama:<br><code>garak --model_type ollama.OllamaChat --model_name llama3.2:1b -p dan.Dan_11_0</code></p></div>
    <div class="doc"><i data-lucide="database"></i><h4>Detection (SIEM)</h4><p>Kibana + Elasticsearch dashboards for comparing noisy vs stealthy attacks. <a href="http://localhost:5601" target="_blank" style="color:var(--blue)">Open Kibana &rarr;</a></p></div>
    <div class="doc"><i data-lucide="workflow"></i><h4>Solutions & Walkthroughs</h4><p>Reference solutions for evasion labs and end-to-end engagement walkthroughs.</p></div>
  </div>
</section>

<!-- ================= SETTINGS ================= -->
<section class="view" id="view-settings">
  <div class="sec-head"><div class="t">
    <div class="badge-ic"><i data-lucide="settings"></i></div>
    <div><h2>Settings</h2><p>Personalize your learning environment</p></div>
  </div></div>
  <div style="max-width:720px">
    <div class="set-card"><div class="l"><i data-lucide="moon"></i><div><h4>Dark Theme</h4><p>Enterprise dark interface</p></div></div><div class="toggle on" id="darkThemeToggle" onclick="toggleDarkTheme()"></div></div>
    <div class="set-card"><div class="l"><i data-lucide="zap"></i><div><h4>Card Animations</h4><p>Smooth hover and transition effects</p></div></div><div class="toggle on" onclick="this.classList.toggle('on')"></div></div>
    <div class="set-card"><div class="l"><i data-lucide="badge-alert"></i><div><h4>Show Difficulty Badges</h4><p>Display module difficulty labels</p></div></div><div class="toggle on" onclick="this.classList.toggle('on')"></div></div>
    <div class="set-card"><div class="l"><i data-lucide="user"></i><div><h4>Profile</h4><p>Instructor Local</p></div></div><span style="font-size:12.5px;color:var(--text-3)">Placeholder</span></div>
    <div class="set-card"><div class="l"><i data-lucide="server"></i><div><h4>Lab Host</h4><p>All labs served from localhost</p></div></div><span style="font-size:12.5px;color:var(--cyan);font-family:monospace">localhost</span></div>
    <div class="set-card"><div class="l"><i data-lucide="sparkles"></i><div><h4>AI Assistant</h4><p id="settingsAiStatus">No API key configured</p></div></div><button class="btn-ghost" onclick="openAiKeyModal()"><i data-lucide="key-round"></i>Manage API Key</button></div>
  </div>
</section>

</div>

<!-- ================= ASK AI PANEL ================= -->
<div class="ai-overlay" id="aiOverlay">
  <div class="ai-panel">
    <div class="ai-head">
      <div class="ic"><i data-lucide="sparkles"></i></div>
      <div>
        <div class="ttl">Ask AI</div>
        <div class="sub" id="aiProviderLabel">No provider configured</div>
      </div>
      <div class="ai-head-actions">
        <div class="ai-icon-btn" title="Change API key" onclick="openAiKeyModal()"><i data-lucide="key-round"></i></div>
        <div class="ai-icon-btn" title="Clear chat" onclick="clearAiChat()"><i data-lucide="trash-2"></i></div>
        <div class="ai-icon-btn" title="Close" onclick="closeAiPanel()"><i data-lucide="x"></i></div>
      </div>
    </div>
    <div class="ai-body" id="aiBody"></div>
    <div class="ai-context-bar">
      <i data-lucide="info"></i>
      <span>Context-aware: <b id="aiContextLabel">General Academy</b></span>
    </div>
    <div class="ai-input-row">
      <textarea id="aiInput" rows="1" placeholder="Ask anything about a lab or topic (English, Hindi, Hinglish — your choice)"></textarea>
      <button class="ai-send" id="aiSendBtn" onclick="sendAiMessage()"><i data-lucide="send"></i></button>
    </div>
  </div>
</div>

<!-- ================= API KEY MODAL ================= -->
<div class="ai-modal-overlay" id="aiKeyModalOverlay">
  <div class="ai-modal">
    <h3>Connect an AI Provider</h3>
    <div class="sub">Add an API key to power the Ask AI assistant. Your key is stored only in this browser (localStorage) and sent directly to the server-side proxy for each request — never shared elsewhere.</div>

    <div id="aiKeyStatusBox"></div>

    <div class="ai-provider-grid" id="aiProviderGrid">
      <div class="ai-provider-opt" data-provider="claude"><i data-lucide="sparkle"></i>Claude</div>
      <div class="ai-provider-opt" data-provider="gemini"><i data-lucide="gem"></i>Gemini</div>
      <div class="ai-provider-opt" data-provider="openai"><i data-lucide="brain"></i>OpenAI</div>
      <div class="ai-provider-opt" data-provider="ollama"><i data-lucide="server-cog"></i>Ollama</div>
    </div>

    <div class="ai-field" id="aiKeyFieldWrap">
      <label id="aiKeyLabel">API Key</label>
      <input type="password" id="aiKeyInput" placeholder="sk-... / AIza... / ollama not required">
    </div>
    <div class="ai-field">
      <label>Model</label>
      <input type="text" id="aiModelInput" placeholder="e.g. claude-sonnet-4-6">
      <div class="hint" id="aiModelHint">Pick the model name for your provider.</div>
    </div>
    <div class="ai-field" id="aiBaseUrlWrap" style="display:none">
      <label>Ollama Base URL</label>
      <input type="text" id="aiBaseUrlInput" placeholder="http://localhost:11434">
      <div class="hint">Use <code>http://localhost:11434</code> if this app and Ollama run on the <b>same machine</b> (most common). Only use a LAN IP (e.g. <code>http://192.168.1.2:11434</code>) if Ollama runs on a different device — and in that case Ollama must be started with <code>OLLAMA_HOST=0.0.0.0 ollama serve</code> and the firewall must allow port 11434.</div>
    </div>

    <div class="ai-modal-actions">
      <button class="btn-ghost" onclick="closeAiKeyModal()"><i data-lucide="x"></i>Cancel</button>
      <button class="btn-primary" onclick="saveAiKey()"><i data-lucide="check"></i>Save & Connect</button>
    </div>
  </div>
</div>

<script>
/* =====================================================================
   DATA MODEL
   MODULES array preserved from your original file.
   `slug` added to each module so the frontend can fetch content from
   /api/academy/modules/<slug>. Lab arrays are kept exactly as-is —
   the "Hands-on Labs" lesson reuses them and your real Flask routes.
   ===================================================================== */
const MODULES = [
  {id:1, slug:"01-ai-ml-fundamentals", name:"AI & ML Fundamentals", icon:"brain-circuit", diff:"beg", dur:"2 Hours",
   desc:"Core machine learning concepts that underpin every AI attack surface.",
   long:"Build the foundation. Understand models, training, inference, and where trust boundaries emerge in an ML system before you attack them.",
   labs:[]},
  {id:2, slug:"02-llm-fundamentals", name:"LLM Fundamentals", icon:"message-square-code", diff:"beg", dur:"2 Hours",
   desc:"How LLMs work, plus recon and fingerprinting of AI-backed applications.",
   long:"Learn how large language models process prompts, then practice reconnaissance: fingerprinting models, mapping RAG vs non-RAG apps, and health endpoint enumeration.",
   labs:[
     {n:"Recon Target", port:5011, ic:"radar", d:"HTTP headers, health endpoints, JS discovery, 401 vs 404 enumeration, model fingerprinting.", tags:["passive recon","active recon","fingerprinting"]},
     {n:"RAG Support Chatbot", port:5001, ic:"messages-square", d:"RAG vs non-RAG identification, knowledge base mapping, retrieval threshold testing, honeypot recognition.", tags:["RAG recon","source mining"]},
   ]},
  {id:3, slug:"03-prompt-injection", name:"Prompt Injection", icon:"syringe", diff:"int", dur:"3 Hours",
   desc:"Direct, indirect, and channel-based prompt injection techniques.",
   long:"Manipulate model behavior through crafted input. Extract secrets via direct injection, chain indirect payloads through URLs and email, and abuse business logic.",
   labs:[
     {n:"NimbleTech Web (Direct)", port:5000, ic:"key-round", d:"Extract the system prompt secret key. 7 strategies: rule change, story telling, translation, encoding, and more.", tags:["prompt leaking","system prompt"]},
     {n:"Order Bot (Financial)", port:5004, ic:"shopping-cart", d:"Apply unauthorized discounts via direct injection. Cause financial harm by manipulating prices.", tags:["direct injection","business logic"]},
     {n:"URL Summarizer (Indirect)", port:5003, ic:"link", d:"Host malicious HTML, inject payloads via HTML comments, exfiltrate secret keys indirectly.", tags:["indirect injection","URL-based"]},
     {n:"Email Assistant (SMTP)", port:5002, ic:"mail", d:"Send emails with injection payloads in HTML comments via SMTP port 2525.", tags:["SMTP injection","multipart"]},
     {n:"Jailbreak Practice Lab", port:5005, ic:"unlock", d:"Bypass system prompts across 3 escalating levels: basic refusal, strict domain restriction, and a hardened prompt guarding an admin password.", tags:["jailbreak","system prompt bypass"]},
   ]},
  {id:4, slug:"04-rag-pipeline-security", name:"RAG Pipeline Security", icon:"database-zap", diff:"int", dur:"3 Hours",
   desc:"Attacks against retrieval-augmented generation pipelines.",
   long:"Target the full hybrid retrieval stack (ChromaDB + Elasticsearch + Postgres). Practice information extraction, ingestion poisoning, embedding collision, and retrieval hijacking.",
   labs:[
     {n:"RAG Knowledge Base (Full Pipeline)", port:5012, ic:"layers", d:"Hybrid retrieval lab. All 4 RAG attacks: extraction, poisoning, collision, hijacking, plus evasion techniques.", tags:["hybrid retrieval","poisoning","hijacking"]},
   ]},
  {id:5, slug:"05-ai-agent-security", name:"AI Agent Security", icon:"bot", diff:"int", dur:"4 Hours",
   desc:"Exploiting autonomous agents with tools, memory, and browsing.",
   long:"Attack agents that act on the world. Bypass output filters, chain documents, abuse browsing and code-review agents, enumerate memory, and exploit the supply chain.",
   labs:[
     {n:"IT Helpdesk Agent", port:5006, ic:"headset", d:"Output filter bypass via char spacing. Extract DB creds, connect to Postgres, dump employees & api_keys.", tags:["direct injection","filter evasion"]},
     {n:"Document Processor Agent", port:5007, ic:"files", d:"Cross-document fragmentation. Upload 2 chained files, extract MinIO credentials.", tags:["indirect injection","chaining"]},
     {n:"Browser Agent (CSS Hidden)", port:5008, ic:"globe", d:"Host HTML with hidden div injection. Agent fetches and leaks a Slack bot token.", tags:["CSS evasion","browsing agents"]},
     {n:"Code Review Agent", port:5009, ic:"code", d:"Import resolution attack. Upload a Python file that imports config; agent leaks secrets.", tags:["import resolution","code abuse"]},
     {n:"Memory Agent (Enumeration)", port:5010, ic:"brain", d:"Predictable session IDs. Enumerate sessions for JIRA creds, AWS codes, GitHub PATs. DB poisoning too.", tags:["session enum","memory poisoning"]},
     {n:"Supply Chain Lab", port:5025, ic:"package-check", d:"MCP backdoor, pickle RCE, training-data poisoning, LoRA poisoning, tokenizer manipulation, scanner bypass.", tags:["model poisoning","RCE","evasion"]},
     {n:"NimbleCart Shopping Assistant (IDOR)", port:5054, ic:"shield-alert", d:"AI shopping assistant with broken object-level auth. Enumerate other customers' orders/accounts, then tamper with an order you don't own.", tags:["IDOR","BOLA","broken auth"]},
   ]},
  {id:6, slug:"06-multi-agent-security", name:"Multi-Agent Security", icon:"network", diff:"adv", dur:"3 Hours",
   desc:"Attacking agent-to-agent (A2A) orchestration pipelines.",
   long:"Compromise multi-agent systems. Manipulate workflow integrity, inject malicious links, and register rogue agents across a 4-agent orchestration pipeline.",
   labs:[
     {n:"Content Pipeline Orchestrato", port:8000, ic:"share-2", d:"4-agent pipeline. Skip security scan via history injection, inject malicious links, register rogue agents.", tags:["A2A protocol","agent cards","workflow"]},
   ]},
  {id:7, slug:"07-llm-output-attacks", name:"LLM Output Attacks", icon:"file-warning", diff:"int", dur:"3 Hours",
   desc:"Improper output handling: XSS, SQLi, code injection, exfiltration.",
   long:"Weaponize unsanitized LLM output. Trigger reflected and stored XSS, SQL injection via NL-to-SQL translators, command injection, function-calling abuse, and markdown exfiltration.",
   labs:[
     {n:"Reflected XSS via LLM", port:5044, ic:"code-xml", d:"LLM output rendered as innerHTML. HTML tag probe, event handler, remote script, cookie stealer.", tags:["output handling","reflected XSS"]},
     {n:"Stored XSS via Aggregation", port:5045, ic:"code-xml", d:"Site escapes testimonials but LLM chat reflects them raw. Plant payload, then ask the bot to display it.", tags:["stored XSS","indirect surface"]},
     {n:"SQL Injection via Translator", port:5046, ic:"database", d:"NL to SQL translator executes generated SQL. Enumerate tables, dump admin_data, UNION bypass.", tags:["SQLi via LLM","query manipulation"]},
     {n:"Code Injection via LLM", port:5047, ic:"terminal", d:"NL to bash with shell=True. Use ; | && or NL piping to escape ping and read the flag.", tags:["command injection","shell metachars"]},
     {n:"Function Calling Abuse", port:5048, ic:"function-square", d:"Insecure eval dispatch, excessive agency (admin-only system_check), SQLi-vulnerable search tool.", tags:["function calling","excessive agency"]},
     {n:"Markdown Exfiltration", port:5049, ic:"image", d:"LLM emits image markdown to attacker URL. Browser auto-fetches. Practice on /collect endpoint.", tags:["exfiltration","markdown images"]},
   ]},
  {id:8, slug:"08-ai-data-attacks", name:"AI Data Attacks", icon:"flask-conical", diff:"int", dur:"3 Hours",
   desc:"Data poisoning, backdoors, and abuse of AI safeguards.",
   long:"Poison the data and probe the guardrails. Label flipping, clean-label & trojan backdoors, pickle/tensor steganography, hallucination surface analysis, and abuse detection evasion.",
   labs:[
     {n:"AI Data Attacks Lab", port:5053, ic:"biohazard", d:"Label flipping, targeted & clean label, trojan backdoor, pickle/tensor steganography. Mode switcher.", tags:["data poisoning","backdoor","pickle RCE"]},
     {n:"Hallucination Lab", port:5050, ic:"ghost", d:"LLM invents Python packages. Auto-flags real vs hallucinated imports. Typosquatting surface analysis.", tags:["package hallucination"]},
     {n:"Abuse Attacks Lab", port:5051, ic:"megaphone", d:"Misinformation framing, fake reviews, hate-speech detector evasion via char-swap and paraphrasing.", tags:["misinformation","detector evasion"]},
     {n:"Safeguards Lab", port:5052, ic:"shield", d:"Two-stage guardrail pipeline (input + output). Probe with benign, injection, dangerous, hate queries.", tags:["ShieldGemma","layered defense"]},
   ]},
  {id:9, slug:"09-mcp-security", name:"MCP Security", icon:"plug", diff:"adv", dur:"4 Hours",
   desc:"Model Context Protocol recon, poisoning, and chaining to RCE.",
   long:"Exploit the MCP tooling layer. Enumerate tool servers, poison tool descriptions, run UI-rendering phishing, abuse permissions with path traversal, and chain tools into SSTI/RCE.",
   labs:[
     {n:"MCP Recon & Enumeration", port:5020, ic:"scan-search", d:"Developer workstation. Enumerate MCP servers, read .env, recover deleted secrets from git history.", tags:["tool enum","git mining"]},
     {n:"Tool Description Poisoning", port:5021, ic:"file-lock", d:"Inject hidden SYSTEM INSTRUCTIONS into tool descriptions. Server-side base64 exfil.", tags:["supply chain","hidden instructions"]},
     {n:"MCP Apps UI Attack", port:5022, ic:"app-window", d:"Fake Microsoft login in sandboxed srcdoc iframe. No URL bar. AppBridge postMessage exfil.", tags:["UI phishing","postMessage"]},
     {n:"Permission Abuse + Traversal", port:5023, ic:"folder-key", d:"Over-privileged DB tool. CVE-2025-53109/53110 path traversal, symlink sandbox escape.", tags:["privilege abuse","path traversal","symlink"]},
     {n:"Tool Chaining to SSTI to RCE", port:5024, ic:"link-2", d:"4-tool pipeline into Jinja2. Confirm SSTI, achieve RCE, build reverse shell via fragmentation.", tags:["Jinja2 SSTI","fragmentation","RCE"]},
   ]},
  {id:10, slug:"10-ai-evasion", name:"AI Evasion", icon:"crosshair", diff:"adv", dur:"3 Hours",
   desc:"Inference-time evasion against ML classifiers (white & black box).",
   long:"Fool the classifier at inference time. Master the GoodWords attack on Naive Bayes in white-box and black-box settings, and complete a two-phase sentiment-flip skills assessment.",
   labs:[
     {n:"Spam Filter WB Evasion", port:5040, ic:"file-search", d:"White-box GoodWords on SMS spam. Download model, extract top words, sweep the attack curve.", tags:["white-box","goodness scoring"]},
     {n:"GoodWords Black-Box", port:5041, ic:"eye-off", d:"CTF-style. Query budget, no model access. Append 25 words max, flip spam to ham.", tags:["black-box","epsilon-greedy","UCB"]},
     {n:"Sentiment Flip Assessment", port:5042, ic:"repeat", d:"2-phase. WB: positive to negative. BB: negative to positive. Final flag on both.", tags:["WB+BB","end-to-end skills"]},
   ]},
  {id:11, slug:"11-embeddings-vector-db-security", name:"Embeddings & Vector DB Security", icon:"boxes", diff:"adv", dur:"5 Hours",
   desc:"Recon, export, and inversion attacks against embedding stores.",
   long:"Attack the vector layer directly. Fingerprint embedding models, bulk-export vectors, and reconstruct original text through zero-shot, beam-search, ALGEN, and vec2text inversion, plus membership inference.",
   labs:[
     {n:"Embedding Recon", port:5013, ic:"radar", d:"Vector DB discovery, dimension fingerprinting, inference probing to identify the embedding model.", tags:["enumeration","model ID"]},
     {n:"Embedding Export & Triage", port:5014, ic:"download", d:"GraphQL pagination to dump all vectors. 3-stage triage to find high-value targets.", tags:["bulk export","KNN density","RRF"]},
     {n:"Zero-Shot Inversion", port:5015, ic:"unlock", d:"Template bank matches structure, then membership inference brute-forces the PASSWORD slot.", tags:["template gen","slot filling"]},
     {n:"Beam Search Inversion", port:5016, ic:"git-fork", d:"GPT-2 guided token-by-token reconstruction with entropy-based masking for follow-up brute force.", tags:["beam search","GPT-2","entropy"]},
     {n:"ALGEN Canary Injection", port:5017, ic:"bird", d:"No target-model knowledge needed. Inject canaries, harvest pairs, train ridge alignment, decode.", tags:["canary","ridge regression","transfer"]},
     {n:"Vec2Text Supervised Inversion", port:5018, ic:"dna", d:"Inverter to Corrector. Initial hypothesis then iterative residual-driven refinement.", tags:["supervised","corrector loop"]},
     {n:"Membership & Attribute Inference", port:5019, ic:"target", d:"Is candidate X in the DB? Classify chunks without seeing text. Pre-filter for inversion attacks.", tags:["k-NN membership","attribute","wordlist"]},
   ]},
  {id:12, slug:"12-ai-infrastructure", name:"AI Infrastructure", icon:"server-cog", diff:"int", dur:"5 Hours",
   desc:"Cloud, IAM, Kubernetes, and GPU container security for AI systems.",
   long:"Attack the deployment layer. SSRF to cloud credentials, IAM privilege escalation chains, multi-service credential hunting, exposed inference endpoints, Kubernetes RBAC abuse, and GPU container escape.",
   labs:[
     {n:"Cloud SSRF to AWS Creds", port:5026, ic:"cloud", d:"Lambda env leak via SSRF. Extract keys, session token, role ARN. file:// + IMDS abuse.", tags:["SSRF","IMDS","Lambda"]},
   ]},
  {id:13, slug:"13-threat-modeling", name:"Threat Modeling", icon:"map", diff:"int", dur:"3 Hours",
   desc:"Reconstruct AI targets and plan structured engagements.",
   long:"Think like an engagement lead. Build assumption registers, rank crown jewels, map trust boundaries, plan escalation paths, and generate versioned intelligence briefs against a partially-known AI target.",
   labs:[
     {n:"Threat Modeling Workbench", port:5034, ic:"clipboard-list", d:"Reconstruct NimbleTech Ops AI from partial intel. Assumption register, crown jewels, ATLAS mapping.", tags:["assumption register","trust boundaries","MITRE ATLAS"]},
   ]},
  {id:14, slug:"14-ai-red-teaming-tools", name:"AI Red Teaming Tools", icon:"wrench", diff:"beg", dur:"4 Hours",
    desc:"Open-source, enterprise, and lesser-known tools for AI/LLM red teaming — install, configure, and run.",
    long:"Go from theory to tooling. Master PyRIT, Garak, Giskard, DeepTeam, Promptfoo, and the adversarial ML toolkits, plus lesser-known/niche tools most practitioners never discover.",
    labs:[]},
  {id:15, slug:"15-final-assessment", name:"Final Assessment", icon:"award", diff:"adv", dur:"6 Hours",
    desc:"Comprehensive exam covering all 14 modules — concepts, scenarios, critical thinking, and tool usage.",
    long:"The capstone test. 80 questions per module across all 14 modules — mixing recall, scenario-based reasoning, critical thinking, best-prompt selection, and tool knowledge, at easy/medium/hard difficulty.",
    labs:[
    {n:"ShopSphere", port:5035, ic:"message-circle", d:"AI shopping assistant vulnerable to indirect prompt injection leading to SSRF and cloud metadata credential leak.", tags:["Indirect Prompt Injection","SSRF","Metadata Credential Leak"]},
    {n:"RAG Agent", port:5036, ic:"database-zap", d:"Knowledge base poisoning + indirect prompt injection.", tags:["RAG Poisoning","Tool Abuse","Path Traversal"]},
    ]},
];

const DIFF_LABEL = {beg:"Beginner", int:"Intermediate", adv:"Advanced"};
const modBySlug = s => MODULES.find(m => m.slug === s);

/* These 2 labs used to live in a separate "Capstone" section. That section
   is gone for good (per instructions) — but the labs themselves still show
   up inside "All Labs", just tagged as a normal engagement instead. */
const FINAL_ENGAGEMENT_LABS = [
];

/* Lightweight in-memory progress store (client-side placeholder).
   Persists completed lessons per module in localStorage. */
const Progress = {
  key: s => "vv_prog_" + s,
  get(slug){ try{ return JSON.parse(localStorage.getItem(this.key(slug))) || []; }catch(e){ return []; } },
  mark(slug, lesson){ const d = this.get(slug); if(!d.includes(lesson)){ d.push(lesson); localStorage.setItem(this.key(slug), JSON.stringify(d)); } },
  pct(slug, total){ if(!total) return 0; return Math.round(this.get(slug).length / total * 100); }
};

/* ================= RENDER HELPERS (preserved) ================= */
function modCard(m){
  return `<div class="mod" data-mod="${m.id}">
    <div class="mod-top">
      <div class="mod-ic"><i data-lucide="${m.icon}"></i></div>
      <span class="mod-num">${String(m.id).padStart(2,'0')}</span>
    </div>
    <h3>${m.name}</h3>
    <div class="desc">${m.desc}</div>
    <div class="mod-meta">
      <span class="diff ${m.diff}">${DIFF_LABEL[m.diff]}</span>
      <span class="dur"><i data-lucide="clock"></i>${m.dur}</span>
    </div>
    <div class="mod-cta">Open Module <i data-lucide="arrow-right"></i></div>
  </div>`;
}

function labCard(l){
  const modes = l.modes ? `<div class="mode-pills"><span class="pill v">VULN</span><span class="pill h">HARD</span><span class="pill g">GUARD</span></div>` : `<span></span>`;
  return `<div class="lab">
    <div class="lab-head">
      <div class="lab-ic"><i data-lucide="${l.ic}"></i></div>
      <div><h4>${l.n}</h4><div class="port">localhost:${l.port}</div></div>
    </div>
    <div class="lab-desc">${l.d}</div>
    <div class="topics">${l.tags.map(t=>`<span class="tag">${t}</span>`).join('')}</div>
    <div class="lab-foot">
      ${modes}
      <a class="launch" href="http://localhost:${l.port}" target="_blank" rel="noopener">Launch Lab <i data-lucide="external-link"></i></a>
    </div>
  </div>`;
}
function allLabCardWithModule(l, moduleName){
  return `<div class="lab">
    <div class="lab-head">
      <div class="lab-ic"><i data-lucide="${l.ic}"></i></div>
      <div><h4>${l.n}</h4><div class="port">localhost:${l.port}</div></div>
    </div>
    <span class="phase" style="display:inline-block;margin-bottom:10px;font-size:10px;font-weight:700;color:var(--text-3);background:var(--panel-2);padding:3px 8px;border-radius:5px">${moduleName}</span>
    <div class="lab-desc">${l.d}</div>
    <div class="topics">${l.tags.map(t=>`<span class="tag">${t}</span>`).join('')}</div>
    <div class="lab-foot">
      <span></span>
      <a class="launch" href="http://localhost:${l.port}" target="_blank" rel="noopener">Launch Lab <i data-lucide="external-link"></i></a>
    </div>
  </div>`;
}

function buildAllLabs(){
  const items = [];
  MODULES.forEach(m => { m.labs.forEach(l => items.push({l, moduleName:m.name})); });
  FINAL_ENGAGEMENT_LABS.forEach(l => items.push({l, moduleName:"Red Team Engagement"}));
  document.getElementById('allLabsGrid').innerHTML = items.map(x=>allLabCardWithModule(x.l, x.moduleName)).join('');
  document.getElementById('allLabsCount').textContent = `${items.length} labs`;
}

/* ================= BUILD PAGES (preserved) ================= */
function buildAcademy(){
  document.getElementById('modGrid').innerHTML = MODULES.map(modCard).join('');
  document.getElementById('dashModGrid').innerHTML = MODULES.slice(0,6).map(modCard).join('');
}
function buildStats(){
  const totalLabs = MODULES.reduce((a,m)=>a+m.labs.length,0) + FINAL_ENGAGEMENT_LABS.length;
  const stats = [
    {ic:"library", n:MODULES.length, l:"Learning Modules"},
    {ic:"terminal", n:totalLabs, l:"Hands-on Labs"},
    {ic:"layers", n:"3", l:"Defense Modes"},
    {ic:"signal", n:"3", l:"Difficulty Tiers"},
  ];
  document.getElementById('statsGrid').innerHTML = stats.map(s=>
    `<div class="stat"><i data-lucide="${s.ic}"></i><div class="num">${s.n}</div><div class="lbl">${s.l}</div></div>`).join('');
}

/* =====================================================================
   COURSE VIEW  (NEW — replaces the old flat openModule)
   Loads module.json + lesson JSON from the Flask data routes.
   ===================================================================== */
const LESSON_TYPE_ICON = { content:"file-text", quiz:"list-checks", labs:"terminal-square" };

let CURRENT = { module:null, meta:null, lessons:[], active:null };
let CURRENT_QUIZ = [];   // holds the fetched questions[] for the quiz lesson currently on screen

async function fetchJSON(url){
  const r = await fetch(url);
  if(!r.ok) throw new Error(url + " -> " + r.status);
  return r.json();
}

/* Fallback lesson list generated from the module's labs, used ONLY when
   no module.json exists yet — so the UI never breaks while you author content. */
function fallbackLessons(m){
  const base = [
    {slug:"01-introduction",   title:"Introduction",         type:"content"},
    {slug:"02-core-concepts",  title:"Core Concepts",        type:"content"},
    {slug:"03-how-it-works",   title:"How It Works",         type:"content"},
    {slug:"04-attack-surface", title:"Attack Surface",       type:"content"},
    {slug:"05-best-practices", title:"Best Practices",       type:"content"},
    {slug:"quiz",              title:"Knowledge Check",      type:"quiz"},
  ];
  if(m.labs && m.labs.length) base.push({slug:"hands-on-labs", title:"Hands-on Labs", type:"labs"});
  return base;
}
function fallbackLessonContent(m, meta){
  return { slug:meta.slug, title:meta.title, type:meta.type||"content",
           difficulty:DIFF_LABEL[m.diff], reading_time:"— min", sections:[] };
}

async function openModule(id){
  const m = MODULES.find(x=>x.id===id);
  if(!m) return;
  switchView('module', false);
  window.scrollTo({top:0,behavior:'smooth'});
  // loading shell
  document.getElementById('view-module').innerHTML =
    `<div class="back" onclick="switchView('academy')"><i data-lucide="arrow-left"></i>Back to Academy</div>
     <div class="ph dashed"><div class="skeleton"><div class="sk-line w60"></div><div class="sk-line"></div><div class="sk-line w75"></div></div></div>`;
  lucide.createIcons();

  let meta;
  try {
    meta = await fetchJSON(`/api/academy/modules/${m.slug}`);
  } catch(e) {
    // no module.json yet -> generate a sensible fallback so the page still works
    meta = { name:m.name, lessons: fallbackLessons(m) };
  }
  const lessons = (meta.lessons && meta.lessons.length) ? meta.lessons : fallbackLessons(m);
  CURRENT = { module:m, meta, lessons, active: lessons[0].slug };
  renderCourse();
  openLesson(lessons[0].slug);
  updateAiContext();
}

function renderCourse(){
  const m = CURRENT.module, lessons = CURRENT.lessons;
  const done = Progress.get(m.slug);
  const pct = Progress.pct(m.slug, lessons.length);

  const navItems = lessons.map((ls,i)=>{
    const isDone = done.includes(ls.slug);
    const cls = `lesson-item${ls.slug===CURRENT.active?' active':''}${isDone?' done':''}`;
    const num = ls.type==='labs' ? '<i data-lucide="flask-conical" class="li-type"></i>'
              : ls.type==='quiz' ? '<i data-lucide="help-circle" class="li-type"></i>'
              : String(i+1).padStart(2,'0');
    const numEl = `<span class="li-num">${num}</span>`;
    const mark = isDone ? '<i data-lucide="check" class="li-mark"></i>' : '';
    return `<div class="${cls}" data-lesson="${ls.slug}">${numEl}<span class="li-txt">${ls.title}</span>${mark}</div>`;
  }).join('');

  document.getElementById('view-module').innerHTML = `
    <div class="back" onclick="switchView('academy')"><i data-lucide="arrow-left"></i>Back to Academy</div>
    <div class="detail-hero">
      <div class="row">
        <div class="big-ic"><i data-lucide="${m.icon}"></i></div>
        <div>
          <h1>Module ${String(m.id).padStart(2,'0')} · ${m.name}</h1>
          <div class="meta">
            <span class="diff ${m.diff}">${DIFF_LABEL[m.diff]}</span>
            <span class="dur"><i data-lucide="clock"></i>${m.dur}</span>
            <span class="dur"><i data-lucide="list"></i>${lessons.length} lessons</span>
          </div>
        </div>
      </div>
      <div class="long">${m.long}</div>
      <div class="hero-progress">
        <div class="track"><div class="fill" style="width:${pct}%"></div></div>
        <div class="lbl"><span>Module progress</span><span>${pct}% complete</span></div>
      </div>
    </div>

    <div class="course">
      <aside class="lesson-nav">
        <div class="rail-title">Learning Path</div>
        <div id="lessonNav">${navItems}</div>
        <div class="rail-foot">
          <div class="track"><div class="fill" style="width:${pct}%"></div></div>
          <div class="lbl">${done.length} of ${lessons.length} lessons complete</div>
        </div>
      </aside>
      <div class="lesson-pane" id="lessonPane"></div>
    </div>
  `;
  document.getElementById('lessonNav').addEventListener('click', e=>{
    const it = e.target.closest('.lesson-item');
    if(it) { openLesson(it.dataset.lesson); updateAiContext(); }
  });
  lucide.createIcons();
}

async function openLesson(slug){
  CURRENT.active = slug;
  const m = CURRENT.module;
  const idx = CURRENT.lessons.findIndex(l=>l.slug===slug);
  const meta = CURRENT.lessons[idx];
  const prev = idx>0 ? CURRENT.lessons[idx-1] : null;
  const next = idx<CURRENT.lessons.length-1 ? CURRENT.lessons[idx+1] : null;

  // update left-rail active state without full re-render
  document.querySelectorAll('#lessonNav .lesson-item').forEach(el=>{
    el.classList.toggle('active', el.dataset.lesson===slug);
  });

  const pane = document.getElementById('lessonPane');
  pane.innerHTML = `<div class="ph dashed"><div class="skeleton"><div class="sk-line w45"></div><div class="sk-line"></div><div class="sk-line w90"></div></div></div>`;

  // fetch lesson content; fall back gracefully
  let lesson;
  try {
    lesson = await fetchJSON(`/api/academy/modules/${m.slug}/lessons/${slug}`);
  } catch(e) {
    lesson = fallbackLessonContent(m, meta);
  }

  if(meta.type === 'labs' || lesson.type === 'labs'){
    pane.innerHTML = labsView(m, meta, prev, next);
  } else if(meta.type === 'quiz' || lesson.type === 'quiz'){
    pane.innerHTML = quizView(m, lesson, meta, prev, next);
  } else {
    pane.innerHTML = lessonReader(m, lesson, meta, prev, next);
  }

  // mark complete + refresh progress bars
  Progress.mark(m.slug, slug);
  refreshProgressBars();
  lucide.createIcons();
  window.scrollTo({top:0,behavior:'smooth'});
}

function refreshProgressBars(){
  const m = CURRENT.module, total = CURRENT.lessons.length;
  const pct = Progress.pct(m.slug, total), done = Progress.get(m.slug);
  document.querySelectorAll('#view-module .fill').forEach(f=>f.style.width = pct+'%');
  const hl = document.querySelector('#view-module .hero-progress .lbl span:last-child');
  if(hl) hl.textContent = pct+'% complete';
  const rf = document.querySelector('#view-module .rail-foot .lbl');
  if(rf) rf.textContent = `${done.length} of ${total} lessons complete`;
  // add done styling to rail items
  document.querySelectorAll('#lessonNav .lesson-item').forEach(el=>{
    if(done.includes(el.dataset.lesson)) el.classList.add('done');
  });
}

/* ---- breadcrumb + prev/next shared bits ---- */
function crumb(m, title){
  return `<div class="crumb">
    <a onclick="switchView('academy')">Academy</a><i data-lucide="chevron-right" class="sep"></i>
    <a onclick="openModule(${m.id})">${m.name}</a><i data-lucide="chevron-right" class="sep"></i>
    <span class="cur">${title}</span>
  </div>`;
}
function prevNext(prev, next){
  const p = prev
    ? `<div class="nav-btn prev" onclick="openLesson('${prev.slug}')"><i data-lucide="arrow-left"></i><div><div class="lbl">Previous</div><div class="ttl">${prev.title}</div></div></div>`
    : `<div class="nav-btn prev disabled"><i data-lucide="arrow-left"></i><div><div class="lbl">Previous</div><div class="ttl">—</div></div></div>`;
  const n = next
    ? `<div class="nav-btn next" onclick="openLesson('${next.slug}')"><div><div class="lbl">Next</div><div class="ttl">${next.title}</div></div><i data-lucide="arrow-right"></i></div>`
    : `<div class="nav-btn next disabled"><div><div class="lbl">Next</div><div class="ttl">—</div></div><i data-lucide="arrow-right"></i></div>`;
  return `<div class="lesson-foot">${p}${n}</div>`;
}

/* ---- render helpers for real lesson content ---- */
function escapeHtml(str){
  return (str||"").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function simpleMarkdown(md){
  if(!md) return "";

  const lines = md.split("\n");
  const out = [];
  const codeBlocks = [];
  const blockquoteBlocks = [];
  let i = 0;

  while(i < lines.length){
    const line = lines[i];

    // Detect fenced code blocks (```...```)
    if(/^\s*```/.test(line)){
      const codeLines = [];
      i++;
      while(i < lines.length && !/^\s*```/.test(lines[i])){
        codeLines.push(lines[i]);
        i++;
      }
      i++; // skip the closing ```
      codeBlocks.push(escapeHtml(codeLines.join("\n")));
      out.push(`@@CODEBLOCK${codeBlocks.length - 1}@@`);
      continue;
    }

    // Detect a run of consecutive blockquote lines ("> ...") and merge
    // them into ONE <blockquote>, with <br> between the inner lines,
    // instead of letting each line become its own <blockquote> element.
    if(/^\s*>\s?/.test(line)){
      const quoteLines = [];
      while(i < lines.length && /^\s*>\s?/.test(lines[i])){
        quoteLines.push(lines[i].replace(/^\s*>\s?/, ""));
        i++;
      }
      const inner = quoteLines.map(l => inlineMarkdown(l)).join("<br>");
      blockquoteBlocks.push(inner);
      out.push(`@@QUOTE${blockquoteBlocks.length - 1}@@`);
      continue;
    }

    // Detect start of a markdown table: current line looks like a table row,
    // and the next line is a valid separator row (e.g. |---|---|)
    if(/^\s*\|.*\|\s*$/.test(line) &&
       lines[i+1] && /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|?\s*$/.test(lines[i+1])){

      const splitRow = row => row.trim().replace(/^\||\|$/g, "").split("|").map(c => c.trim());
      const headers = splitRow(line);
      const rows = [];
      i += 2; // skip header + separator

      while(i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])){
        rows.push(splitRow(lines[i]));
        i++;
      }

      let table = "<table><thead><tr>";
      headers.forEach(h => table += `<th>${escapeHtml(h)}</th>`);
      table += "</tr></thead><tbody>";
      rows.forEach(r => {
        table += "<tr>";
        r.forEach(c => table += `<td>${inlineMarkdown(c)}</td>`);
        table += "</tr>";
      });
      table += "</tbody></table>";
      out.push(table);
      continue;
    }

    out.push(line);
    i++;
  }

  let html = out.join("\n");

  // Protect tables from escaping (they're already built as HTML)
  const tableParts = [];
  html = html.replace(/<table>[\s\S]*?<\/table>/g, m => {
    tableParts.push(m);
    return `@@TBL${tableParts.length - 1}@@`;
  });

  html = escapeHtml(html);
  html = html.replace(/^### (.*)$/gm, "<h3>$1</h3>")
             .replace(/^## (.*)$/gm, "<h2>$1</h2>")
             .replace(/^# (.*)$/gm, "<h1>$1</h1>")
             .replace(/^---$/gm, "<hr>")
             .replace(/`([^`]+)`/g, "<code>$1</code>")
             .replace(/\*\*(.*?)\*\*/g, "<b>$1</b>")
             .replace(/\*(.*?)\*/g, "<i>$1</i>")
             .replace(/^- (.*)$/gm, "<li>$1</li>")
             .replace(/\n{2,}/g, "</p><p>")
             .replace(/\n/g, "<br>");

  // Put tables back in
  html = html.replace(/@@TBL(\d+)@@/g, (m, idx) => tableParts[parseInt(idx)]);

  // Put fenced code blocks back in as proper <pre><code> blocks
  html = html.replace(/@@CODEBLOCK(\d+)@@(<br>)?/g, (m, idx) =>
    `</p><pre><code>${codeBlocks[parseInt(idx)]}</code></pre><p>`
  );

  // Put merged blockquotes back in as ONE <blockquote> each
  html = html.replace(/@@QUOTE(\d+)@@(<br>)?/g, (m, idx) =>
    `</p><blockquote>${blockquoteBlocks[parseInt(idx)]}</blockquote><p>`
  );

  return "<p>" + html + "</p>";
}

function inlineMarkdown(text){
  let t = escapeHtml(text);
  t = t.replace(/`([^`]+)`/g, "<code>$1</code>")
       .replace(/\*\*(.*?)\*\*/g, "<b>$1</b>")
       .replace(/\*(.*?)\*/g, "<i>$1</i>");
  return t;
}
function renderSection(sec){
  // "content" sections render as plain flowing prose (no box/label) —
  // grouping happens in renderSections() below, this is just the inner markup.
  if(sec.type === "content"){
    return `<div class="markdown-body">${simpleMarkdown(sec.body)}</div>`;
  }
  if(sec.type === "diagram"){
    return `<div class="ph diagram"><div class="ph-label"><i data-lucide="git-branch"></i>Diagram</div>
      <pre class="mermaid">${escapeHtml(sec.src)}</pre></div>`;
  }
  if(sec.type === "code"){
    const lang = sec.language || "plaintext";
    return `<div class="ph code"><div class="ph-label"><i data-lucide="code-2"></i>Code</div>
      <pre><code class="language-${lang}">${escapeHtml(sec.body)}</code></pre></div>`;
  }
  if(sec.type === "note"){
    return `<div class="ph note"><div class="ph-label"><i data-lucide="sticky-note"></i>Note</div>
      <div class="ph-body markdown-body">${simpleMarkdown(sec.body)}</div></div>`;
  }
  if(sec.type === "image"){
    return `<div class="ph image"><div class="ph-label"><i data-lucide="image"></i>Image</div>
      <div class="canvas"><img src="${sec.src||''}" alt="${sec.alt||''}" style="max-width:100%;border-radius:10px"></div></div>`;
  }
  return "";
}

// Groups consecutive "content" sections into a single flowing card
// (one CONTENT label, no repeated boxes/gaps). Non-content sections
// (diagram/code/note/image) still render as their own standalone cards.
function renderSections(sections){
  if(!sections || !sections.length) return "";
  const out = [];
  let buffer = [];
  const flushBuffer = () => {
    if(buffer.length){
      out.push(`<div class="ph"><div class="ph-label"><i data-lucide="align-left"></i>Content</div>${buffer.join('')}</div>`);
      buffer = [];
    }
  };
  sections.forEach(sec => {
    if(sec.type === "content"){
      buffer.push(renderSection(sec));
    } else {
      flushBuffer();
      out.push(renderSection(sec));
    }
  });
  flushBuffer();
  return out.join('');
}

/* ---- CONTENT lesson (renders real sections from lesson JSON) ---- */
function lessonReader(m, lesson, meta, prev, next){
  const title = lesson.title || meta.title;
  const rt = lesson.readingtime || lesson.reading_time || "— min read";
  const diff = lesson.difficulty || DIFF_LABEL[m.diff];
  const pct = Progress.pct(m.slug, CURRENT.lessons.length);

  const sectionsHTML = (lesson.sections && lesson.sections.length)
    ? renderSections(lesson.sections)
    : `<div class="ph dashed"><div class="ph-body">No content yet for this lesson.</div></div>`;

  const html = `
    ${crumb(m, title)}
    <div class="lesson-head"><h1>${title}</h1></div>
    <div class="lesson-meta">
      <span class="chip"><i data-lucide="clock"></i>${rt}</span>
      <span class="chip"><i data-lucide="signal"></i>${diff}</span>
      <span class="chip"><i data-lucide="trending-up"></i>${pct}% module progress</span>
    </div>
    ${sectionsHTML}
    ${prevNext(prev, next)}
  `;
  setTimeout(()=>{ if(window.mermaid){ mermaid.init(undefined, document.querySelectorAll('.mermaid')); } }, 30);
  setTimeout(()=>{ if(window.hljs){ document.querySelectorAll('pre code').forEach(el => hljs.highlightElement(el)); } }, 30);
  return html;
}

/* ---- QUIZ lesson (renders real questions from lesson JSON) ---- */
function quizView(m, lesson, meta, prev, next){
  const title = lesson.title || meta.title || "Knowledge Check";
  const questions = lesson.questions || [];
  CURRENT_QUIZ = questions;   // keep full question data (incl. correct answer + explanation) around for grading

  const cards = questions.map((qz, i) => `
    <div class="quiz-card" data-qidx="${i}" data-answer="${qz.answer}">
      <div class="q-num">QUESTION ${i+1}</div>
      <div class="q-text">${escapeHtml(qz.q)}</div>
      ${qz.options.map((op, oi) => `
        <div class="quiz-opt" data-oi="${oi}" onclick="
          this.parentElement.querySelectorAll('.quiz-opt').forEach(o=>o.classList.remove('sel'));
          this.classList.add('sel');
        ">
          <div class="dot"></div><div class="txt">${escapeHtml(op)}</div>
        </div>`).join('')}
      <div class="q-explain"></div>
    </div>`).join('');

  return `
    ${crumb(m, title)}
    <div class="lesson-head"><h1>${title}</h1></div>
    <div class="lesson-meta">
      <span class="chip"><i data-lucide="list-checks"></i>${questions.length} questions</span>
      <span class="chip"><i data-lucide="award"></i>Knowledge Check</span>
    </div>
    ${cards}
    <div class="quiz-actions">
      <button class="btn-primary" onclick="gradeQuiz()"><i data-lucide="check-circle-2"></i>Submit Answers</button>
      <button class="btn-ghost" onclick="openLesson('${meta.slug}')"><i data-lucide="rotate-ccw"></i>Reset</button>
    </div>
    ${prevNext(prev, next)}
  `;
}

function gradeQuiz(){
  let correct = 0, total = 0;
  document.querySelectorAll('.quiz-card').forEach(card => {
    total++;
    const answer = parseInt(card.dataset.answer, 10);
    const selected = card.querySelector('.quiz-opt.sel');
    const explainEl = card.querySelector('.q-explain');
    card.querySelectorAll('.quiz-opt').forEach((opt, oi) => {
      opt.classList.remove('correct','wrong');
      if(oi === answer) opt.classList.add('correct');
    });
    let isCorrect = false;
    if(selected){
      const oi = parseInt(selected.dataset.oi, 10);
      if(oi === answer){ correct++; isCorrect = true; }
      else{ selected.classList.add('wrong'); }
    }
    if(explainEl){
      const qi = parseInt(card.dataset.qidx, 10);
      const qz = CURRENT_QUIZ[qi];
      const statusHtml = selected
        ? `<b style="color:${isCorrect ? 'var(--green)' : 'var(--red)'}">${isCorrect ? 'Correct.' : 'Incorrect.'}</b> `
        : `<b style="color:var(--amber)">No answer selected.</b> `;
      const explanationText = (qz && qz.explanation) ? escapeHtml(qz.explanation) : '';
      explainEl.innerHTML = statusHtml + explanationText;
      explainEl.style.display = 'block';
    }
  });
  const pct = total ? Math.round(correct/total*100) : 0;
  const existingBanner = document.querySelector('.quiz-score-banner');
  if(existingBanner) existingBanner.remove();
  const banner = document.createElement('div');
  banner.className = 'ph note quiz-score-banner';
  banner.innerHTML = `<div class="ph-label"><i data-lucide="award"></i>Score</div><div class="ph-body">You got ${correct} of ${total} correct (${pct}%).</div>`;
  const actions = document.querySelector('.quiz-actions');
  actions.parentNode.insertBefore(banner, actions);
  lucide.createIcons();
}

/* ---- HANDS-ON LABS lesson (reuses your labCard + real routes) ---- */
function labsView(m, meta, prev, next){
  const title = meta.title || "Hands-on Labs";
  const body = (m.labs && m.labs.length)
    ? `<div class="lab-grid">${m.labs.map(l=>labCard(l)).join('')}</div>`
    : `<div class="no-lab"><i data-lucide="graduation-cap"></i><div>This is a foundational theory module. Master these concepts, then move on to hands-on modules.</div></div>`;
  return `
    ${crumb(m, title)}
    <div class="lesson-head"><h1>${title}</h1></div>
    <div class="lesson-meta">
      <span class="chip"><i data-lucide="terminal-square"></i>${m.labs.length} lab${m.labs.length!==1?'s':''}</span>
      <span class="chip"><i data-lucide="server"></i>Served on localhost</span>
    </div>
    ${body}
    ${prevNext(prev, next)}
  `;
}

/* ================= NAV / VIEW SWITCHING (preserved) ================= */
function switchView(view, updateNav=true){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.getElementById('view-'+view).classList.add('active');
  if(updateNav){
    document.querySelectorAll('#navlinks a').forEach(a=>a.classList.remove('active'));
    const navMap = {academy:'academy', module:'academy', dashboard:'dashboard', alllabs:'alllabs', docs:'docs', settings:'settings'};
    const target = document.querySelector(`#navlinks a[data-view="${navMap[view]||view}"]`);
    if(target) target.classList.add('active');
  }
  window.scrollTo({top:0,behavior:'smooth'});
  updateAiContext();
}

/* ================= SEARCH (preserved) ================= */
function runSearch(q){
  q = q.trim().toLowerCase();
  const grid = document.getElementById('modGrid');
  if(!q){ grid.innerHTML = MODULES.map(modCard).join(''); document.getElementById('modCount').textContent = `${MODULES.length} modules`; lucide.createIcons(); return; }
  const matches = MODULES.filter(m=>{
    const hay = (m.name+m.desc+m.long+m.labs.map(l=>l.n+l.d+l.tags.join(' ')).join(' ')).toLowerCase();
    return hay.includes(q);
  });
  document.getElementById('modCount').textContent = `${matches.length} result${matches.length!==1?'s':''}`;
  grid.innerHTML = matches.length ? matches.map(modCard).join('')
    : `<div class="empty-search" style="grid-column:1/-1"><i data-lucide="search-x"></i><div>No modules match "${q}"</div></div>`;
  switchView('academy');
  lucide.createIcons();
}

/* =====================================================================
   ASK AI ASSISTANT (NEW)
   - Multi-provider (Claude / Gemini / OpenAI / Ollama), key stored in
     localStorage only.
   - Calls go through the Flask backend proxy at /api/ai/chat so there
     are no browser CORS issues and keys never sit in page HTML.
   - Builds a system prompt describing the whole lab environment
     (modules, labs, ports) so answers are grounded in this project.
   ===================================================================== */
const AI_KEY_STORAGE = "vv_ai_config";
const AI_CHAT_STORAGE = "vv_ai_chat_history";

const AI_PROVIDER_DEFAULTS = {
  claude: { model: "claude-sonnet-4-6", label: "Claude", needsKey: true },
  gemini: { model: "gemini-2.5-flash", label: "Gemini", needsKey: true },
  openai: { model: "gpt-4o-mini", label: "OpenAI", needsKey: true },
  ollama: { model: "llama3.2", label: "Ollama (local)", needsKey: false, defaultBaseUrl: "http://localhost:11434" },
};

function getAiConfig(){
  try { return JSON.parse(localStorage.getItem(AI_KEY_STORAGE)) || null; } catch(e){ return null; }
}
function setAiConfig(cfg){ localStorage.setItem(AI_KEY_STORAGE, JSON.stringify(cfg)); }

function getAiChatHistory(){
  try { return JSON.parse(sessionStorage.getItem(AI_CHAT_STORAGE)) || []; } catch(e){ return []; }
}
function setAiChatHistory(h){ sessionStorage.setItem(AI_CHAT_STORAGE, JSON.stringify(h)); }

/* ---- build a compact description of the whole lab environment ---- */
function buildEnvironmentContext(){
  const lines = [];
  lines.push("You are the embedded AI mentor inside 'VulnVerse AI Security Academy', a local, self-hosted, hands-on AI/LLM security training platform (like a personal AI-security CTF academy). Everything here is an intentionally vulnerable lab environment for authorized learning by the student running it locally — help them understand concepts and solve labs.");
  lines.push("The academy has " + MODULES.length + " modules, beginner to advanced:");
  MODULES.forEach(m=>{
    const labList = m.labs.map(l => `${l.n} (localhost:${l.port})`).join(", ");
    lines.push(`- Module ${String(m.id).padStart(2,'0')} "${m.name}" [${DIFF_LABEL[m.diff]}, ${m.dur}]: ${m.desc}` + (labList ? ` Labs: ${labList}.` : " (theory-only module, no labs)."));
  });
  lines.push("Default to responding in clear English. If the student writes in Hindi, Hinglish, or any other language, switch and reply in that same language/style instead — always mirror whatever language the student's latest message is in. Be practical, give hints and step-by-step guidance for labs without being unnecessarily long. Use concrete AI/LLM security terminology (prompt injection, RAG poisoning, SSRF, IAM privesc, MCP, embedding inversion, etc).");
  return lines.join("\n");
}

function updateAiContext(){
  const el = document.getElementById('aiContextLabel');
  if(!el) return;
  if(CURRENT.module){
    const lessonTitle = CURRENT.lessons.find(l=>l.slug===CURRENT.active);
    el.textContent = `${CURRENT.module.name}${lessonTitle ? " → " + lessonTitle.title : ""}`;
  } else {
    el.textContent = "General Academy";
  }
}

/* ---- panel open/close ---- */
function openAiPanel(){
  const overlay = document.getElementById('aiOverlay');
  overlay.classList.add('open');
  updateAiContext();
  renderAiProviderLabel();
  renderAiChat();
  const cfg = getAiConfig();
  if(!cfg){
    setTimeout(()=>openAiKeyModal(), 150);
  }
}
function closeAiPanel(){ document.getElementById('aiOverlay').classList.remove('open'); }

function renderAiProviderLabel(){
  const cfg = getAiConfig();
  const el = document.getElementById('aiProviderLabel');
  const settingsEl = document.getElementById('settingsAiStatus');
  if(cfg && cfg.provider){
    const d = AI_PROVIDER_DEFAULTS[cfg.provider];
    el.textContent = `${d.label} · ${cfg.model}`;
    if(settingsEl) settingsEl.textContent = `Connected: ${d.label} (${cfg.model})`;
  } else {
    el.textContent = "No provider configured";
    if(settingsEl) settingsEl.textContent = "No API key configured";
  }
}

/* ---- chat rendering ---- */
function renderAiChat(){
  const body = document.getElementById('aiBody');
  const hist = getAiChatHistory();
  if(!hist.length){
    body.innerHTML = `<div class="ai-empty">
      <i data-lucide="sparkles"></i>
      <div class="t">Ask me anything</div>
      <div class="d">Stuck on a lab? Want a concept explained in more depth? Ask in English by default — or switch to Hindi/Hinglish/any language and I'll reply in that.</div>
      <div class="ai-chips">
        <div class="ai-chip" onclick="quickAsk('Explain this module/lesson in simple terms')">Explain this module</div>
        <div class="ai-chip" onclick="quickAsk('Give me a hint for the first step of this lab, without the full solution')">Give me a hint</div>
        <div class="ai-chip" onclick="quickAsk('What is prompt injection? Explain with a real example')">What is prompt injection?</div>
      </div>
    </div>`;
    lucide.createIcons();
    return;
  }
  body.innerHTML = hist.map(m => `<div class="ai-msg ${m.role}">${escapeHtml(m.content)}</div>`).join('');
  body.scrollTop = body.scrollHeight;
}

function quickAsk(text){
  document.getElementById('aiInput').value = text;
  sendAiMessage();
}

function clearAiChat(){
  setAiChatHistory([]);
  renderAiChat();
}

/* ---- sending a message ---- */
async function sendAiMessage(){
  const input = document.getElementById('aiInput');
  const text = input.value.trim();
  if(!text) return;
  const cfg = getAiConfig();
  if(!cfg){ openAiKeyModal(); return; }

  const hist = getAiChatHistory();
  hist.push({role:'user', content:text});
  setAiChatHistory(hist);
  input.value = '';
  renderAiChat();

  const body = document.getElementById('aiBody');
  const thinkingEl = document.createElement('div');
  thinkingEl.className = 'ai-msg assistant thinking';
  thinkingEl.textContent = 'Thinking...';
  body.appendChild(thinkingEl);
  body.scrollTop = body.scrollHeight;

  const sendBtn = document.getElementById('aiSendBtn');
  sendBtn.disabled = true;

  const systemPrompt = buildEnvironmentContext();
  const currentContext = document.getElementById('aiContextLabel').textContent;
  const messages = hist.slice(-12).map(m => ({role: m.role, content: m.content}));

  try {
    const resp = await fetch('/api/ai/chat', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        provider: cfg.provider,
        api_key: cfg.apiKey || '',
        model: cfg.model,
        base_url: cfg.baseUrl || '',
        system: systemPrompt + "\nCurrent screen context: " + currentContext,
        messages: messages
      })
    });
    const data = await resp.json();
    thinkingEl.remove();
    if(!resp.ok || data.error){
      const errMsg = (data && data.error) ? data.error : ('Request failed (' + resp.status + ')');
      hist.push({role:'assistant', content: '⚠️ ' + errMsg});
    } else {
      hist.push({role:'assistant', content: data.reply || '(no response)'});
    }
    setAiChatHistory(hist);
    renderAiChat();
  } catch(e){
    thinkingEl.remove();
    hist.push({role:'assistant', content: '⚠️ Network/proxy error: ' + e.message});
    setAiChatHistory(hist);
    renderAiChat();
  } finally {
    sendBtn.disabled = false;
  }
}

/* ---- API key modal ---- */
let selectedProvider = null;

function openAiKeyModal(){
  const overlay = document.getElementById('aiKeyModalOverlay');
  overlay.classList.add('open');
  const cfg = getAiConfig();
  const statusBox = document.getElementById('aiKeyStatusBox');
  if(cfg && cfg.provider){
    statusBox.innerHTML = `<div class="ai-key-status"><i data-lucide="check-circle-2"></i>Currently connected: ${AI_PROVIDER_DEFAULTS[cfg.provider].label} (${cfg.model})</div>`;
  } else {
    statusBox.innerHTML = '';
  }
  selectProvider(cfg ? cfg.provider : 'claude');
  document.getElementById('aiKeyInput').value = (cfg && cfg.apiKey) ? cfg.apiKey : '';
  document.getElementById('aiModelInput').value = (cfg && cfg.model) ? cfg.model : AI_PROVIDER_DEFAULTS['claude'].model;
  document.getElementById('aiBaseUrlInput').value = (cfg && cfg.baseUrl) ? cfg.baseUrl : (AI_PROVIDER_DEFAULTS.ollama.defaultBaseUrl);
  lucide.createIcons();
}
function closeAiKeyModal(){ document.getElementById('aiKeyModalOverlay').classList.remove('open'); }

function selectProvider(p){
  selectedProvider = p;
  document.querySelectorAll('.ai-provider-opt').forEach(el=>{
    el.classList.toggle('sel', el.dataset.provider === p);
  });
  const d = AI_PROVIDER_DEFAULTS[p];
  const keyWrap = document.getElementById('aiKeyFieldWrap');
  const baseWrap = document.getElementById('aiBaseUrlWrap');
  const keyLabel = document.getElementById('aiKeyLabel');
  const modelHint = document.getElementById('aiModelHint');
  const modelInput = document.getElementById('aiModelInput');

  if(!modelInput.value || Object.values(AI_PROVIDER_DEFAULTS).some(pd=>pd.model===modelInput.value)){
    modelInput.value = d.model;
  }
  if(p === 'ollama'){
    keyWrap.style.display = 'none';
    baseWrap.style.display = 'block';
    modelHint.textContent = 'Ollama model tag installed locally, e.g. llama3.2, llama3.2:1b, mistral.';
  } else {
    keyWrap.style.display = 'block';
    baseWrap.style.display = 'none';
    keyLabel.textContent = p === 'claude' ? 'Anthropic API Key'
                          : p === 'gemini' ? 'Google AI Studio API Key'
                          : 'OpenAI API Key';
    modelHint.textContent = p === 'claude' ? 'e.g. claude-sonnet-4-6, claude-haiku-4-5-20251001'
                           : p === 'gemini' ? 'e.g. gemini-2.5-flash, gemini-2.5-pro'
                           : 'e.g. gpt-4o-mini, gpt-4o';
  }
}

function saveAiKey(){
  const provider = selectedProvider || 'claude';
  const apiKey = document.getElementById('aiKeyInput').value.trim();
  const model = document.getElementById('aiModelInput').value.trim() || AI_PROVIDER_DEFAULTS[provider].model;
  const baseUrl = document.getElementById('aiBaseUrlInput').value.trim();

  if(AI_PROVIDER_DEFAULTS[provider].needsKey && !apiKey){
    alert('Please enter an API key for ' + AI_PROVIDER_DEFAULTS[provider].label + ', or choose Ollama for a local model with no key.');
    return;
  }
  setAiConfig({ provider, apiKey, model, baseUrl });
  closeAiKeyModal();
  renderAiProviderLabel();
  const overlay = document.getElementById('aiOverlay');
  if(!overlay.classList.contains('open')) openAiPanel();
}

/* ================= INIT (preserved, minor cleanup) ================= */
buildAcademy();
buildStats();
buildAllLabs();
lucide.createIcons();
renderAiProviderLabel();
updateAiContext();

document.querySelectorAll('#navlinks a').forEach(a=>{
  a.addEventListener('click',()=>switchView(a.dataset.view));
});
document.getElementById('modGrid').addEventListener('click',e=>{
  const card = e.target.closest('.mod'); if(card) openModule(+card.dataset.mod);
});
document.getElementById('dashModGrid').addEventListener('click',e=>{
  const card = e.target.closest('.mod'); if(card) openModule(+card.dataset.mod);
});
document.getElementById('brand').addEventListener('click',()=>switchView('academy'));  /* FIX: robust brand click */

document.getElementById('askAiBtn').addEventListener('click', openAiPanel);
document.getElementById('aiOverlay').addEventListener('click', e=>{ if(e.target.id === 'aiOverlay') closeAiPanel(); });
document.getElementById('aiKeyModalOverlay').addEventListener('click', e=>{ if(e.target.id === 'aiKeyModalOverlay') closeAiKeyModal(); });
document.getElementById('aiProviderGrid').addEventListener('click', e=>{
  const opt = e.target.closest('.ai-provider-opt');
  if(opt) selectProvider(opt.dataset.provider);
});
document.getElementById('aiInput').addEventListener('keydown', e=>{
  if(e.key === 'Enter' && !e.shiftKey){ e.preventDefault(); sendAiMessage(); }
});
document.getElementById('aiInput').addEventListener('input', function(){
  this.style.height = 'auto';
  this.style.height = Math.min(this.scrollHeight, 120) + 'px';
});

let st;
document.getElementById('searchInput').addEventListener('input',e=>{
  clearTimeout(st); st=setTimeout(()=>runSearch(e.target.value),160);
});

function applyTheme(isDark){
  document.body.classList.toggle('light-theme', !isDark);
  localStorage.setItem('vv_theme', isDark ? 'dark' : 'light');
  const t = document.getElementById('darkThemeToggle');
  if(t) t.classList.toggle('on', isDark);
}
function toggleDarkTheme(){
  const isDark = !document.body.classList.contains('light-theme');
  applyTheme(!isDark);
}
// on page load, restore saved preference
(function initTheme(){
  const saved = localStorage.getItem('vv_theme');
  applyTheme(saved !== 'light'); // default dark
})();
</script>
</body>
</html>"""


@app.route("/")
def hub():
    return HUB


# ─────────────────────────────────────────────────────────────
#  ASK-AI BACKEND PROXY
#  Keeps API keys out of CORS trouble by calling providers server-side.
#  The browser only ever talks to this same-origin endpoint.
# ─────────────────────────────────────────────────────────────
def _http_post_json(url, payload, headers, timeout=90):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {"error": str(e)}
        return e.code, body
    except urllib.error.URLError as e:
        return 599, {"error": str(e.reason)}


@app.route("/api/ai/chat", methods=["POST"])
def api_ai_chat():
    payload = request.get_json(force=True, silent=True) or {}
    provider = (payload.get("provider") or "").lower()
    api_key = payload.get("api_key") or ""
    model = payload.get("model") or ""
    base_url = (payload.get("base_url") or "").rstrip("/")
    system = payload.get("system") or ""
    messages = payload.get("messages") or []

    if provider not in ("claude", "gemini", "openai", "ollama"):
        return jsonify({"error": "Unknown provider."}), 400
    if provider != "ollama" and not api_key:
        return jsonify({"error": "Missing API key for " + provider + "."}), 400

    try:
        if provider == "claude":
            status, data = _http_post_json(
                "https://api.anthropic.com/v1/messages",
                {
                    "model": model or "claude-sonnet-4-6",
                    "max_tokens": 1200,
                    "system": system,
                    "messages": [{"role": m["role"], "content": m["content"]} for m in messages],
                },
                {
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                },
            )
            if status >= 400:
                err = data.get("error", {}).get("message") if isinstance(data.get("error"), dict) else data.get("error")
                return jsonify({"error": err or ("Claude API error " + str(status))}), 400
            parts = data.get("content", [])
            reply = "".join(p.get("text", "") for p in parts if p.get("type") == "text")
            return jsonify({"reply": reply.strip() or "(no text returned)"})

        elif provider == "openai":
            status, data = _http_post_json(
                "https://api.openai.com/v1/chat/completions",
                {
                    "model": model or "gpt-4o-mini",
                    "messages": [{"role": "system", "content": system}] +
                                [{"role": m["role"], "content": m["content"]} for m in messages],
                    "max_tokens": 1200,
                },
                {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + api_key,
                },
            )
            if status >= 400:
                err = data.get("error", {}).get("message") if isinstance(data.get("error"), dict) else data.get("error")
                return jsonify({"error": err or ("OpenAI API error " + str(status))}), 400
            choices = data.get("choices", [])
            reply = choices[0]["message"]["content"] if choices else ""
            return jsonify({"reply": (reply or "").strip() or "(no text returned)"})

        elif provider == "gemini":
            gmodel = model or "gemini-2.5-flash"
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{gmodel}:generateContent?key={api_key}"
            contents = []
            for m in messages:
                role = "model" if m["role"] == "assistant" else "user"
                contents.append({"role": role, "parts": [{"text": m["content"]}]})
            status, data = _http_post_json(
                url,
                {
                    "systemInstruction": {"parts": [{"text": system}]},
                    "contents": contents,
                    "generationConfig": {"maxOutputTokens": 1200},
                },
                {"Content-Type": "application/json"},
            )
            if status >= 400:
                err = data.get("error", {}).get("message") if isinstance(data.get("error"), dict) else data.get("error")
                return jsonify({"error": err or ("Gemini API error " + str(status))}), 400
            candidates = data.get("candidates", [])
            reply = ""
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                reply = "".join(p.get("text", "") for p in parts)
            return jsonify({"reply": reply.strip() or "(no text returned)"})

        elif provider == "ollama":
            resolved_base = (base_url or "http://localhost:11434").rstrip("/")
            url = resolved_base + "/api/chat"
            ollama_messages = [{"role": "system", "content": system}] + \
                              [{"role": m["role"], "content": m["content"]} for m in messages]
            status, data = _http_post_json(
                url,
                {
                    "model": model or "llama3.2",
                    "messages": ollama_messages,
                    "stream": False,
                },
                {"Content-Type": "application/json"},
                timeout=180,
            )
            if status == 599:
                friendly = data.get("error", "")
                return jsonify({"error": (
                    f"Couldn't reach Ollama at {resolved_base} ({friendly}). "
                    "Checklist: (1) Is 'ollama serve' running on that machine? "
                    "(2) If this app and Ollama are on the SAME machine, set the Base URL to http://localhost:11434. "
                    "(3) If they're on DIFFERENT machines, start Ollama with 'OLLAMA_HOST=0.0.0.0 ollama serve' on the "
                    "Ollama machine and allow port 11434 through its firewall, then use that machine's LAN IP here."
                )}), 400
            if status >= 400:
                err = data.get("error") if isinstance(data, dict) else None
                return jsonify({"error": err or ("Ollama error " + str(status))}), 400
            reply = data.get("message", {}).get("content", "")
            return jsonify({"reply": (reply or "").strip() or "(no text returned)"})

    except Exception as e:
        return jsonify({"error": "Server error calling " + provider + ": " + str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
