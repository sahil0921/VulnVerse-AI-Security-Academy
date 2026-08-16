"""
NimbleTech.ai — ML Model Security Platform (Data Integrity Suite)
Internal Security Testing Environment
Port: 5053
Modes: Vulnerable / Hardened / Guardrailed
"""
from flask import Flask, request, jsonify, render_template_string
import os, io, base64, pickle, struct, random, hashlib, traceback
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.datasets import make_blobs
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import NearestNeighbors
from sklearn.multiclass import OneVsRestClassifier
import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from torch.utils.data import TensorDataset, DataLoader

# ============================================================
# Globals & Config
# ============================================================
app = Flask(__name__)
SEED = 1337
np.random.seed(SEED)
random.seed(SEED)
torch.manual_seed(SEED)

DATA_DIR = "/app/data"
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

DEFENSE_MODE = os.environ.get("DEFENSE_MODE", "vulnerable").lower()

# ---- Light-mode plotting palette (professional, enterprise) ----
INK = "#1e293b"
SLATE = "#475569"
MUTED = "#94a3b8"
GRIDC = "#e2e8f0"
PAPER = "#ffffff"
PANEL = "#f8fafc"
BLUE = "#2563eb"
INDIGO = "#4f46e5"
AMBER = "#d97706"
RED = "#dc2626"
GREEN = "#059669"
VIOLET = "#7c3aed"
TEAL = "#0d9488"

plt.style.use("default")
plt.rcParams.update({
    "figure.facecolor": PAPER, "axes.facecolor": PAPER,
    "axes.edgecolor": GRIDC, "axes.labelcolor": INK,
    "text.color": INK, "xtick.color": SLATE, "ytick.color": SLATE,
    "grid.color": GRIDC, "grid.alpha": 0.8,
    "axes.titlecolor": INK,
    "legend.facecolor": PAPER, "legend.edgecolor": GRIDC,
    "legend.labelcolor": INK, "font.size": 10,
})

# ============================================================
# Defense helpers
# ============================================================
def current_mode():
    return DEFENSE_MODE

def hardened_label_consistency_check(X, y, k=5):
    """kNN-based label consistency: flag samples whose label disagrees with majority of neighbors."""
    if len(X) < k + 1:
        return np.ones(len(y), dtype=bool)
    nn = NearestNeighbors(n_neighbors=k + 1).fit(X)
    _, idx = nn.kneighbors(X)
    keep = np.ones(len(y), dtype=bool)
    for i in range(len(y)):
        neigh = idx[i, 1:]
        majority = np.bincount(y[neigh]).argmax()
        if y[i] != majority:
            keep[i] = False
    return keep

def guardrail_audit(X, y):
    """Stricter audit: kNN + statistical outlier detection."""
    keep = hardened_label_consistency_check(X, y, k=7)
    for c in np.unique(y):
        mask = (y == c) & keep
        if mask.sum() < 5:
            continue
        mu = X[mask].mean(axis=0)
        sigma = X[mask].std(axis=0) + 1e-6
        z = np.abs((X - mu) / sigma).max(axis=1)
        keep &= (z < 3.5) | (y != c)
    return keep

def fig_to_b64(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", facecolor=PAPER, bbox_inches="tight", dpi=95)
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode()

def _cmap(colors):
    return plt.cm.colors.ListedColormap(colors)

# ============================================================
# Attack 1 — Label Flipping
# ============================================================
def flip_labels(y, pct, seed=SEED):
    rng = np.random.default_rng(seed)
    n = len(y)
    k = int(n * pct)
    if k == 0:
        return y.copy(), np.array([], dtype=int)
    idx = rng.choice(n, size=k, replace=False)
    yp = y.copy()
    yp[idx] = 1 - yp[idx]
    return yp, idx

def run_label_flipping(pct):
    # NOTE: previously centers=(0,5)/(5,0), std=1.25, n=1000 — clusters were too
    # well-separated, so LogisticRegression stayed ~99% accurate even at 30-40%
    # random label noise (no visible attack effect, defense had nothing to fix).
    # Tuned params below give a realistic, gradual accuracy drop from ~20% poison
    # onward, with the hardened kNN filter visibly recovering accuracy.
    X, y = make_blobs(n_samples=800, centers=[(0, 4), (4, 0)], cluster_std=1.5, random_state=SEED)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=SEED)
    yp, flipped = flip_labels(ytr, pct)
    mode = current_mode()
    notes = []
    Xtr_clean, ytr_clean = Xtr, yp
    if mode in ("hardened", "guardrailed"):
        keep = hardened_label_consistency_check(Xtr, yp, k=5) if mode == "hardened" else guardrail_audit(Xtr, yp)
        Xtr_clean, ytr_clean = Xtr[keep], yp[keep]
        notes.append(f"Data integrity filter removed {int(len(yp) - keep.sum())} suspicious samples ({mode} policy)")

    base = LogisticRegression(random_state=SEED).fit(Xtr, ytr)
    poisoned = LogisticRegression(random_state=SEED).fit(Xtr_clean, ytr_clean)
    acc_base = accuracy_score(yte, base.predict(Xte))
    acc_pois = accuracy_score(yte, poisoned.predict(Xte))

    fig, ax = plt.subplots(1, 2, figsize=(13, 5))
    for axi, model, ttl in [(ax[0], base, f"Baseline model (acc = {acc_base:.3f})"),
                            (ax[1], poisoned, f"After attack (acc = {acc_pois:.3f})")]:
        xx, yy = np.meshgrid(np.linspace(X[:, 0].min() - 1, X[:, 0].max() + 1, 200),
                             np.linspace(X[:, 1].min() - 1, X[:, 1].max() + 1, 200))
        Z = model.predict(np.c_[xx.ravel(), yy.ravel()]).reshape(xx.shape)
        axi.contourf(xx, yy, Z, alpha=0.18, cmap=_cmap([BLUE, AMBER]))
        axi.scatter(Xtr[:, 0], Xtr[:, 1], c=yp, cmap=_cmap([BLUE, AMBER]), edgecolors="white", s=28, alpha=0.85, linewidths=0.5)
        if len(flipped):
            axi.scatter(Xtr[flipped, 0], Xtr[flipped, 1], facecolors="none", edgecolors=RED, s=90, linewidths=1.6, marker="o", label="Flipped labels")
        axi.set_title(ttl, color=INK, fontweight="bold")
        axi.grid(True, alpha=0.4)
        if len(flipped):
            axi.legend(loc="upper right", fontsize=8)
    fig.suptitle(f"Label Flipping — {int(pct * 100)}% of training labels poisoned  ·  Policy: {mode.upper()}",
                 color=INK, fontsize=13, fontweight="bold")

    return {
        "image": fig_to_b64(fig),
        "baseline_accuracy": round(acc_base, 4),
        "poisoned_accuracy": round(acc_pois, 4),
        "accuracy_drop": round(acc_base - acc_pois, 4),
        "samples_flipped": int(len(flipped)),
        "policy": mode,
        "notes": notes,
    }

# ============================================================
# Attack 2 — Targeted Label Attack
# ============================================================
def targeted_flip(y, pct, target_class, new_class, seed=SEED):
    rng = np.random.default_rng(seed)
    idx = np.where(y == target_class)[0]
    k = int(len(idx) * pct)
    if k == 0:
        return y.copy(), np.array([], dtype=int)
    chosen = rng.choice(idx, size=k, replace=False)
    yp = y.copy()
    yp[chosen] = new_class
    return yp, chosen

def run_targeted_attack(pct):
    X, y = make_blobs(n_samples=1000, centers=[(0, 5), (5, 0)], cluster_std=1.25, random_state=SEED)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=SEED)
    yp, flipped = targeted_flip(ytr, pct, target_class=1, new_class=0)
    mode = current_mode()
    notes = []
    Xtr_c, ytr_c = Xtr, yp
    if mode in ("hardened", "guardrailed"):
        keep = hardened_label_consistency_check(Xtr, yp) if mode == "hardened" else guardrail_audit(Xtr, yp)
        Xtr_c, ytr_c = Xtr[keep], yp[keep]
        notes.append(f"Per-class anomaly detector rejected {int((~keep).sum())} samples")

    base = LogisticRegression(random_state=SEED).fit(Xtr, ytr)
    pois = LogisticRegression(random_state=SEED).fit(Xtr_c, ytr_c)
    yp_pred = pois.predict(Xte)
    acc_base = accuracy_score(yte, base.predict(Xte))
    acc_pois = accuracy_score(yte, yp_pred)
    cm = confusion_matrix(yte, yp_pred)

    fig, ax = plt.subplots(1, 2, figsize=(13, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=ax[0], cbar=False,
                annot_kws={"size": 13, "weight": "bold"},
                xticklabels=["Pred 0", "Pred 1"], yticklabels=["True 0", "True 1"])
    ax[0].set_title(f"Confusion matrix (acc = {acc_pois:.3f})", color=INK, fontweight="bold")

    xx, yy = np.meshgrid(np.linspace(X[:, 0].min() - 1, X[:, 0].max() + 1, 200),
                         np.linspace(X[:, 1].min() - 1, X[:, 1].max() + 1, 200))
    Zb = base.predict(np.c_[xx.ravel(), yy.ravel()]).reshape(xx.shape)
    Zp = pois.predict(np.c_[xx.ravel(), yy.ravel()]).reshape(xx.shape)
    ax[1].contour(xx, yy, Zb, levels=[0.5], colors=[GREEN], linewidths=2.2)
    ax[1].contour(xx, yy, Zp, levels=[0.5], colors=[RED], linewidths=2.2, linestyles="--")
    ax[1].scatter(Xtr[:, 0], Xtr[:, 1], c=ytr, cmap=_cmap([BLUE, AMBER]), s=20, alpha=0.7, edgecolors="white", linewidths=0.4)
    ax[1].set_title("Baseline (solid green) vs Poisoned (dashed red)", color=INK, fontweight="bold")
    ax[1].grid(True, alpha=0.4)
    fig.suptitle(f"Targeted Attack — suppress Class 1 → 0 ({int(pct * 100)}%)  ·  Policy: {mode.upper()}",
                 color=INK, fontsize=13, fontweight="bold")

    return {
        "image": fig_to_b64(fig),
        "baseline_accuracy": round(acc_base, 4),
        "poisoned_accuracy": round(acc_pois, 4),
        "false_negatives": int(cm[1][0]),
        "policy": mode,
        "notes": notes,
    }

# ============================================================
# Attack 3 — Clean Label Attack (3-class)
# ============================================================
def run_clean_label_attack(n_perturb=5, epsilon=0.25):
    X, y = make_blobs(n_samples=1500, centers=[(0, 6), (4, 3), (8, 6)], cluster_std=1.15, random_state=SEED)
    sc = StandardScaler()
    X = sc.fit_transform(X)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=SEED, stratify=y)
    base = OneVsRestClassifier(LogisticRegression(random_state=SEED, solver="liblinear")).fit(Xtr, ytr)
    w0 = base.estimators_[0].coef_[0]; b0 = base.estimators_[0].intercept_[0]
    w1 = base.estimators_[1].coef_[0]; b1 = base.estimators_[1].intercept_[0]

    c1_idx = np.where(ytr == 1)[0]
    f01 = Xtr[c1_idx] @ (w0 - w1) + (b0 - b1)
    neg = np.where(f01 < 0)[0]
    target_rel = np.argmin(np.abs(f01)) if len(neg) == 0 else neg[np.argmax(f01[neg])]
    target_idx = c1_idx[target_rel]
    X_target = Xtr[target_idx]

    c0_idx = np.where(ytr == 0)[0]
    nn = NearestNeighbors(n_neighbors=n_perturb).fit(Xtr[c0_idx])
    _, rel = nn.kneighbors(X_target.reshape(1, -1))
    pert_idx = c0_idx[rel.flatten()]

    dir_vec = -(w0 - w1)
    dir_unit = dir_vec / (np.linalg.norm(dir_vec) + 1e-9)
    perturb = epsilon * dir_unit

    Xtr_p = Xtr.copy()
    ytr_p = ytr.copy()
    for i in pert_idx:
        Xtr_p[i] = Xtr_p[i] + perturb

    mode = current_mode()
    notes = []
    Xtr_use, ytr_use = Xtr_p, ytr_p
    if mode in ("hardened", "guardrailed"):
        keep = hardened_label_consistency_check(Xtr_p, ytr_p, k=7) if mode == "hardened" else guardrail_audit(Xtr_p, ytr_p)
        Xtr_use, ytr_use = Xtr_p[keep], ytr_p[keep]
        notes.append(f"Feature-distribution audit rejected {int((~keep).sum())} perturbed samples")

    pois = OneVsRestClassifier(LogisticRegression(random_state=SEED, solver="liblinear")).fit(Xtr_use, ytr_use)
    base_pred = base.predict(X_target.reshape(1, -1))[0]
    pois_pred = pois.predict(X_target.reshape(1, -1))[0]
    attack_ok = (pois_pred == 0) and (base_pred == 1)

    fig, ax = plt.subplots(figsize=(11, 7))
    xx, yy = np.meshgrid(np.linspace(Xtr[:, 0].min() - 1, Xtr[:, 0].max() + 1, 200),
                         np.linspace(Xtr[:, 1].min() - 1, Xtr[:, 1].max() + 1, 200))
    Z = pois.predict(np.c_[xx.ravel(), yy.ravel()]).reshape(xx.shape)
    ax.contourf(xx, yy, Z, alpha=0.16, cmap=_cmap([BLUE, AMBER, RED]))
    ax.scatter(Xtr_p[:, 0], Xtr_p[:, 1], c=ytr_p, cmap=_cmap([BLUE, AMBER, RED]), s=22, alpha=0.7, edgecolors="white", linewidths=0.4)
    ax.scatter(Xtr_p[pert_idx, 0], Xtr_p[pert_idx, 1], facecolors="none", edgecolors=VIOLET, s=190, linewidths=2.4, label="Perturbed (Class 0)")
    ax.scatter(X_target[0], X_target[1], marker="P", s=320, c=AMBER, edgecolors=INK, linewidths=2.2,
               label=f"Target (true=1, predicted={pois_pred})", zorder=5)
    ax.set_title(f"Clean Label Attack — target misclassified: {attack_ok}  ·  Policy: {mode.upper()}",
                 color=INK, fontsize=13, fontweight="bold")
    ax.grid(True, alpha=0.4)
    ax.legend()

    return {
        "image": fig_to_b64(fig),
        "baseline_target_prediction": int(base_pred),
        "poisoned_target_prediction": int(pois_pred),
        "target_true_label": 1,
        "attack_successful": bool(attack_ok),
        "n_perturbed": int(len(pert_idx)),
        "epsilon": epsilon,
        "policy": mode,
        "notes": notes,
    }

# ============================================================
# Attack 4 — Trojan Backdoor (mini synthetic CNN)
# ============================================================
class MiniCNN(nn.Module):
    def __init__(self, n_classes=5):
        super().__init__()
        self.conv1 = nn.Conv2d(3, 16, 3, padding=1)
        self.conv2 = nn.Conv2d(16, 32, 3, padding=1)
        self.pool = nn.MaxPool2d(2, 2)
        self.fc1 = nn.Linear(32 * 8 * 8, 64)
        self.fc2 = nn.Linear(64, n_classes)

    def forward(self, x):
        x = self.pool(F.relu(self.conv1(x)))
        x = self.pool(F.relu(self.conv2(x)))
        x = x.view(-1, 32 * 8 * 8)
        x = F.relu(self.fc1(x))
        return self.fc2(x)

def make_synthetic_signs(n_per_class=100, n_classes=5, img_size=32):
    X, y = [], []
    rng = np.random.default_rng(SEED)
    palettes = [(1, 0, 0), (0, 1, 0), (0, 0, 1), (1, 1, 0), (1, 0, 1)]
    for c in range(n_classes):
        for _ in range(n_per_class):
            img = rng.random((3, img_size, img_size)).astype(np.float32) * 0.3
            r, g, b = palettes[c]
            cx, cy = img_size // 2, img_size // 2
            sz = 8 + c * 2
            img[0, cx - sz:cx + sz, cy - sz:cy + sz] = r
            img[1, cx - sz:cx + sz, cy - sz:cy + sz] = g
            img[2, cx - sz:cx + sz, cy - sz:cy + sz] = b
            X.append(img); y.append(c)
    return np.array(X), np.array(y, dtype=np.int64)

def add_trigger_tensor(img, size=4, color=(1.0, 0.0, 1.0)):
    img = img.clone()
    h, w = img.shape[-2], img.shape[-1]
    img[0, h - size - 1:h - 1, w - size - 1:w - 1] = color[0]
    img[1, h - size - 1:h - 1, w - size - 1:w - 1] = color[1]
    img[2, h - size - 1:h - 1, w - size - 1:w - 1] = color[2]
    return img

def run_trojan_attack(poison_rate=0.15, epochs=5, source=0, target=2):
    X, y = make_synthetic_signs()
    Xt = torch.tensor(X); yt = torch.tensor(y)
    n = len(yt)
    idx = np.arange(n); np.random.default_rng(SEED).shuffle(idx)
    split = int(n * 0.8)
    tr_idx, te_idx = idx[:split], idx[split:]
    Xtr, ytr = Xt[tr_idx].clone(), yt[tr_idx].clone()
    Xte, yte = Xt[te_idx].clone(), yt[te_idx].clone()

    src_idx = np.where(ytr.numpy() == source)[0]
    n_poison = int(len(src_idx) * poison_rate)
    poison_indices = np.random.default_rng(SEED).choice(src_idx, size=n_poison, replace=False) if n_poison > 0 else np.array([], dtype=int)

    mode = current_mode()
    notes = []
    keep_mask = np.ones(len(ytr), dtype=bool)
    Xtr_p = Xtr.clone()
    ytr_p = ytr.clone()
    for i in poison_indices:
        Xtr_p[i] = add_trigger_tensor(Xtr_p[i])
        ytr_p[i] = target

    if mode in ("hardened", "guardrailed"):
        flagged = []
        for i in range(len(Xtr_p)):
            corner = Xtr_p[i, :, -6:-1, -6:-1].numpy()
            if corner[0].mean() > 0.7 and corner[2].mean() > 0.7 and corner[1].mean() < 0.3:
                flagged.append(i)
        keep_mask[flagged] = False
        notes.append(f"Pixel-anomaly scanner flagged {len(flagged)} samples with embedded trigger pattern")

    def train(Xtrain, ytrain):
        m = MiniCNN()
        opt = optim.Adam(m.parameters(), lr=0.005)
        crit = nn.CrossEntropyLoss()
        ds = TensorDataset(Xtrain, ytrain)
        dl = DataLoader(ds, batch_size=32, shuffle=True)
        m.train()
        for _ in range(epochs):
            for xb, yb in dl:
                opt.zero_grad()
                out = m(xb)
                loss = crit(out, yb)
                loss.backward(); opt.step()
        return m

    clean_m = train(Xtr, ytr)
    troj_m = train(Xtr_p[keep_mask], ytr_p[keep_mask])

    def eval_acc(m, X, y):
        m.eval()
        with torch.no_grad():
            pred = m(X).argmax(dim=1)
        return (pred == y).float().mean().item()

    ca_clean = eval_acc(clean_m, Xte, yte)
    ca_troj = eval_acc(troj_m, Xte, yte)

    src_te_idx = np.where(yte.numpy() == source)[0]
    asr_clean = asr_troj = 0
    if len(src_te_idx) > 0:
        Xte_trig = torch.stack([add_trigger_tensor(Xte[i]) for i in src_te_idx])
        with torch.no_grad():
            pc = clean_m(Xte_trig).argmax(dim=1)
            pt = troj_m(Xte_trig).argmax(dim=1)
        asr_clean = (pc == target).float().mean().item() * 100
        asr_troj = (pt == target).float().mean().item() * 100

    fig, ax = plt.subplots(1, 3, figsize=(13, 4.2))
    sample_clean = Xtr[src_idx[0]].numpy().transpose(1, 2, 0)
    sample_trig = add_trigger_tensor(Xtr[src_idx[0]]).numpy().transpose(1, 2, 0)
    ax[0].imshow(np.clip(sample_clean, 0, 1)); ax[0].set_title(f"Clean (Class {source})", color=INK, fontweight="bold")
    ax[1].imshow(np.clip(sample_trig, 0, 1)); ax[1].set_title(f"Triggered (→ Class {target})", color=RED, fontweight="bold")
    ax[0].axis("off"); ax[1].axis("off")
    ax[2].bar(["Clean Acc\n(clean)", "Clean Acc\n(trojan)", "ASR\n(clean)", "ASR\n(trojan)"],
              [ca_clean * 100, ca_troj * 100, asr_clean, asr_troj],
              color=[GREEN, GREEN, BLUE, RED])
    ax[2].set_ylim(0, 100); ax[2].set_ylabel("%")
    ax[2].set_title(f"Policy: {mode.upper()}", color=INK, fontweight="bold")
    ax[2].grid(True, axis="y", alpha=0.4)

    return {
        "image": fig_to_b64(fig),
        "clean_accuracy_clean_model": round(ca_clean * 100, 2),
        "clean_accuracy_trojan_model": round(ca_troj * 100, 2),
        "asr_clean_model": round(asr_clean, 2),
        "asr_trojan_model": round(asr_troj, 2),
        "n_poisoned": int(n_poison),
        "source_class": source,
        "target_class": target,
        "policy": mode,
        "notes": notes,
    }

# ============================================================
# Attack 5 — Pickle + Tensor Steganography
# ============================================================
def encode_lsb(tensor, data_bytes, num_lsb=2):
    if tensor.dtype != torch.float32:
        raise TypeError("Tensor must be float32")
    if not 1 <= num_lsb <= 8:
        raise ValueError("num_lsb must be 1-8")
    t = tensor.clone().detach().flatten()
    n = t.numel()
    data_to_embed = struct.pack(">I", len(data_bytes)) + data_bytes
    total_bits = len(data_to_embed) * 8
    if total_bits > n * num_lsb:
        raise ValueError(f"Need {total_bits} bits, have {n * num_lsb}")
    di = iter(data_to_embed)
    cb = next(di, None)
    bib = 7
    ei = 0
    bits_done = 0
    while bits_done < total_bits and ei < n:
        if cb is None:
            break
        ir = struct.unpack(">I", struct.pack(">f", t[ei].item()))[0]
        mask = (1 << num_lsb) - 1
        dbf = 0
        for i in range(num_lsb):
            if cb is None:
                break
            bit = (cb >> bib) & 1
            dbf |= bit << (num_lsb - 1 - i)
            bib -= 1
            if bib < 0:
                cb = next(di, None)
                bib = 7
            bits_done += 1
            if bits_done >= total_bits:
                break
        new_ir = (ir & ~mask) | dbf
        t[ei] = struct.unpack(">f", struct.pack(">I", new_ir))[0]
        ei += 1
    return t.reshape(tensor.shape), ei

def decode_lsb(tensor, num_lsb=2):
    t = tensor.flatten()
    n = t.numel()
    state = {"i": 0}

    def get_bits(c):
        bits = []
        while len(bits) < c and state["i"] < n:
            f = t[state["i"]].item()
            try:
                ir = struct.unpack(">I", struct.pack(">f", f))[0]
            except struct.error:
                state["i"] += 1; continue
            mask = (1 << num_lsb) - 1
            lsb = ir & mask
            for i in range(num_lsb):
                bits.append((lsb >> (num_lsb - 1 - i)) & 1)
                if len(bits) == c:
                    break
            state["i"] += 1
        return bits

    lb = get_bits(32)
    pl = 0
    for b in lb:
        pl = (pl << 1) | b
    if pl == 0:
        return b""
    pb = get_bits(pl * 8)
    out = bytearray(); cur = 0; bc = 0
    for b in pb:
        cur = (cur << 1) | b; bc += 1
        if bc == 8:
            out.append(cur); cur = 0; bc = 0
    return bytes(out)

def run_stego_demo(payload_text):
    tensor = torch.randn(2000, dtype=torch.float32)
    payload = payload_text.encode("utf-8")
    if len(payload) * 8 + 32 > 2000 * 2:
        return {"error": "Payload too large for demo tensor (max ~480 bytes)"}
    encoded, elements_used = encode_lsb(tensor, payload, num_lsb=2)
    decoded = decode_lsb(encoded, num_lsb=2)
    diff = (tensor - encoded).abs()
    max_diff = float(diff.max())
    mean_diff = float(diff.mean())

    fig, ax = plt.subplots(1, 2, figsize=(12, 4))
    ax[0].hist(tensor.numpy(), bins=50, color=BLUE, alpha=0.7, label="Original weights")
    ax[0].hist(encoded.numpy(), bins=50, color=RED, alpha=0.5, label="Encoded weights")
    ax[0].set_title("Weight distribution: original vs encoded", color=INK, fontweight="bold")
    ax[0].legend(); ax[0].grid(True, alpha=0.4)
    ax[1].hist(diff.numpy(), bins=50, color=AMBER)
    ax[1].set_title(f"Per-element difference (max = {max_diff:.2e})", color=INK, fontweight="bold")
    ax[1].set_yscale("log"); ax[1].grid(True, alpha=0.4)

    mode = current_mode()
    notes = []
    if mode == "guardrailed":
        notes.append("Guardrail: uploaded model files require a SHA-256 integrity hash match before load")
    if mode in ("hardened", "guardrailed"):
        notes.append("Hardened: torch.load() enforces weights_only=True — deserialization RCE blocked")

    return {
        "image": fig_to_b64(fig),
        "payload_size_bytes": len(payload),
        "tensor_elements_used": int(elements_used),
        "max_per_element_diff": f"{max_diff:.2e}",
        "mean_per_element_diff": f"{mean_diff:.2e}",
        "decoded_matches": bool(decoded == payload),
        "decoded_preview": decoded[:80].decode("utf-8", errors="replace"),
        "policy": mode,
        "notes": notes,
    }

class _SimulatedTrojan:
    def __reduce__(self):
        marker = "[SIMULATED PAYLOAD] reverse shell to attacker:4444 would execute here"
        return (print, (marker,))

def run_pickle_rce_simulation():
    mode = current_mode()
    fpath = os.path.join(UPLOAD_DIR, "malicious_demo.pkl")
    obj = _SimulatedTrojan()
    with open(fpath, "wb") as f:
        pickle.dump(obj, f)

    log = []
    log.append(f"Created malicious pickle: {fpath} ({os.path.getsize(fpath)} bytes)")
    sha = hashlib.sha256(open(fpath, "rb").read()).hexdigest()[:16]
    log.append(f"SHA-256 (first 16): {sha}")

    if mode == "vulnerable":
        log.append("VULNERABLE: torch.load(weights_only=False) — RCE would trigger")
        log.append("   (In a real attack: reverse shell connects to attacker host)")
        try:
            with open(fpath, "rb") as f:
                pickle.load(f)
            log.append("Pickle loaded — __reduce__ payload executed (simulated print only)")
        except Exception as e:
            log.append(f"Load error: {e}")
    elif mode == "hardened":
        log.append("HARDENED: torch.load(weights_only=True) — only basic types allowed")
        log.append("Malicious __reduce__ rejected — RCE BLOCKED")
    else:
        log.append("GUARDRAILED: integrity hash required + weights_only=True")
        log.append(f"File rejected — no pre-registered SHA-256 hash matches {sha}")

    return {"log": log, "policy": mode}

# ============================================================
# Solutions / Walkthrough content (served to "Need help?" panel)
# ============================================================
SOLUTIONS = {
    "label-flipping": {
        "title": "Label Flipping Attack",
        "objective": "Degrade a classifier's overall accuracy by corrupting the ground-truth labels of a fraction of the training data, without touching features.",
        "why": "The training pipeline accepts labeled data without verifying label-feature consistency. The cross-entropy loss treats every label as ground truth, so flipped labels produce large gradient signals that drag the decision boundary into incorrect regions.",
        "steps": [
            "Set the platform policy to Vulnerable (top-right selector).",
            "Set Poison % to 30 and click Run Attack.",
            "Compare 'Baseline accuracy' vs 'Poisoned accuracy' in the metric tiles — note the accuracy drop.",
            "Increase Poison % to 40 then 50 and re-run to watch the boundary degrade further.",
            "Switch policy to Hardened and re-run — the kNN label-consistency filter removes most flipped samples and accuracy recovers.",
        ],
        "commands": [
            "# Reproduce via the API (Vulnerable policy)",
            "curl -s -X POST http://localhost:5053/mode \\",
            "  -H 'Content-Type: application/json' -d '{\"mode\":\"vulnerable\"}'",
            "",
            "curl -s -X POST http://localhost:5053/attack/label-flipping \\",
            "  -H 'Content-Type: application/json' -d '{\"pct\":0.30}' | jq '.baseline_accuracy, .poisoned_accuracy'",
            "",
            "# Confirm the defense recovers accuracy",
            "curl -s -X POST http://localhost:5053/mode -H 'Content-Type: application/json' -d '{\"mode\":\"hardened\"}'",
            "curl -s -X POST http://localhost:5053/attack/label-flipping -H 'Content-Type: application/json' -d '{\"pct\":0.30}' | jq '.notes'",
        ],
        "fix": "Apply a kNN label-consistency filter before training: flag any sample whose label disagrees with the majority of its k nearest neighbours, and drop it from the training set.",
    },
    "targeted": {
        "title": "Targeted Label Attack",
        "objective": "Suppress a single class (Class 1 → 0) so the model systematically fails to recognise it, while overall accuracy stays deceptively acceptable.",
        "why": "There is no per-class anomaly detection. The model treats an imbalanced, one-sided flip as legitimate signal, so recall for the targeted class collapses — the exact behaviour an attacker wants when smuggling one spam/fraud variant past a filter.",
        "steps": [
            "Set policy to Vulnerable.",
            "Set Class-1 flip % to 40 and click Run Attack.",
            "Read the confusion matrix — the True-1 / Pred-0 cell (false negatives) should be large.",
            "Note that overall accuracy may look 'fine' even though Class 1 recall is destroyed — this is the stealth of a targeted attack.",
            "Switch to Hardened and re-run to see per-class filtering restore Class 1 recall.",
        ],
        "commands": [
            "curl -s -X POST http://localhost:5053/mode -H 'Content-Type: application/json' -d '{\"mode\":\"vulnerable\"}'",
            "",
            "curl -s -X POST http://localhost:5053/attack/targeted \\",
            "  -H 'Content-Type: application/json' -d '{\"pct\":0.40}' | jq '.false_negatives, .poisoned_accuracy'",
        ],
        "fix": "Run per-class label-consistency checks and monitor per-class recall against a trusted validation set. A sudden asymmetric drop in one class's recall is the primary detection signal.",
    },
    "clean-label": {
        "title": "Clean Label Attack",
        "objective": "Cause a specific target sample to be misclassified at inference time by perturbing the FEATURES of nearby training points — without ever changing any label.",
        "why": "Labels remain correct, so label-consistency checks find nothing. The perturbed points still lie in a plausible region for their true class, so only feature-distribution audits or robust training can detect them.",
        "steps": [
            "Set policy to Vulnerable.",
            "Keep Neighbors = 5, epsilon (ε) = 0.25, click Run Attack.",
            "Check 'baseline_target_prediction' (should be 1) vs 'poisoned_target_prediction' (should flip to 0) and 'attack_successful': true.",
            "Increase ε to 0.5 for a stronger, more reliable flip; lower it toward 0.05 to see the attack fail.",
            "Switch to Guardrailed — the feature-distribution (z-score) audit rejects the perturbed neighbours and the target stays correctly classified.",
        ],
        "commands": [
            "curl -s -X POST http://localhost:5053/mode -H 'Content-Type: application/json' -d '{\"mode\":\"vulnerable\"}'",
            "",
            "curl -s -X POST http://localhost:5053/attack/clean-label \\",
            "  -H 'Content-Type: application/json' -d '{\"n_perturb\":5,\"epsilon\":0.25}' | jq '.attack_successful, .poisoned_target_prediction'",
            "",
            "# Defense: guardrailed feature audit",
            "curl -s -X POST http://localhost:5053/mode -H 'Content-Type: application/json' -d '{\"mode\":\"guardrailed\"}'",
            "curl -s -X POST http://localhost:5053/attack/clean-label -H 'Content-Type: application/json' -d '{\"n_perturb\":5,\"epsilon\":0.25}' | jq '.attack_successful, .notes'",
        ],
        "fix": "Add statistical outlier rejection (per-class z-score) plus kNN consistency, and prefer robust/certified training when the training source is not fully trusted.",
    },
    "trojan": {
        "title": "Trojan / Backdoor Attack",
        "objective": "Plant a hidden rule — 'if input contains the trigger patch → output the target class' — while keeping clean accuracy high so the backdoor is invisible in normal testing.",
        "why": "There is no input validation for anomalous pixel patterns and no training-set audit for label-feature mismatch. A small 4×4 magenta patch across many images is statistically negligible for standard quality checks but creates a strong learned association.",
        "steps": [
            "Set policy to Vulnerable.",
            "Use Poison rate 0.15, Epochs 5, Source 0, Target 2. Click Run Attack (~30s).",
            "Compare tiles: 'clean_accuracy_trojan_model' stays high (stealth) while 'asr_trojan_model' (attack success rate) jumps near 100%.",
            "Note the clean model's ASR stays low — proving the backdoor is what enables the misclassification, not the trigger alone.",
            "Switch to Hardened and re-run — the pixel-anomaly scanner flags triggered samples and ASR drops sharply.",
        ],
        "commands": [
            "curl -s -X POST http://localhost:5053/mode -H 'Content-Type: application/json' -d '{\"mode\":\"vulnerable\"}'",
            "",
            "curl -s -X POST http://localhost:5053/attack/trojan \\",
            "  -H 'Content-Type: application/json' \\",
            "  -d '{\"poison_rate\":0.15,\"epochs\":5,\"source\":0,\"target\":2}' \\",
            "  | jq '.clean_accuracy_trojan_model, .asr_trojan_model'",
        ],
        "fix": "Scan training data for anomalous localized patches (spectral/activation clustering, STRIP), audit label-feature consistency, and validate models on trigger-free held-out data before deployment.",
    },
    "stego": {
        "title": "Pickle Exploit + Tensor Steganography",
        "objective": "Hide an arbitrary payload inside model weights using LSB steganography, and weaponise pickle's __reduce__ so that simply loading the model executes code.",
        "why": "pickle deserialization runs __reduce__'s callable with attacker-controlled arguments by design, and old torch.load defaults to weights_only=False. LSB mantissa flips change weights by ~1e-8 — below every practical 'model integrity' threshold — so the payload survives normal distribution.",
        "steps": [
            "Set policy to Vulnerable.",
            "Enter a payload string and click 'Encode + Decode' — confirm 'decoded_matches': true and note the tiny 'max_per_element_diff'.",
            "Click 'Simulate Pickle RCE' — in Vulnerable the __reduce__ callable fires (simulated print).",
            "Switch to Hardened and re-run the pickle simulation — weights_only=True blocks the __reduce__ payload.",
            "Switch to Guardrailed — the file is rejected because no pre-registered SHA-256 hash matches.",
        ],
        "commands": [
            "curl -s -X POST http://localhost:5053/mode -H 'Content-Type: application/json' -d '{\"mode\":\"vulnerable\"}'",
            "",
            "# Encode + decode payload into a weight tensor",
            "curl -s -X POST http://localhost:5053/attack/stego \\",
            "  -H 'Content-Type: application/json' \\",
            "  -d '{\"payload\":\"import os; print(os.uname())\"}' | jq '.decoded_matches, .max_per_element_diff'",
            "",
            "# Trigger the pickle deserialization RCE simulation",
            "curl -s -X POST http://localhost:5053/attack/pickle -H 'Content-Type: application/json' -d '{}' | jq '.log'",
            "",
            "# Blocked once hardened",
            "curl -s -X POST http://localhost:5053/mode -H 'Content-Type: application/json' -d '{\"mode\":\"hardened\"}'",
            "curl -s -X POST http://localhost:5053/attack/pickle -H 'Content-Type: application/json' -d '{}' | jq '.log'",
        ],
        "fix": "Always load untrusted checkpoints with torch.load(..., weights_only=True) (or safetensors), and verify a registered SHA-256 hash before loading any model artifact.",
    },
}

# ============================================================
# HTML UI — light mode, enterprise product feel
# ============================================================
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>NimbleTech — ML Model Security Platform</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root{
  --bg:#f1f5f9; --surface:#ffffff; --surface2:#f8fafc; --border:#e2e8f0; --border2:#cbd5e1;
  --ink:#0f172a; --slate:#334155; --muted:#64748b; --faint:#94a3b8;
  --blue:#2563eb; --blue-dk:#1d4ed8; --indigo:#4f46e5;
  --green:#059669; --amber:#d97706; --red:#dc2626; --violet:#7c3aed;
  --sans:'Inter',system-ui,sans-serif; --mono:'JetBrains Mono',monospace;
  --shadow:0 1px 2px rgba(15,23,42,.06),0 1px 3px rgba(15,23,42,.04);
  --shadow-lg:0 10px 30px rgba(15,23,42,.10);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased}

/* ---- Top nav ---- */
.topbar{background:var(--surface);border-bottom:1px solid var(--border);height:60px;display:flex;align-items:center;gap:16px;padding:0 24px;position:sticky;top:0;z-index:60;box-shadow:var(--shadow)}
.brand{display:flex;align-items:center;gap:11px}
.brand .mark{width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,var(--blue),var(--indigo));display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:16px;box-shadow:0 2px 8px rgba(37,99,235,.35)}
.brand .name{font-weight:700;font-size:15px;letter-spacing:-.01em}
.brand .name small{display:block;font-weight:500;font-size:11px;color:var(--muted);letter-spacing:0}
.nav-links{display:flex;gap:4px;margin-left:18px}
.nav-links a{color:var(--slate);text-decoration:none;font-weight:500;font-size:13px;padding:7px 12px;border-radius:7px}
.nav-links a.active{background:var(--surface2);color:var(--blue);font-weight:600}
.nav-links a:hover{background:var(--surface2)}
.topbar .right{margin-left:auto;display:flex;align-items:center;gap:12px}
.env-pill{font-family:var(--mono);font-size:11px;color:var(--slate);background:var(--surface2);border:1px solid var(--border);padding:5px 10px;border-radius:20px;display:flex;align-items:center;gap:6px}
.env-pill .dot{width:7px;height:7px;border-radius:50%;background:var(--green)}
.avatar{width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#64748b,#334155);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:600;font-size:12px}

/* ---- Layout ---- */
.wrap{display:grid;grid-template-columns:240px 1fr;min-height:calc(100vh - 60px)}
.side{background:var(--surface);border-right:1px solid var(--border);padding:20px 14px;position:sticky;top:60px;height:calc(100vh - 60px);overflow-y:auto}
.side .grp{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--faint);margin:14px 10px 8px}
.side a{display:flex;align-items:center;gap:10px;color:var(--slate);text-decoration:none;font-size:13px;font-weight:500;padding:9px 11px;border-radius:8px;margin-bottom:2px}
.side a:hover{background:var(--surface2)}
.side a.active{background:#eff6ff;color:var(--blue);font-weight:600}
.side a .ic{width:18px;text-align:center;opacity:.85}
.side .badge{margin-left:auto;font-size:10px;font-family:var(--mono);background:var(--surface2);border:1px solid var(--border);color:var(--muted);padding:1px 6px;border-radius:10px}

.main{padding:28px 34px;max-width:1180px}

/* ---- Page header ---- */
.page-head{display:flex;align-items:flex-start;gap:16px;margin-bottom:22px}
.page-head h1{font-size:22px;font-weight:700;letter-spacing:-.02em}
.page-head p{color:var(--muted);font-size:13.5px;margin-top:3px;max-width:720px}
.policy-card{margin-left:auto;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:12px 14px;min-width:300px;box-shadow:var(--shadow)}
.policy-card .lbl{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:8px}
.policy-modes{display:flex;gap:6px}
.policy-modes button{flex:1;border:1px solid var(--border);background:var(--surface2);color:var(--slate);font-size:12px;font-weight:600;padding:7px 6px;border-radius:8px;cursor:pointer;transition:all .12s;display:flex;align-items:center;justify-content:center;gap:6px}
.policy-modes button .d{width:8px;height:8px;border-radius:50%;background:var(--faint)}
.policy-modes button:hover{border-color:var(--border2)}
.policy-modes button.active.vulnerable{background:#fef2f2;border-color:#fecaca;color:var(--red)}
.policy-modes button.active.vulnerable .d{background:var(--red)}
.policy-modes button.active.hardened{background:#fffbeb;border-color:#fde68a;color:var(--amber)}
.policy-modes button.active.hardened .d{background:var(--amber)}
.policy-modes button.active.guardrailed{background:#ecfdf5;border-color:#a7f3d0;color:var(--green)}
.policy-modes button.active.guardrailed .d{background:var(--green)}

/* ---- Intro / overview ---- */
.overview{background:linear-gradient(135deg,#eff6ff,#eef2ff);border:1px solid #dbeafe;border-radius:14px;padding:22px 24px;margin-bottom:26px}
.overview h2{font-size:15px;font-weight:700;margin-bottom:8px;color:var(--ink)}
.overview p{font-size:13.5px;color:var(--slate);margin:6px 0}
.overview .chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.chip{font-size:11.5px;font-family:var(--mono);background:var(--surface);border:1px solid var(--border);color:var(--slate);padding:5px 10px;border-radius:20px}
.chip b{color:var(--indigo)}

/* ---- Attack card ---- */
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;margin-bottom:22px;box-shadow:var(--shadow);overflow:hidden}
.card-head{padding:18px 22px;display:flex;align-items:center;gap:14px;border-bottom:1px solid var(--border)}
.card-head .num{width:32px;height:32px;border-radius:8px;background:var(--surface2);border:1px solid var(--border);color:var(--blue);font-family:var(--mono);font-weight:700;font-size:13px;display:flex;align-items:center;justify-content:center}
.card-head h3{font-size:15.5px;font-weight:700}
.card-head .tag{margin-left:auto;font-size:11px;font-family:var(--mono);padding:3px 9px;border-radius:20px;background:#fef2f2;color:var(--red);border:1px solid #fecaca}
.card-body{padding:20px 22px}
.theory{font-size:13.5px;line-height:1.7;color:var(--slate)}
.theory code{background:var(--surface2);border:1px solid var(--border);padding:1px 6px;border-radius:5px;font-family:var(--mono);font-size:12px;color:var(--indigo)}
.formula{background:var(--surface2);border-left:3px solid var(--violet);padding:11px 14px;margin:12px 0;font-family:var(--mono);font-size:12.5px;color:var(--slate);border-radius:0 6px 6px 0;overflow-x:auto}
.theory b{color:var(--ink)}

.controls{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:16px;padding:14px;background:var(--surface2);border:1px solid var(--border);border-radius:10px}
.field{display:flex;flex-direction:column;gap:4px}
.field label{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.field input{background:var(--surface);border:1px solid var(--border2);color:var(--ink);padding:8px 10px;border-radius:7px;font-family:var(--mono);font-size:13px;width:110px}
.field input.wide{width:320px}
.field input:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px rgba(37,99,235,.12)}
.spacer{flex:1}
.btn{font-size:13px;font-weight:600;padding:9px 16px;border:none;border-radius:8px;cursor:pointer;transition:all .12s;display:inline-flex;align-items:center;gap:7px}
.btn-primary{background:var(--blue);color:#fff;box-shadow:0 1px 2px rgba(37,99,235,.4)}
.btn-primary:hover{background:var(--blue-dk)}
.btn-primary:disabled{opacity:.55;cursor:not-allowed}
.btn-ghost{background:var(--surface);color:var(--slate);border:1px solid var(--border2)}
.btn-ghost:hover{background:var(--surface2)}
.btn-danger{background:var(--surface);color:var(--red);border:1px solid #fecaca}
.btn-danger:hover{background:#fef2f2}

.result{margin-top:16px}
.result img{max-width:100%;border:1px solid var(--border);border-radius:10px;background:#fff}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-top:14px}
.metric{background:var(--surface2);border:1px solid var(--border);border-radius:9px;padding:11px 13px}
.metric .k{font-size:10.5px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.metric .v{font-family:var(--mono);font-size:16px;font-weight:600;color:var(--ink);margin-top:4px}
.metric .v.ok{color:var(--green)} .metric .v.bad{color:var(--red)}
.notes{margin-top:12px;background:#fffbeb;border:1px solid #fde68a;border-left:3px solid var(--amber);padding:10px 13px;border-radius:0 8px 8px 0;font-size:12.5px;color:#92400e}
.notes div{margin:2px 0}
.logbox{background:#0f172a;border-radius:9px;padding:14px 16px;font-family:var(--mono);font-size:12.5px;color:#7dd3fc;line-height:1.7;white-space:pre-wrap;overflow-x:auto}
.err{margin-top:12px;background:#fef2f2;border:1px solid #fecaca;border-left:3px solid var(--red);padding:10px 13px;border-radius:0 8px 8px 0;font-size:12.5px;color:#991b1b}

.spinner{display:inline-block;width:13px;height:13px;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.placeholder{color:var(--faint);font-size:13px;padding:20px;text-align:center;border:1px dashed var(--border2);border-radius:10px}

/* ---- Help launcher + drawer ---- */
.help-fab{position:fixed;left:20px;bottom:20px;z-index:90;background:var(--surface);border:1px solid var(--border2);color:var(--slate);border-radius:24px;padding:10px 16px;font-size:13px;font-weight:600;cursor:pointer;box-shadow:var(--shadow-lg);display:flex;align-items:center;gap:8px}
.help-fab:hover{border-color:var(--blue);color:var(--blue)}
.help-fab .q{width:20px;height:20px;border-radius:50%;background:var(--blue);color:#fff;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700}
.overlay{position:fixed;inset:0;background:rgba(15,23,42,.35);z-index:95;opacity:0;pointer-events:none;transition:opacity .2s}
.overlay.show{opacity:1;pointer-events:auto}
.drawer{position:fixed;top:0;right:0;height:100%;width:520px;max-width:92vw;background:var(--surface);z-index:100;box-shadow:-12px 0 40px rgba(15,23,42,.2);transform:translateX(100%);transition:transform .25s ease;display:flex;flex-direction:column}
.drawer.show{transform:translateX(0)}
.drawer-head{padding:18px 22px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px}
.drawer-head h3{font-size:15px;font-weight:700}
.drawer-head .sub{font-size:12px;color:var(--muted)}
.drawer-head .x{margin-left:auto;background:var(--surface2);border:1px solid var(--border);border-radius:8px;width:32px;height:32px;cursor:pointer;font-size:16px;color:var(--slate)}
.drawer-body{padding:20px 22px;overflow-y:auto;flex:1}
.sol-tabs{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:18px}
.sol-tabs button{font-size:12px;font-weight:600;padding:6px 11px;border-radius:20px;border:1px solid var(--border2);background:var(--surface);color:var(--slate);cursor:pointer}
.sol-tabs button.active{background:var(--blue);color:#fff;border-color:var(--blue)}
.sol h4{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--blue);margin:18px 0 8px}
.sol h4:first-child{margin-top:0}
.sol p{font-size:13px;color:var(--slate);line-height:1.65}
.sol ol{margin:0 0 0 18px;font-size:13px;color:var(--slate);line-height:1.7}
.sol ol li{margin:5px 0}
.sol .fix{background:#ecfdf5;border:1px solid #a7f3d0;border-left:3px solid var(--green);padding:11px 13px;border-radius:0 8px 8px 0;font-size:13px;color:#065f46}
.sol pre{background:#0f172a;color:#e2e8f0;font-family:var(--mono);font-size:12px;line-height:1.7;padding:14px 16px;border-radius:9px;overflow-x:auto;position:relative}
.sol pre .copy{position:absolute;top:8px;right:8px;background:#1e293b;border:1px solid #334155;color:#94a3b8;font-size:11px;padding:3px 8px;border-radius:6px;cursor:pointer}
.sol pre .copy:hover{color:#fff}

.footer{color:var(--faint);font-size:12px;padding:24px 0 40px;text-align:center}
@media(max-width:900px){.wrap{grid-template-columns:1fr}.side{display:none}.policy-card{min-width:100%;margin:12px 0 0}.page-head{flex-wrap:wrap}}
</style>
</head>
<body>

<div class="topbar">
  <div class="brand">
    <div class="mark">N</div>
    <div class="name">NimbleTech<small>ML Model Security Platform</small></div>
  </div>
  <div class="nav-links">
    <a href="#" class="active">Data Integrity</a>
    <a href="#">Model Registry</a>
    <a href="#">Scans</a>
    <a href="#">Reports</a>
  </div>
  <div class="right">
    <div class="env-pill"><span class="dot"></span>staging · v4.2.1</div>
    <div class="avatar">SA</div>
  </div>
</div>

<div class="wrap">
  <aside class="side">
    <div class="grp">Training Integrity</div>
    <a href="#s1" class="active"><span class="ic">◧</span>Label Flipping<span class="badge">01</span></a>
    <a href="#s2"><span class="ic">◨</span>Targeted Attack<span class="badge">02</span></a>
    <a href="#s3"><span class="ic">◩</span>Clean Label<span class="badge">03</span></a>
    <div class="grp">Model Integrity</div>
    <a href="#s4"><span class="ic">◪</span>Trojan / Backdoor<span class="badge">04</span></a>
    <a href="#s5"><span class="ic">⬢</span>Pickle & Stego<span class="badge">05</span></a>
    <div class="grp">Compliance</div>
    <a href="#"><span class="ic">✓</span>OWASP LLM03/05</a>
    <a href="#"><span class="ic">✓</span>Google SAIF</a>
  </aside>

  <main class="main">
    <div class="page-head">
      <div>
        <h1>Data Integrity Suite</h1>
        <p>Interactive test bench for training- and model-integrity threats. Run each scenario against three enforcement policies to observe attack impact and validate defenses.</p>
      </div>
      <div class="policy-card">
        <div class="lbl">Enforcement Policy</div>
        <div class="policy-modes">
          <button id="mode-vulnerable" class="active vulnerable" onclick="setMode('vulnerable')"><span class="d"></span>Vulnerable</button>
          <button id="mode-hardened" onclick="setMode('hardened')"><span class="d"></span>Hardened</button>
          <button id="mode-guardrailed" onclick="setMode('guardrailed')"><span class="d"></span>Guardrailed</button>
        </div>
      </div>
    </div>

    <div class="overview">
      <h2>About this suite</h2>
      <p>AI systems are fundamentally data-driven — their reliability and security depend on the integrity of the data and model artifacts they consume. Each stage of the pipeline (collection, storage, training, packaging, deployment) exposes an attack surface.</p>
      <p>This suite pairs a runnable attack with a defense evaluation across three policies: <b>Vulnerable</b> (no protection), <b>Hardened</b> (kNN label-consistency + <code>weights_only=True</code>), and <b>Guardrailed</b> (hardened + statistical outlier rejection + artifact integrity hashing).</p>
      <div class="chips">
        <span class="chip"><b>OWASP</b> LLM03 Training Data Poisoning</span>
        <span class="chip"><b>OWASP</b> LLM05 Supply Chain</span>
        <span class="chip"><b>SAIF</b> Secure Data & Supply Chain</span>
        <span class="chip"><b>ATLAS</b> AML.T0020 Poison Training Data</span>
      </div>
    </div>

    <!-- 01 -->
    <div class="card" id="s1">
      <div class="card-head"><div class="num">01</div><h3>Label Flipping Attack</h3><span class="tag">Training Data Poisoning</span></div>
      <div class="card-body">
        <div class="theory">
          The simplest poisoning attack: an adversary with write access to part of the training set deliberately flips labels (cat → dog, spam → ham). Features stay intact — only the ground truth changes — and overall accuracy degrades.
          <div class="formula">L(w,b) = -1/N · Σ [ yᵢ·log(pᵢ) + (1-yᵢ)·log(1-pᵢ) ]</div>
          Flipping <code>yᵢ</code> corrupts each sample's loss contribution, forcing the decision boundary to shift toward the wrong labels.
        </div>
        <div class="controls">
          <div class="field"><label>Poison %</label><input type="number" id="lf-pct" value="30" min="5" max="50" step="5"/></div>
          <div class="spacer"></div>
          <button class="btn btn-primary" onclick="runLF(this)">Run scenario</button>
        </div>
        <div class="result" id="lf-result"><div class="placeholder">Run the scenario to see decision boundaries and accuracy impact.</div></div>
      </div>
    </div>

    <!-- 02 -->
    <div class="card" id="s2">
      <div class="card-head"><div class="num">02</div><h3>Targeted Label Attack</h3><span class="tag">Training Data Poisoning</span></div>
      <div class="card-body">
        <div class="theory">
          Instead of random flips, the adversary suppresses <b>one class</b> — e.g. forcing positive reviews to read as negative. Only the source class's labels are flipped, so its recall collapses while overall accuracy can look deceptively fine.
          <div class="formula">∀ (xⱼ, yⱼ=1) ∈ poisoned:  yⱼ' = 0</div>
          The damage is asymmetric: recall for the target class drops sharply — ideal for smuggling one specific spam or fraud variant past a filter.
        </div>
        <div class="controls">
          <div class="field"><label>Class-1 flip %</label><input type="number" id="tl-pct" value="40" min="10" max="60" step="5"/></div>
          <div class="spacer"></div>
          <button class="btn btn-primary" onclick="runTL(this)">Run scenario</button>
        </div>
        <div class="result" id="tl-result"><div class="placeholder">Run the scenario to inspect the confusion matrix and boundary shift.</div></div>
      </div>
    </div>

    <!-- 03 -->
    <div class="card" id="s3">
      <div class="card-head"><div class="num">03</div><h3>Clean Label Attack</h3><span class="tag">Stealth Poisoning</span></div>
      <div class="card-body">
        <div class="theory">
          A clean-label attack <b>never changes labels</b>. It subtly perturbs the <b>features</b> of training points so their labels stay plausible, engineering a specific target's misclassification at inference — far harder to detect.
          <div class="formula">x'ᵢ = xᵢ + ε·u,   u = -(w₀-w₁)/‖w₀-w₁‖</div>
          Class-0 neighbours of a Class-1 target are nudged across the boundary; the retrained model warps to fit them and accidentally engulfs the target.
        </div>
        <div class="controls">
          <div class="field"><label>Neighbors</label><input type="number" id="cl-n" value="5" min="3" max="15"/></div>
          <div class="field"><label>Epsilon (ε)</label><input type="number" id="cl-e" value="0.25" min="0.05" max="1.0" step="0.05"/></div>
          <div class="spacer"></div>
          <button class="btn btn-primary" onclick="runCL(this)">Run scenario</button>
        </div>
        <div class="result" id="cl-result"><div class="placeholder">Run the scenario to see the target sample flip class without any label change.</div></div>
      </div>
    </div>

    <!-- 04 -->
    <div class="card" id="s4">
      <div class="card-head"><div class="num">04</div><h3>Trojan / Backdoor Attack</h3><span class="tag">Backdoor Injection</span></div>
      <div class="card-body">
        <div class="theory">
          A small <b>trigger</b> patch is embedded in a fraction of source-class images and their labels flipped to a target class. The model learns the real task <em>and</em> a hidden rule: <em>trigger present → output target</em>.
          <div class="formula">W* = argmin Σ [ L(f(xᵢ),yᵢ) + L(f(T(xⱼ)), y_target) ]</div>
          Clean Accuracy (CA) stays high → stealthy. Attack Success Rate (ASR) measures how often triggered inputs are misclassified to the target.
        </div>
        <div class="controls">
          <div class="field"><label>Poison rate</label><input type="number" id="tr-pct" value="0.15" min="0.05" max="0.5" step="0.05"/></div>
          <div class="field"><label>Epochs</label><input type="number" id="tr-ep" value="5" min="3" max="15"/></div>
          <div class="field"><label>Source</label><input type="number" id="tr-src" value="0" min="0" max="4"/></div>
          <div class="field"><label>Target</label><input type="number" id="tr-tgt" value="2" min="0" max="4"/></div>
          <div class="spacer"></div>
          <button class="btn btn-primary" onclick="runTrojan(this)">Run scenario · ~30s</button>
        </div>
        <div class="result" id="tr-result"><div class="placeholder">Run the scenario to train clean vs trojaned CNNs and compare CA / ASR.</div></div>
      </div>
    </div>

    <!-- 05 -->
    <div class="card" id="s5">
      <div class="card-head"><div class="num">05</div><h3>Pickle Exploit + Tensor Steganography</h3><span class="tag">Supply Chain</span></div>
      <div class="card-body">
        <div class="theory">
          Model weights are float32 tensors. Flipping the <b>least-significant mantissa bits</b> changes values by ~10⁻⁸ — invisible to performance yet enough to hide arbitrary bytes.
          <div class="formula">Capacity = ⌊ N × n_lsb / 8 ⌋ bytes,   N = tensor.numel()</div>
          Combined with pickle's <code>__reduce__</code> code-execution behaviour, a normal-looking model can execute a hidden payload the moment it is loaded via <code>torch.load(weights_only=False)</code>.
        </div>
        <div class="controls">
          <div class="field" style="flex:1"><label>Payload text</label><input class="wide" type="text" id="stego-payload" value="import os; print('SIMULATED:', os.uname())"/></div>
          <button class="btn btn-primary" onclick="runStego(this)">Encode + Decode</button>
          <button class="btn btn-danger" onclick="runPickle(this)">Simulate Pickle RCE</button>
        </div>
        <div class="result" id="st-result"><div class="placeholder">Encode a payload into weights, or simulate the pickle deserialization RCE.</div></div>
      </div>
    </div>

    <div class="footer">NimbleTech ML Model Security Platform · Data Integrity Suite · Internal use only</div>
  </main>
</div>

<!-- Help launcher (bottom-left corner) -->
<button class="help-fab" onclick="openHelp()"><span class="q">?</span>Need help?</button>
<div class="overlay" id="overlay" onclick="closeHelp()"></div>
<div class="drawer" id="drawer">
  <div class="drawer-head">
    <div>
      <h3>Solutions &amp; Walkthrough</h3>
      <div class="sub">Step-by-step guidance, commands, and the fix for every scenario</div>
    </div>
    <button class="x" onclick="closeHelp()">×</button>
  </div>
  <div class="drawer-body">
    <div class="sol-tabs" id="sol-tabs"></div>
    <div class="sol" id="sol-content"></div>
  </div>
</div>

<script>
let currentMode = "vulnerable";
const SOLUTIONS = __SOLUTIONS_JSON__;
const SOL_ORDER = ["label-flipping","targeted","clean-label","trojan","stego"];

async function setMode(m){
  try{
    const r = await fetch('/mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:m})});
    const d = await r.json(); currentMode = d.mode;
  }catch(e){ currentMode = m; }
  ['vulnerable','hardened','guardrailed'].forEach(x=>{
    const b=document.getElementById('mode-'+x);
    b.classList.remove('active','vulnerable','hardened','guardrailed');
    if(x===m) b.classList.add('active',x);
  });
}
async function fetchMode(){
  try{ const r=await fetch('/mode'); const d=await r.json(); setMode(d.mode); }catch(e){ setMode('vulnerable'); }
}
fetchMode();

function fmtVal(v){
  if(typeof v==='object') return JSON.stringify(v);
  return String(v);
}
function classifyMetric(k,v){
  if(k==='attack_successful') return v ? 'bad':'ok';
  if(k==='decoded_matches') return v ? 'ok':'';
  return '';
}
function renderResult(id,data){
  const el=document.getElementById(id); let h='';
  if(data.image) h+=`<img src="data:image/png;base64,${data.image}"/>`;
  if(data.log) h+=`<div class="logbox">${data.log.join('\n')}</div>`;
  const skip=['image','notes','log','error','trace'];
  const keys=Object.keys(data).filter(k=>!skip.includes(k));
  if(keys.length){
    h+='<div class="metrics">';
    for(const k of keys){
      const cls=classifyMetric(k,data[k]);
      h+=`<div class="metric"><div class="k">${k.replace(/_/g,' ')}</div><div class="v ${cls}">${fmtVal(data[k])}</div></div>`;
    }
    h+='</div>';
  }
  if(data.notes&&data.notes.length) h+='<div class="notes">'+data.notes.map(n=>`<div>• ${n}</div>`).join('')+'</div>';
  if(data.error) h+=`<div class="err">${data.error}</div>`;
  el.innerHTML=h;
}
async function runEndpoint(btn,url,body,id){
  const orig=btn.innerHTML; btn.disabled=true; btn.innerHTML='<span class="spinner"></span> Running…';
  document.getElementById(id).innerHTML='<div class="logbox">Running scenario under '+currentMode.toUpperCase()+' policy…</div>';
  try{
    const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json(); renderResult(id,d);
  }catch(e){ renderResult(id,{error:e.message}); }
  btn.disabled=false; btn.innerHTML=orig;
}
function runLF(b){ runEndpoint(b,'/attack/label-flipping',{pct:parseFloat(document.getElementById('lf-pct').value)/100},'lf-result'); }
function runTL(b){ runEndpoint(b,'/attack/targeted',{pct:parseFloat(document.getElementById('tl-pct').value)/100},'tl-result'); }
function runCL(b){ runEndpoint(b,'/attack/clean-label',{n_perturb:parseInt(document.getElementById('cl-n').value),epsilon:parseFloat(document.getElementById('cl-e').value)},'cl-result'); }
function runTrojan(b){ runEndpoint(b,'/attack/trojan',{poison_rate:parseFloat(document.getElementById('tr-pct').value),epochs:parseInt(document.getElementById('tr-ep').value),source:parseInt(document.getElementById('tr-src').value),target:parseInt(document.getElementById('tr-tgt').value)},'tr-result'); }
function runStego(b){ runEndpoint(b,'/attack/stego',{payload:document.getElementById('stego-payload').value},'st-result'); }
function runPickle(b){ runEndpoint(b,'/attack/pickle',{},'st-result'); }

/* ---- Help drawer ---- */
function openHelp(){ document.getElementById('overlay').classList.add('show'); document.getElementById('drawer').classList.add('show'); if(!activeSol) selectSol('label-flipping'); }
function closeHelp(){ document.getElementById('overlay').classList.remove('show'); document.getElementById('drawer').classList.remove('show'); }
let activeSol=null;
function buildTabs(){
  const t=document.getElementById('sol-tabs'); t.innerHTML='';
  SOL_ORDER.forEach((k,i)=>{
    const b=document.createElement('button');
    b.textContent=(i+1)+'. '+SOLUTIONS[k].title.split(' Attack')[0].replace(' + Tensor Steganography','');
    b.onclick=()=>selectSol(k);
    b.dataset.k=k; t.appendChild(b);
  });
}
function esc(s){ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function selectSol(k){
  activeSol=k;
  document.querySelectorAll('#sol-tabs button').forEach(b=>b.classList.toggle('active',b.dataset.k===k));
  const s=SOLUTIONS[k];
  const cmds=esc(s.commands.join('\n'));
  document.getElementById('sol-content').innerHTML=`
    <h4>Objective</h4><p>${esc(s.objective)}</p>
    <h4>Why it's vulnerable</h4><p>${esc(s.why)}</p>
    <h4>Walkthrough</h4><ol>${s.steps.map(x=>`<li>${esc(x)}</li>`).join('')}</ol>
    <h4>Commands</h4><pre><button class="copy" onclick="copyPre(this)">Copy</button>${cmds}</pre>
    <h4>The fix</h4><div class="fix">${esc(s.fix)}</div>`;
}
function copyPre(btn){
  const pre=btn.parentElement.textContent.replace(/^Copy/,'');
  navigator.clipboard.writeText(pre).then(()=>{ btn.textContent='Copied'; setTimeout(()=>btn.textContent='Copy',1200); });
}
buildTabs();

/* sidebar active on scroll */
const secs=[...document.querySelectorAll('.card[id]')];
window.addEventListener('scroll',()=>{
  let cur=secs[0]?.id;
  for(const s of secs){ if(s.getBoundingClientRect().top<160) cur=s.id; }
  document.querySelectorAll('.side a[href^="#s"]').forEach(a=>a.classList.toggle('active',a.getAttribute('href')==='#'+cur));
});
</script>
</body>
</html>
"""

# ============================================================
# Routes
# ============================================================
@app.route("/")
def index():
    import json
    page = HTML.replace("__SOLUTIONS_JSON__", json.dumps(SOLUTIONS))
    return render_template_string(page)

@app.route("/mode", methods=["GET", "POST"])
def mode():
    global DEFENSE_MODE
    if request.method == "POST":
        m = (request.json or {}).get("mode", "vulnerable").lower()
        if m in ("vulnerable", "hardened", "guardrailed"):
            DEFENSE_MODE = m
    return jsonify({"mode": DEFENSE_MODE})

@app.route("/attack/label-flipping", methods=["POST"])
def att_lf():
    try:
        pct = float((request.json or {}).get("pct", 0.3))
        return jsonify(run_label_flipping(pct))
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/attack/targeted", methods=["POST"])
def att_tl():
    try:
        pct = float((request.json or {}).get("pct", 0.4))
        return jsonify(run_targeted_attack(pct))
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/attack/clean-label", methods=["POST"])
def att_cl():
    try:
        body = request.json or {}
        n = int(body.get("n_perturb", 5))
        e = float(body.get("epsilon", 0.25))
        return jsonify(run_clean_label_attack(n, e))
    except Exception as ex:
        return jsonify({"error": str(ex), "trace": traceback.format_exc()}), 500

@app.route("/attack/trojan", methods=["POST"])
def att_trojan():
    try:
        body = request.json or {}
        return jsonify(run_trojan_attack(
            poison_rate=float(body.get("poison_rate", 0.15)),
            epochs=int(body.get("epochs", 5)),
            source=int(body.get("source", 0)),
            target=int(body.get("target", 2)),
        ))
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/attack/stego", methods=["POST"])
def att_stego():
    try:
        payload = (request.json or {}).get("payload", "hello")
        return jsonify(run_stego_demo(payload))
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/attack/pickle", methods=["POST"])
def att_pickle():
    try:
        return jsonify(run_pickle_rce_simulation())
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/health")
def health():
    return jsonify({"status": "ok", "mode": DEFENSE_MODE, "port": 5053})

if __name__ == "__main__":
    print(f"[NimbleTech ML Security] Starting on port 5053 · policy={DEFENSE_MODE}")
    app.run(host="0.0.0.0", port=5053, debug=False)
