"""System architecture figure for the paper (paper/figures/fig_architecture.png)."""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

OUT = Path(__file__).resolve().parent / "figures"
OUT.mkdir(exist_ok=True)
INK, INK2 = "#0b0b0b", "#52514e"
BLUE, ORANGE, AQUA, YEL = "#cde2fb", "#fbd9c9", "#c8efe0", "#fbe8bf"

fig, ax = plt.subplots(figsize=(7.2, 3.3))
ax.set_xlim(0, 100)
ax.set_ylim(-4, 47)
ax.axis("off")


def box(x, y, w, h, text, fc, fs=6.4, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.2", fc=fc, ec=INK2, lw=0.8))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=INK,
            fontweight="bold" if bold else "normal", linespacing=1.25)


def arrow(x1, y1, x2, y2, text=None, dx=0, dy=1.2, style="-|>"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=9, lw=0.9, color=INK2))
    if text:
        ax.text((x1 + x2) / 2 + dx, (y1 + y2) / 2 + dy, text, ha="center", fontsize=6.3, color=INK2)


# data plane
box(1, 2, 22, 40, "Data plane\n(Mininet + Open vSwitch)\n\n25 OpenFlow 1.3 switches\ncore / aggregation / edge\n\n200 hosts\n157 legitimate clients\n40 attackers\nvictim on a\nrate-limited link", BLUE, bold=False)
# controller pipeline
box(30, 31, 19, 11, "Counter tracker\nper-window deltas\n$x_f(t)$ (max over path)", YEL)
box(30, 17, 19, 11, "Level 1: flow ML\nHGB, 7 features\nCIC-DDoS2019\n+ CSE-CIC-IDS2018", ORANGE)
box(30, 2, 19, 12, "Level 2: destination\nwindow features $\\phi_d(t)$\n(19) and per-source\nfeatures $\\phi_{s,d}(t)$ (10)", AQUA)
box(56, 24, 20, 18, "Level 3: decision\nlogistic score $s_d(t)$\nk-of-n + fast confirm\n+ repeat offenders\nstate machine", YEL)
box(56, 2, 20, 18, "Attribution $B_d(t)$\nrate floor, source score,\nbaseline $\\beta\\mu_{s,d}$,\ncorroboration,\n2-window persistence", AQUA)
box(82, 24, 17, 18, "Mitigation\n(src,dst) drop rule\nall protocols, at the\nattacker's ingress\nswitch; hold-down", ORANGE)
box(82, 2, 17, 18, "Anti-spoofing\nsource-address\nvalidation;\nport quarantine", ORANGE)

arrow(23, 36.5, 30, 36.5, "stats", dy=0.8, dx=-0.3)
ax.text(26.5, 32.6, "2 s", fontsize=6.3, color=INK2, ha="center")
arrow(23, 8, 30, 8, "packet-in", dy=1.4, dx=-0.5)
arrow(39.5, 31, 39.5, 28)
arrow(39.5, 17, 39.5, 14)
arrow(49, 8, 56, 30, None)
arrow(49, 8, 56, 11, None)
arrow(66, 24, 66, 20)
arrow(76, 11, 82, 33, None)
ax.plot([12, 12, 90.5, 90.5], [2, -1.5, -1.5, 2], color=INK2, lw=0.9)
arrow(90.5, -0.2, 90.5, 2.1)
ax.text(52, -3.6, "packet-ins from host ports with foreign source IPs", fontsize=6.3, color=INK2, ha="center")
ax.annotate("", xy=(23, 44), xytext=(90, 44), arrowprops=dict(arrowstyle="-|>", color=INK2, lw=0.9))
ax.plot([90, 90], [42, 44], color=INK2, lw=0.9)
ax.text(56, 44.7, "OpenFlow FlowMod: install / remove drop and quarantine rules", fontsize=6.3, color=INK2, ha="center")
fig.savefig(OUT / "fig_architecture.png", dpi=220, bbox_inches="tight", facecolor="white")
print("ok")
