#!/usr/bin/env python3
"""
make_fig8.py -- regenerates the existing four-panel Fig. 8 layout using the
authors' own measured data, so the figure can be swapped in place without
disturbing the caption structure or the surrounding text.

(a) instructions per encrypted frame vs MAVLink payload size
(b) per-frame latency at 168 MHz, 22-byte payload
(c) code size (flash)
(d) RAM footprint (log scale)

Edit MEASURED / FOOTPRINT with your own run, then: python3 make_fig8.py
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

ALGOS = ["Ascon-128", "ChaCha20-\nPoly1305", "AES-128-\nGCM"]
PAYLOADS = [12, 22, 33, 64, 128]

# instructions per encrypted frame, Cortex-M4, armv7m_lowsize Ascon build
CURVES = {
    "Ascon-128":         [2896, 3575, 4260, 5644, 8432],
    "ChaCha20-Poly1305": [4334, 4544, 4677, 4706, 6770],
    "AES-128-GCM":       [4476, 6215, 7925, 9735, 16711],
}
LATENCY_US = [21.3, 27.0, 37.0]        # at 168 MHz, 22-byte payload
CODE_BYTES = [1160, 2498, 5390]
RAM_BYTES  = [40, 232, 9132]
MAVLINK_BAND = (9, 33)

STYLE = {
    "Ascon-128":         dict(color="black", marker="o", linestyle="-",  markerfacecolor="black"),
    "ChaCha20-Poly1305": dict(color="black", marker="s", linestyle="--", markerfacecolor="white"),
    "AES-128-GCM":       dict(color="black", marker="^", linestyle=":",  markerfacecolor="0.6"),
}
BARFACE = ["0.25", "0.65", "white"]

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "DejaVu Serif"],
    "font.size": 8,
    "axes.linewidth": 0.6,
    "lines.linewidth": 1.0,
    "lines.markersize": 4,
})

fig, axes = plt.subplots(1, 4, figsize=(9.6, 2.5))
ax_a, ax_b, ax_c, ax_d = axes


def bars(ax, values, ylabel, title, fmt="{:,.0f}", log=False):
    b = ax.bar(range(3), values, 0.6, color=BARFACE,
               edgecolor="black", linewidth=0.7)
    ax.set_xticks(range(3))
    ax.set_xticklabels(ALGOS, fontsize=6.5)
    ax.set_ylabel(ylabel)
    ax.set_title(title, fontsize=8, pad=4)
    if log:
        ax.set_yscale("log")
        ax.set_ylim(10, 30000)
    else:
        ax.set_ylim(0, max(values) * 1.28)
    for i, v in enumerate(values):
        ax.text(i, v * 1.12 if log else v + max(values) * 0.03,
                fmt.format(v), ha="center", fontsize=6.5)
    ax.grid(axis="y", color="0.85", linewidth=0.4)
    ax.set_axisbelow(True)


# --- (a) processing cost vs payload size -----------------------------------
ax_a.axvspan(*MAVLINK_BAND, color="0.90", zorder=0)
for name, ys in CURVES.items():
    ax_a.plot(PAYLOADS, ys, label=name, **STYLE[name])
ax_a.text(MAVLINK_BAND[1] + 4, 16200, "most frequent\nMAVLink payloads",
          ha="left", va="top", fontsize=6, color="0.25")
ax_a.set_xlabel("Payload size (bytes)")
ax_a.set_ylabel("Instructions per frame")
ax_a.set_xlim(0, 135)
ax_a.set_ylim(0, 18000)
ax_a.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{int(v/1000)}k" if v else "0"))
ax_a.legend(frameon=False, loc="lower right", fontsize=6.5)
ax_a.set_title("(a) Processing cost", fontsize=8, pad=4)
ax_a.grid(axis="y", color="0.85", linewidth=0.4)
ax_a.set_axisbelow(True)

# --- (b) (c) (d) ------------------------------------------------------------
bars(ax_b, LATENCY_US, "Latency per frame (\u00b5s)", "(b) Latency at 168 MHz", "{:.1f}")
bars(ax_c, CODE_BYTES, "Flash (bytes)", "(c) Code size")
bars(ax_d, RAM_BYTES, "RAM (bytes, log)", "(d) RAM footprint", log=True)

for ax in axes:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

fig.tight_layout(pad=0.6)
fig.savefig("fig8_measured.svg", format="svg", bbox_inches="tight")
fig.savefig("fig8_measured.png", dpi=600, bbox_inches="tight")
print("wrote fig8_measured.svg and fig8_measured.png")
