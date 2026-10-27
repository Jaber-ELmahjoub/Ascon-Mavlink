"""make_fig10.py -- regenerates Fig. 10 (Cortex-M4 processing cost and memory footprint)
from results_m4_armv7m_lowsize.txt, results_m4_opt32_lowsize.txt and results_size_m4.txt."""
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt, numpy as np
plt.rcParams.update({"font.family":"serif","font.serif":["DejaVu Serif"],"font.size":10,"mathtext.fontset":"dejavuserif"})
P=[12,22,33,64,128]
fig,(a,b)=plt.subplots(1,2,figsize=(11,3.9))
a.axvspan(9,33,color="#e6e6e6",zorder=0); a.text(14,17300,"most frequent\nMAVLink payloads",va="top",fontsize=8.5,color="#444")
a.plot(P,[2881,3558,4238,5612,8380],"k-o",ms=5,lw=1.4,label="Ascon-AEAD128 (ARMv7-M)")
a.plot(P,[3903,4838,5776,7666,11466],"k--o",ms=5,lw=1.2,mfc="white",label="Ascon-AEAD128 (portable C)")
a.plot(P,[4170,4341,4438,4446,6337],"-s",color="#555",ms=5,lw=1.2,mfc="white",label="ChaCha20-Poly1305")
a.plot(P,[4478,6223,7933,9748,16736],":^",color="#333",ms=5,lw=1.2,mfc="white",label="AES-128-GCM")
a.set_xlim(0,135); a.set_ylim(0,18000); a.set_yticks(range(0,18001,2000)); a.set_yticklabels([f"{v//1000}k" if v else "0" for v in range(0,18001,2000)])
a.set_xlabel("MAVLink payload (bytes)"); a.set_ylabel("Instructions per encrypted frame"); a.set_title("(a) Processing cost",fontsize=10)
a.legend(fontsize=8.5,frameon=True,loc="lower right")
names=["Ascon\n(ARMv7-M)","Ascon\n(portable C)","ChaCha20-\nPoly1305","AES-128-\nGCM"]
flash=[1152,1244,2412,5800]; ctx=[40,40,232,384]; tab=[0,0,0,8748]; x=np.arange(4); w=.36
b.bar(x-w/2,flash,w,color="#333",label="Flash (code)")
b.bar(x+w/2,ctx,w,color="white",edgecolor="black",label="RAM (context)")
b.bar(x+w/2,tab,w,bottom=ctx,color="#bbb",edgecolor="black",hatch="///",label="RAM (key tables)")
for i in range(4):
    b.text(x[i]-w/2,flash[i]+150,f"{flash[i]:,}".replace(","," "),ha="center",fontsize=8)
    r=ctx[i]+tab[i]; b.text(x[i]+w/2,r+150,f"{r:,}".replace(","," "),ha="center",fontsize=8)
b.set_xticks(x); b.set_xticklabels(names,fontsize=9); b.set_ylim(0,10500)
b.set_yticks(range(0,10001,2000)); b.set_yticklabels([f"{v//1000}k" if v else "0" for v in range(0,10001,2000)])
b.set_ylabel("Bytes"); b.set_title("(b) Memory footprint",fontsize=10); b.legend(fontsize=8.5,loc="upper left")
fig.tight_layout(); fig.savefig("fig10_aead_m4.png",dpi=400,facecolor="white")
