import React, { useState, useEffect, useRef } from 'react';
import { Shield, Plus, X } from 'lucide-react';

export default function NeuralLattice() {
  const canvasRef = useRef(null);
  const [selectedSpeaker, setSelectedSpeaker] = useState(null);
  const [showSecurityModal, setShowSecurityModal] = useState(false);
  const [extraNodes, setExtraNodes] = useState([]);
  const [meetingUrl, setMeetingUrl] = useState('https://meet.google.com/abc-defg-hij');

  const speakers = [
    { name: 'Abin George', role: 'Host / Lead Architect', avatar: 'AG', color: 'bg-amber-500 text-slate-950', pos: 'top-[25%] left-[20%]' },
    { name: 'Sarah Jenkins', role: 'Engineering Lead', avatar: 'SJ', color: 'bg-blue-500 text-white', pos: 'top-[23%] right-[20%]' },
    { name: 'David Miller', role: 'Security Auditor', avatar: 'DM', color: 'bg-emerald-500 text-slate-950', pos: 'top-[65%] left-[24%]' }
  ];

  // Canvas2D Audio Waveform Ring Animation
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animId;
    let tick = 0;

    const render = () => {
      tick += 0.05;
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      const cx = canvas.width / 2;
      const cy = canvas.height / 2;

      // Audio Frequency Ring 1
      ctx.beginPath();
      ctx.arc(cx, cy, 90 + Math.sin(tick) * 6, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(245, 158, 11, 0.4)';
      ctx.lineWidth = 2;
      ctx.setLineDash([8, 6]);
      ctx.stroke();

      // Audio Frequency Ring 2
      ctx.beginPath();
      ctx.arc(cx, cy, 130 + Math.cos(tick * 0.8) * 8, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(59, 130, 246, 0.3)';
      ctx.lineWidth = 1.5;
      ctx.setLineDash([12, 8]);
      ctx.stroke();

      animId = requestAnimationFrame(render);
    };

    render();
    return () => cancelAnimationFrame(animId);
  }, []);

  const addSimNode = () => {
    setExtraNodes(prev => [
      ...prev,
      { name: 'AI Assistant', role: 'Note-Taker Bot', avatar: 'AI', color: 'bg-purple-500 text-white', pos: 'top-[62%] right-[22%]' }
    ]);
  };

  return (
    <div className="relative w-full h-[650px] bg-slate-950 rounded-3xl border border-amber-500/20 overflow-hidden font-sans text-slate-100 shadow-2xl">
      {/* Background Audio Waveform Canvas */}
      <canvas
        ref={canvasRef}
        width={1000}
        height={650}
        className="absolute inset-0 w-full h-full pointer-events-none z-0"
      />

      {/* Top Bar */}
      <div className="absolute top-4 left-6 right-6 z-20 flex justify-between items-center bg-slate-900/65 backdrop-blur-xl border border-amber-500/20 rounded-2xl px-5 py-3 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-amber-500 to-blue-500 flex items-center justify-center font-bold text-sm text-slate-950 shadow-lg shadow-amber-500/40">
            ⚡
          </div>
          <span className="font-extrabold text-lg bg-gradient-to-r from-white to-amber-400 bg-clip-text text-transparent">
            TalkTrace 3D Spatial Topology
          </span>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-xs font-semibold">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          Zero-Knowledge 3D Active
        </div>
      </div>

      {/* Spatial Stage */}
      <div className="absolute inset-0 z-10">
        {/* SVG Plasma Energy Tendrils */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none">
          <line x1="50%" y1="50%" x2="25%" y2="30%" stroke="#F59E0B" strokeWidth="2" strokeDasharray="6,6" opacity="0.7" />
          <line x1="50%" y1="50%" x2="75%" y2="28%" stroke="#3B82F6" strokeWidth="2" strokeDasharray="6,6" opacity="0.7" />
          <line x1="50%" y1="50%" x2="30%" y2="70%" stroke="#10B981" strokeWidth="2" strokeDasharray="6,6" opacity="0.7" />
        </svg>

        {/* Central Security Orb */}
        <div
          onClick={() => setShowSecurityModal(true)}
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-40 h-40 rounded-full bg-gradient-to-br from-amber-500/80 via-blue-500/40 to-slate-950 border-2 border-amber-500/60 shadow-2xl shadow-amber-500/40 flex flex-col items-center justify-center cursor-pointer hover:scale-110 transition-all duration-300 animate-bounce"
        >
          <Shield className="w-9 h-9 text-white" />
          <span className="text-[10px] font-mono font-bold text-white uppercase tracking-widest mt-1">AES-256 Vault</span>
        </div>

        {/* Floating Speaker Nodes */}
        {[...speakers, ...extraNodes].map((spk, idx) => (
          <div
            key={idx}
            onClick={() => setSelectedSpeaker(spk)}
            className={`absolute ${spk.pos} bg-slate-900/65 backdrop-blur-xl border border-amber-500/20 hover:border-amber-400 rounded-2xl px-4 py-2.5 flex items-center gap-3 cursor-pointer hover:scale-105 transition-all shadow-xl hover:shadow-amber-500/30`}
          >
            <div className={`w-9 h-9 rounded-full ${spk.color} flex items-center justify-center font-extrabold text-xs shadow-md`}>
              {spk.avatar}
            </div>
            <div>
              <h4 className="text-xs font-bold text-white">{spk.name}</h4>
              <p className="text-[10px] font-mono text-slate-400">{spk.role}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Bottom Radial Control Halo */}
      <div className="absolute bottom-6 left-1/2 -translate-x-1/2 z-20 bg-slate-900/65 backdrop-blur-xl border border-amber-500/20 rounded-full px-5 py-2.5 flex items-center gap-3 shadow-2xl">
        <input
          type="text"
          value={meetingUrl}
          onChange={(e) => setMeetingUrl(e.target.value)}
          className="bg-slate-950/80 border border-amber-500/20 rounded-full px-4 py-1.5 text-xs font-mono text-white outline-none w-64 focus:border-amber-400"
        />
        <button className="px-4 py-1.5 bg-gradient-to-r from-amber-500 to-blue-500 text-slate-950 font-bold text-xs rounded-full shadow-lg shadow-amber-500/30 hover:scale-105 transition-all cursor-pointer">
          Inject Bot
        </button>
        <button onClick={addSimNode} className="px-3 py-1.5 bg-white/5 border border-white/10 text-white text-xs font-mono rounded-full hover:bg-white/10 flex items-center gap-1 cursor-pointer">
          <Plus className="w-3.5 h-3.5" /> Node Sim
        </button>
      </div>

      {/* Speaker Drawer Overlay */}
      {selectedSpeaker && (
        <div className="absolute top-0 right-0 bottom-0 w-80 bg-slate-900/90 backdrop-blur-2xl border-l border-amber-500/20 z-30 p-6 flex flex-col gap-4 shadow-2xl animate-in slide-in-from-right duration-300">
          <div className="flex justify-between items-center border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-amber-400">{selectedSpeaker.name}</h3>
              <p className="text-xs font-mono text-slate-400">{selectedSpeaker.role}</p>
            </div>
            <button onClick={() => setSelectedSpeaker(null)} className="p-1 rounded-full hover:bg-white/10 text-white cursor-pointer">
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/60 border border-white/5 text-xs space-y-1">
            <span className="font-mono text-[10px] text-amber-400">00:04</span>
            <p className="text-slate-200">"Welcome team. Auditing 3D spatial node topology and client-side sentence vector embeddings RAG engine."</p>
          </div>
        </div>
      )}

      {/* Security Modal */}
      {showSecurityModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-40 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-amber-500 rounded-3xl p-6 max-w-md w-full shadow-2xl shadow-amber-500/30 space-y-4">
            <h3 className="text-sm font-bold text-amber-400 flex items-center gap-2">
              <Shield className="w-4 h-4" /> Zero-Knowledge Security Vault 3D
            </h3>
            <p className="text-xs text-slate-400">Real-time Client-Side SHA-256 Data Integrity Verification Hash:</p>
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-[11px] text-emerald-400 break-all">
              8a7f92bc3e1d4590a1f87e24b901c563e4129b09f7a83c1d92e541b2a90187c3
            </div>
            <button onClick={() => setShowSecurityModal(false)} className="w-full py-2 bg-amber-500 text-slate-950 font-bold rounded-xl text-xs hover:bg-amber-400 cursor-pointer">
              Close Vault Specs
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
