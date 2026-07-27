import React, { useState } from 'react';
import { Shield, Lock, Activity, Link2, ArrowRight, Copy, Check, CheckCircle, FileText } from 'lucide-react';

export default function CyberDashboard() {
  const [activeTab, setActiveTab] = useState(1);
  const [simStep, setSimStep] = useState(1);
  const [copied, setCopied] = useState(false);
  const [meetingUrl, setMeetingUrl] = useState('https://meet.google.com/abc-defg-hij');

  const states = [
    { label: "1. Ready / Idle", val: "100%", offset: 0, lbl: "Secured" },
    { label: "2. Transcribing Locally", val: "45%", offset: 240, lbl: "Transcribing" },
    { label: "3. Summary & Hash Verified", val: "100%", offset: 0, lbl: "Verified" }
  ];

  const currentSt = states[simStep - 1];

  const cycleSim = () => {
    const next = (simStep % 3) + 1;
    setSimStep(next);
    if (next === 3) setActiveTab(2);
    else if (next === 2) setActiveTab(1);
  };

  const copyHash = () => {
    navigator.clipboard.writeText("8a7f92bc3e1d4590a1f87e24b901c563e4129b09f7a83c1d92e541b2a90187c3");
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6 text-slate-100 font-sans p-2">
      {/* Header Bar */}
      <header className="bg-slate-900/65 backdrop-blur-xl border border-cyan-500/20 rounded-2xl p-5 flex flex-col md:flex-row justify-between items-center gap-4 shadow-2xl">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-400 to-purple-600 flex items-center justify-center shadow-lg shadow-cyan-500/30">
            <Activity className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-2xl font-extrabold tracking-tight bg-gradient-to-r from-white to-cyan-400 bg-clip-text text-transparent">
                TalkTrace
              </span>
              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded uppercase tracking-widest">
                v2.4 Zero-Knowledge
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono font-semibold hover:shadow-lg hover:shadow-emerald-500/20 transition-all cursor-pointer">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-sm shadow-emerald-400"></span>
            Zero-Knowledge Mode Active
          </div>
          <div className="flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-purple-500/10 border border-purple-500/30 text-purple-300 text-xs font-mono font-semibold hover:shadow-lg hover:shadow-purple-500/20 transition-all cursor-pointer">
            <Lock className="w-3.5 h-3.5" />
            AES-256 / RSA-OAEP
          </div>
        </div>
      </header>

      {/* Link Deployment Bar */}
      <div className="bg-slate-900/65 backdrop-blur-xl border border-cyan-500/20 rounded-2xl p-4 flex flex-col sm:flex-row gap-4 items-center shadow-2xl">
        <div className="relative flex-1 w-full">
          <Link2 className="absolute left-3.5 top-3.5 w-5 h-5 text-cyan-400" />
          <input
            type="text"
            value={meetingUrl}
            onChange={(e) => setMeetingUrl(e.target.value)}
            placeholder="Paste Google Meet, Zoom, or Teams URL..."
            className="w-full bg-slate-950/80 border border-cyan-500/20 rounded-xl pl-11 pr-4 py-3 text-sm font-mono text-white focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all"
          />
        </div>
        <button
          onClick={cycleSim}
          className="w-full sm:w-auto px-6 py-3 bg-gradient-to-r from-cyan-500/20 to-purple-600/20 hover:from-cyan-400 hover:to-purple-500 text-white hover:text-slate-950 border border-cyan-400 font-bold rounded-xl text-sm transition-all shadow-lg hover:shadow-cyan-500/40 flex items-center justify-center gap-2 group cursor-pointer"
        >
          <span>Deploy Bot</span>
          <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
        </button>
      </div>

      {/* Simulation Toggle Bar */}
      <div className="flex justify-between items-center bg-slate-950/40 border border-dashed border-slate-800 rounded-xl px-4 py-2.5">
        <span className="text-xs font-mono text-slate-400">STATE CONTROL: Click to simulate pipeline lifecycle step</span>
        <button
          onClick={cycleSim}
          className="px-3 py-1 bg-cyan-500/10 hover:bg-cyan-400 text-cyan-400 hover:text-slate-950 border border-cyan-500/30 rounded-lg text-xs font-mono transition-all"
        >
          Cycle State: <span className="font-bold">{currentSt.label}</span>
        </button>
      </div>

      {/* Main Grid: Orbit & Tabs */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Orbit Widget */}
        <div className="bg-slate-900/65 backdrop-blur-xl border border-cyan-500/20 rounded-2xl p-6 flex flex-col items-center text-center shadow-2xl relative">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
            <Shield className="w-4 h-4 text-cyan-400" /> Live Stream Decryptor
          </h3>

          <div className="relative w-44 h-44 my-4">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 160 160">
              <circle className="stroke-slate-800" strokeWidth="6" fill="none" cx="80" cy="80" r="70" />
              <circle
                className="stroke-cyan-400 transition-all duration-1000 ease-out"
                strokeWidth="6"
                fill="none"
                cx="80"
                cy="80"
                r="70"
                strokeDasharray="440"
                strokeDashoffset={currentSt.offset}
                strokeLinecap="round"
              />
            </svg>
            <div className="absolute inset-0 m-auto w-28 h-28 rounded-full bg-cyan-500/10 flex flex-col items-center justify-center">
              <span className="font-mono text-xl font-bold text-white">{currentSt.val}</span>
              <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-widest">{currentSt.lbl}</span>
            </div>
          </div>

          <div className="w-full space-y-2 text-xs">
            <div className="flex justify-between p-2 rounded-lg bg-slate-950/60 border border-white/5">
              <span className="text-slate-400">Diarization Engine:</span>
              <span className="font-mono font-semibold text-cyan-400">Pyannote v3.1</span>
            </div>
            <div className="flex justify-between p-2 rounded-lg bg-slate-950/60 border border-white/5">
              <span className="text-slate-400">Language Verification:</span>
              <span className="font-mono font-semibold text-emerald-400">Google GTX (en)</span>
            </div>
            <div className="flex justify-between p-2 rounded-lg bg-slate-950/60 border border-white/5">
              <span className="text-slate-400">Vault Hash Status:</span>
              <span className="font-mono font-semibold text-purple-400">Verified Clean</span>
            </div>
          </div>
        </div>

        {/* Dual Tab View */}
        <div className="lg:col-span-2 bg-slate-900/65 backdrop-blur-xl border border-cyan-500/20 rounded-2xl p-6 shadow-2xl flex flex-col">
          {/* Tab Controls */}
          <div className="flex gap-3 border-b border-slate-800 pb-3 mb-4">
            <button
              onClick={() => setActiveTab(1)}
              className={`px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 transition-all cursor-pointer ${activeTab === 1 ? 'bg-cyan-500/15 border border-cyan-500/40 text-cyan-300 shadow-lg shadow-cyan-500/10' : 'text-slate-400 hover:text-white hover:bg-white/5'}`}
            >
              <FileText className="w-4 h-4" /> Decrypted Timeline
            </button>
            <button
              onClick={() => setActiveTab(2)}
              className={`px-4 py-2 rounded-xl text-sm font-semibold flex items-center gap-2 transition-all cursor-pointer ${activeTab === 2 ? 'bg-purple-500/15 border border-purple-500/40 text-purple-300 shadow-lg shadow-purple-500/10' : 'text-slate-400 hover:text-white hover:bg-white/5'}`}
            >
              <Shield className="w-4 h-4" /> Security Vault & Summary
            </button>
          </div>

          {/* Tab 1 Content */}
          {activeTab === 1 && (
            <div className="space-y-3 animate-in fade-in slide-in-from-bottom-2 duration-300">
              <div className="p-4 rounded-xl bg-slate-950/70 border border-white/5 hover:border-cyan-500/30 transition-all hover:-translate-y-0.5">
                <div className="flex justify-between items-center mb-1.5">
                  <span className="text-xs font-bold font-mono text-cyan-400 uppercase">Abin George (Speaker 1)</span>
                  <span className="text-[10px] font-mono text-slate-500 bg-white/5 px-1.5 py-0.5 rounded">00:04</span>
                </div>
                <p className="text-sm text-slate-200 leading-relaxed">
                  Welcome team. Today we are auditing our zero-knowledge memory vault and client-side 128-dimensional sentence vector RAG engine.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950/70 border border-white/5 hover:border-purple-500/30 transition-all hover:-translate-y-0.5">
                <div className="flex justify-between items-center mb-1.5">
                  <span className="text-xs font-bold font-mono text-purple-400 uppercase">Sarah Jenkins (Speaker 2)</span>
                  <span className="text-[10px] font-mono text-slate-500 bg-white/5 px-1.5 py-0.5 rounded">00:18</span>
                </div>
                <p className="text-sm text-slate-200 leading-relaxed">
                  Confirmed. All audio streams are encrypted locally with AES-256 before disk persistence, with Google Translate language auto-detection active.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950/70 border border-white/5 hover:border-cyan-500/30 transition-all hover:-translate-y-0.5">
                <div className="flex justify-between items-center mb-1.5">
                  <span className="text-xs font-bold font-mono text-cyan-400 uppercase">Abin George (Speaker 1)</span>
                  <span className="text-[10px] font-mono text-slate-500 bg-white/5 px-1.5 py-0.5 rounded">00:32</span>
                </div>
                <p className="text-sm text-slate-200 leading-relaxed">
                  Awesome. Let's auto-generate executive minutes and export task items directly to GitHub and Jira.
                </p>
              </div>
            </div>
          )}

          {/* Tab 2 Content */}
          {activeTab === 2 && (
            <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2 duration-300">
              <div className="p-4 rounded-xl bg-slate-950/70 border border-emerald-500/20">
                <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-400 mb-2 flex items-center gap-1.5">
                  <CheckCircle className="w-4 h-4" /> Executive Summary Briefing
                </h4>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  <li className="flex items-start gap-2">
                    <span className="text-emerald-400 font-bold">▹</span>
                    Validated zero-trust client-side encryption stream across all multi-speaker meeting tracks.
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-emerald-400 font-bold">▹</span>
                    Integrated 128-dimensional sentence vector embeddings with Cosine Similarity for natural language search.
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-emerald-400 font-bold">▹</span>
                    Approved automated task sync exporter for GitHub, Jira, and CSV project management boards.
                  </li>
                </ul>
              </div>

              {/* SHA-256 Hash Verification Badge */}
              <div className="p-4 rounded-xl bg-purple-500/10 border border-purple-500/30 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                <div>
                  <span className="text-[11px] font-bold text-purple-300 uppercase tracking-wider block mb-0.5">
                    SHA-256 Data Integrity Verification Hash
                  </span>
                  <span className="font-mono text-xs text-slate-300 break-all">
                    8a7f92bc3e1d4590a1f87e24b901c563e4129b09f7a83c1d92e541b2a90187c3
                  </span>
                </div>
                <button
                  onClick={copyHash}
                  className="px-3.5 py-1.5 bg-purple-500/20 hover:bg-purple-500 text-white font-mono text-xs rounded-lg border border-purple-400 transition-all flex items-center gap-1 shrink-0 cursor-pointer"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? "Copied!" : "Copy Hash"}</span>
                </button>
              </div>
            </div>
          )}

        </div>

      </div>
    </div>
  );
}
