import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { createUserWithEmailAndPassword } from 'firebase/auth';
import { auth } from '../firebase';
import { Mail, Lock, ArrowRight, Shield, Mic, CheckCircle2, Sparkles } from 'lucide-react';

export default function Signup() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSignup = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    try {
      await createUserWithEmailAndPassword(auth, email, password);
      navigate('/dashboard');
    } catch (err) {
      setError('Email already exists or invalid format');
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-sleek-mesh flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background Animated Floating Orbs */}
      <div className="fixed top-12 left-12 w-[450px] h-[450px] bg-indigo-600/15 rounded-full blur-[140px] pointer-events-none animate-orb-1 -z-10" />
      <div className="fixed bottom-12 right-12 w-[480px] h-[480px] bg-cyan-500/15 rounded-full blur-[150px] pointer-events-none animate-orb-2 -z-10" />

      <div className="max-w-md w-full sleek-card p-8 md:p-10 animate-in fade-in zoom-in-95 duration-500 relative z-10 border border-slate-700/60 shadow-2xl backdrop-blur-xl shine-effect">
        {/* Header Badge */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-600 to-indigo-600 border border-blue-400/30 flex items-center justify-center mb-4 shadow-xl shadow-blue-500/25 relative group">
            <Mic className="w-7 h-7 text-white group-hover:scale-110 transition-transform duration-300" />
            <div className="absolute -bottom-1 -right-1 w-4 h-4 bg-emerald-400 rounded-full border-2 border-slate-900 animate-pulse" />
          </div>

          <h1 className="text-3xl font-black text-white tracking-tight flex items-center gap-2">
            Create Account
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-medium flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-blue-400" /> Start encrypting your meeting data
          </p>
        </div>
        
        {error && (
          <div className="bg-red-500/10 border border-red-500/40 text-red-300 p-3.5 rounded-xl mb-6 text-xs font-semibold animate-in fade-in slide-in-from-top-2 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-red-400 animate-ping" />
            {error}
          </div>
        )}

        <form onSubmit={handleSignup} className="space-y-4">
          <div>
            <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Account Email</label>
            <div className="relative group">
              <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 group-focus-within:text-blue-400 w-4 h-4 transition-colors" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full pl-11 pr-4 py-3.5 bg-slate-900/90 border border-slate-700/80 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 rounded-xl text-white placeholder-slate-500 focus:outline-none transition-all text-sm font-medium"
                placeholder="name@example.com"
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Password</label>
            <div className="relative group">
              <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 group-focus-within:text-blue-400 w-4 h-4 transition-colors" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-11 pr-4 py-3.5 bg-slate-900/90 border border-slate-700/80 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 rounded-xl text-white placeholder-slate-500 focus:outline-none transition-all text-sm font-medium"
                placeholder="••••••••"
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Confirm Password</label>
            <div className="relative group">
              <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 group-focus-within:text-blue-400 w-4 h-4 transition-colors" />
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full pl-11 pr-4 py-3.5 bg-slate-900/90 border border-slate-700/80 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 rounded-xl text-white placeholder-slate-500 focus:outline-none transition-all text-sm font-medium"
                placeholder="••••••••"
                required
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 btn-sleek-primary text-white font-bold py-3.5 px-4 rounded-xl transition-all duration-200 disabled:opacity-50 text-sm mt-2 glow-pulse-ring cursor-pointer"
          >
            {loading ? 'Creating Account...' : <>Create Account <ArrowRight className="w-4 h-4" /></>}
          </button>
        </form>

        {/* Feature Highlights */}
        <div className="mt-8 pt-6 border-t border-slate-800/80 space-y-2.5">
          <div className="flex items-center gap-2 text-[11px] text-slate-400 font-medium">
            <CheckCircle2 className="w-3.5 h-3.5 text-blue-400 shrink-0" />
            <span>100% Zero-Trust Encrypted Vault</span>
          </div>
          <div className="flex items-center gap-2 text-[11px] text-slate-400 font-medium">
            <CheckCircle2 className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
            <span>Real-Time Participant Speaker Diarization</span>
          </div>
        </div>

        <p className="text-center mt-6 text-xs text-slate-400">
          Already have an account?{' '}
          <Link to="/login" className="text-blue-400 font-bold hover:underline">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}
