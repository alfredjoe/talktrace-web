import { useState } from 'react';
import { Link } from 'react-router-dom';
import { sendPasswordResetEmail } from 'firebase/auth';
import { auth } from '../firebase';
import { Mail, ArrowRight, KeyRound, CheckCircle2 } from 'lucide-react';

export default function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setMessage('');

    try {
      await sendPasswordResetEmail(auth, email);
      setMessage('Password reset email sent! Please check your inbox.');
    } catch (err) {
      if (err.code === 'auth/user-not-found') {
        setError('No account found with this email address.');
      } else if (err.code === 'auth/invalid-email') {
        setError('Invalid email address format.');
      } else {
        setError(err.message || 'Failed to send password reset email.');
      }
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
            <KeyRound className="w-7 h-7 text-white group-hover:scale-110 transition-transform duration-300" />
          </div>

          <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2">
            Reset Password
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-medium text-center">
            Enter your registered email address to receive a password reset link.
          </p>
        </div>

        {error && (
          <div className="bg-red-500/10 border border-red-500/40 text-red-300 p-3.5 rounded-xl mb-6 text-xs font-semibold animate-in fade-in slide-in-from-top-2 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-red-400 animate-ping shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {message && (
          <div className="bg-emerald-500/10 border border-emerald-500/40 text-emerald-300 p-3.5 rounded-xl mb-6 text-xs font-semibold animate-in fade-in slide-in-from-top-2 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{message}</span>
          </div>
        )}

        <form onSubmit={handleResetPassword} className="space-y-5">
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

          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 btn-sleek-primary text-white font-bold py-3.5 px-4 rounded-xl transition-all duration-200 disabled:opacity-50 text-sm mt-2 glow-pulse-ring cursor-pointer"
          >
            {loading ? 'Sending Link...' : <>Send Password Reset Link <ArrowRight className="w-4 h-4" /></>}
          </button>
        </form>

        <p className="text-center mt-6 text-xs text-slate-400">
          Remembered your password?{' '}
          <Link to="/login" className="text-blue-400 font-bold hover:underline">
            Back to Sign In
          </Link>
        </p>
      </div>
    </div>
  );
}
