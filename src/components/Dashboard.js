import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { Mic, Link2, Play, StopCircle, Download, LogOut } from 'lucide-react';

export default function Dashboard() {
  const { user, logout } = useAuth();
  const [meetingLink, setMeetingLink] = useState('');
  const [status, setStatus] = useState('idle');
  const [progress, setProgress] = useState(0);

  const deployBot = async () => {
    setStatus('deploying');
    setProgress(0);

    // Simulate bot deployment (Week 2: Real Zoom bot)
    const interval = setInterval(() => {
      setProgress(p => {
        if (p >= 100) {
          clearInterval(interval);
          setStatus('complete');
          return 100;
        }
        return p + 10;
      });
    }, 800);
  };

  const reset = () => {
    setStatus('idle');
    setProgress(0);
    setMeetingLink('');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-500 via-purple-500 to-indigo-600 p-6 md:p-8">
      <div className="max-w-2xl mx-auto">
        {/* Header */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4">
          <div>
            <h1 className="text-4xl md:text-5xl font-black bg-gradient-to-r from-white to-gray-200 bg-clip-text text-transparent mb-2">
              TalkTrace
            </h1>
            <p className="text-xl text-white/90 font-medium">Secure meeting intelligence</p>
          </div>
          
          <div className="flex items-center gap-3 bg-white/10 backdrop-blur-xl px-4 py-2 rounded-2xl border border-white/20">
            <img 
              src={`https://ui-avatars.com/api/?name=${user?.email?.split('@')[0]}&background=6366f1&color=fff&size=40&bold=true`} 
              alt="avatar" 
              className="w-10 h-10 rounded-full ring-2 ring-white/20" 
            />
            <span className="text-white font-semibold text-sm truncate max-w-32">{user?.email}</span>
            <button 
              onClick={logout}
              className="p-2 hover:bg-white/20 rounded-xl transition-all text-white hover:text-white"
              title="Logout"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Main Card */}
        <div className="bg-white/10 backdrop-blur-2xl rounded-3xl p-8 md:p-12 border border-white/20 shadow-2xl">
          <div className="text-center mb-10">
            <div className="w-24 h-24 bg-gradient-to-r from-emerald-400 to-green-500 rounded-3xl flex items-center justify-center mx-auto mb-6 shadow-2xl">
              <Mic className="w-12 h-12 text-white" />
            </div>
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-3">Deploy Recording Bot</h2>
            <p className="text-xl text-white/80 max-w-md mx-auto">
              Paste your Zoom meeting link. Bot joins automatically, records securely, and delivers encrypted transcript.
            </p>
          </div>

          <div className="space-y-6">
            {/* Meeting Link Input */}
            <div>
              <label className="block text-lg font-semibold text-white mb-4 flex items-center gap-3">
                <Link2 className="w-7 h-7" />
                Meeting Link
              </label>
              <div className="relative group">
                <input
                  value={meetingLink}
                  onChange={(e) => setMeetingLink(e.target.value)}
                  placeholder="https://zoom.us/j/123456789 or https://meet.google.com/abc-defg-hij"
                  className="w-full p-5 pl-14 pr-16 text-xl bg-white/5 border-2 border-white/20 rounded-3xl text-white placeholder-gray-400 focus:outline-none focus:border-blue-400 focus:ring-4 focus:ring-blue-500/30 transition-all group-hover:border-white/40"
                  disabled={status !== 'idle'}
                />
                <div className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-400 group-focus-within:text-blue-400 transition-colors">
                  paste
                </div>
              </div>
            </div>

            {/* Deploy Button */}
            <button
              onClick={deployBot}
              disabled={status !== 'idle' || !meetingLink.trim()}
              className="w-full group relative overflow-hidden bg-gradient-to-r from-emerald-500 via-green-500 to-emerald-600 hover:from-emerald-600 hover:via-green-600 hover:to-emerald-700 text-white font-black py-6 px-8 rounded-3xl text-xl shadow-2xl hover:shadow-emerald-500/50 transform hover:-translate-y-1 transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
            >
              <span className="relative z-10 flex items-center justify-center gap-3">
                {status === 'idle' && <Mic className="w-8 h-8" />}
                {status === 'deploying' && <div className="w-8 h-8 border-2 border-white/30 border-t-white rounded-full animate-spin" />}
                {status === 'complete' && <Play className="w-8 h-8" />}
                
                {status === 'idle' && '🚀 Deploy Recording Bot'}
                {status === 'deploying' && '🤖 Recording Meeting'}
                {status === 'complete' && '✅ Transcript Ready'}
              </span>
              
              <div className="absolute inset-0 bg-gradient-to-r from-emerald-400 to-green-500 opacity-0 group-hover:opacity-100 transition-opacity duration-300 blur-sm -z-10" />
            </button>

            {/* Status & Progress */}
            {status === 'deploying' && (
              <div className="bg-white/10 backdrop-blur-xl p-8 rounded-3xl border border-white/20 animate-in slide-in-from-bottom-4 duration-500">
                <div className="flex items-center gap-4 mb-6">
                  <div className="w-5 h-5 bg-gradient-to-r from-yellow-400 to-orange-500 rounded-full animate-pulse" />
                  <div>
                    <h3 className="text-2xl font-bold text-white mb-1">Recording in Progress</h3>
                    <p className="text-lg text-white/80">Bot joined meeting and capturing audio securely</p>
                  </div>
                </div>
                
                <div className="w-full bg-white/10 rounded-2xl h-4 overflow-hidden">
                  <div 
                    className="bg-gradient-to-r from-emerald-400 via-green-400 to-emerald-500 h-4 rounded-2xl shadow-lg transition-all duration-1000 ease-out"
                    style={{ width: `${progress}%` }}
                  />
                </div>
                <p className="text-center text-xl font-bold text-white mt-3">{progress}% complete</p>
              </div>
            )}

            {status === 'complete' && (
              <div className="bg-gradient-to-r from-emerald-500/20 to-green-500/20 border-2 border-emerald-500/50 backdrop-blur-xl p-8 rounded-3xl animate-in slide-in-from-bottom-4 duration-500">
                <div className="flex items-center gap-4 mb-6">
                  <div className="w-6 h-6 bg-emerald-400 rounded-full flex items-center justify-center">
                    <Play className="w-4 h-4 text-emerald-900" />
                  </div>
                  <div>
                    <h3 className="text-3xl font-bold bg-gradient-to-r from-emerald-300 to-emerald-100 bg-clip-text text-transparent mb-2">
                      Transcript Complete!
                    </h3>
                    <p className="text-xl text-emerald-100">Secure processing finished. Ready for review.</p>
                  </div>
                </div>
                
                <div className="grid md:grid-cols-2 gap-4">
                  <button className="bg-emerald-600 hover:bg-emerald-700 text-white font-bold py-4 px-8 rounded-2xl transition-all flex items-center justify-center gap-3 shadow-xl hover:shadow-emerald-500/50 hover:-translate-y-1">
                    <Download className="w-6 h-6" />
                    View & Edit Transcript
                  </button>
                  <button 
                    onClick={reset}
                    className="bg-white/20 hover:bg-white/30 text-white font-bold py-4 px-8 rounded-2xl transition-all border border-white/30 hover:border-white/50"
                  >
                    🔄 New Meeting
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="mt-16 text-center text-white/60 text-sm">
          <p>© 2025 TalkTrace. Secure meeting transcripts with blockchain verification.</p>
        </div>
      </div>
    </div>
  );
}
