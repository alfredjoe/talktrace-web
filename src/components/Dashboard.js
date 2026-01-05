import { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import { Mic, Link2, Download, LogOut } from 'lucide-react';
import forge from 'node-forge';

export default function Dashboard() {
  const { user, logout } = useAuth();
  const [meetingLink, setMeetingLink] = useState('');
  const [status, setStatus] = useState('idle'); // idle, joining, active, processing, complete
  const [meetingId, setMeetingId] = useState(null);
  const [audioUrl, setAudioUrl] = useState(null);
  const [logs, setLogs] = useState([]);

  const [statusMessage, setStatusMessage] = useState('');

  // State for loaded key (replaces keyPairRef)
  const [privateKey, setPrivateKey] = useState(null);
  const pollingIntervalRef = useRef(null);

  const API_BASE = 'http://localhost:3002';

  const addLog = (msg) => setLogs(prev => [...prev, `${new Date().toLocaleTimeString()} - ${msg}`]);

  // Load RSA Private Key from Env on component mount
  useEffect(() => {
    const loadKey = () => {
      try {
        const rawKey = process.env.REACT_APP_PRIVATE_KEY;
        if (!rawKey) {
          throw new Error("REACT_APP_PRIVATE_KEY is missing in .env");
        }

        addLog('Loading RSA Key from environment...');
        // Handle escaped newlines if present (common in .env)
        const formattedKey = rawKey.replace(/\\n/g, '\n');

        const pKey = forge.pki.privateKeyFromPem(formattedKey);
        setPrivateKey(pKey);
        addLog('RSA Private Key loaded successfully.');
      } catch (err) {
        console.error('Key loading failed:', err);
        addLog(`Error loading key: ${err.message}`);
      }
    };
    loadKey();

    return () => stopPolling();
  }, []);

  const stopPolling = () => {
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = null;
    }
  };

  const joinMeeting = async () => {
    if (!meetingLink) return;
    setStatus('joining');
    setStatusMessage('Initiating connection...');
    addLog(`Joining meeting: ${meetingLink}`);

    try {
      const token = await user.getIdToken();
      const response = await fetch(`${API_BASE}/api/join`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          user_id: user.email,
          meeting_url: meetingLink,
          bot_name: 'Talktrace Bot'
        })
      });

      const data = await response.json();
      if (data.success) {
        setMeetingId(data.meeting_id);
        setStatus('active');
        addLog(`Bot joined. Meeting ID: ${data.meeting_id}`);
        startPolling(data.meeting_id);
      } else {
        throw new Error(data.message || 'Failed to join');
      }
    } catch (error) {
      console.error('Join Error:', error);
      setStatus('idle');
      setStatusMessage('');
      addLog(`Error joining meeting: ${error.message}`);
      alert(`Failed to join meeting: ${error.message}`);
    }
  };

  const startPolling = (currentMeetingId) => {
    stopPolling();
    addLog('Started polling for status...');

    pollingIntervalRef.current = setInterval(async () => {
      try {
        const token = await user.getIdToken();
        const res = await fetch(`${API_BASE}/api/status/${currentMeetingId}?user_id=${user.email}`, {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        const data = await res.json();

        // Handle fine-grained status
        const serverStatus = data.status; // Assuming strict mapping, or check raw_status if available
        // If data.raw_status exists, use it for specific messaging, otherwise fallback to data.status
        const effectiveStatus = data.raw_status || data.status;

        if (data.audio_ready) {
          stopPolling();
          setStatus('complete');
          setStatusMessage('Meeting ended. Audio ready!');
          addLog('Audio is ready for download.');
        } else if (effectiveStatus === 'joining_call') {
          setStatus('joining');
          setStatusMessage("Bot is joining due to Zoom latency...");
        } else if (effectiveStatus === 'in_call_not_recording') {
          setStatus('active');
          setStatusMessage("Bot joined! Waiting for recording permission...");
        } else if (effectiveStatus === 'in_call_recording') {
          setStatus('active');
          setStatusMessage("Recording in progress...");
        } else if (data.status === 'processing' || effectiveStatus === 'processing') {
          setStatus('processing');
          setStatusMessage("Meeting ended. Processing audio...");
        } else if (data.status === 'failed' || data.error) {
          stopPolling();
          setStatus('error');
          setStatusMessage(`Error: ${data.error || 'Unknown error'}`);
          addLog(`Meeting processing failed: ${data.error || 'Unknown error'}`);
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 5000); // Polling faster (5s) for better responsiveness
  };

  const stopRecording = async () => {
    if (!meetingId) return;

    try {
      addLog('Requesting bot to leave the meeting...');
      const token = await user.getIdToken();
      const response = await fetch(`${API_BASE}/api/leave`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ meeting_id: meetingId })
      });

      const data = await response.json();
      if (data.success) {
        addLog("Bot left the meeting successfully.");
        // Optimistically set status to processing as the bot leaves
        setStatus('processing');
      } else {
        throw new Error(data.message || 'Failed to leave meeting');
      }
    } catch (error) {
      console.error("Failed to stop recording:", error);
      addLog(`Failed to stop recording: ${error.message}`);
      alert(`Failed to stop recording: ${error.message}`);
    }
  };

  const downloadAndDecrypt = async () => {
    if (!privateKey) {
      alert('RSA Private Key not loaded. Check .env');
      return;
    }

    try {
      addLog('Initiating secure download (Streaming to Disk, RSA-OAEP)...');

      // Derive Public Key from Private Key
      const publicKey = forge.pki.setRsaPublicKey(privateKey.n, privateKey.e);
      const publicKeyPem = forge.pki.publicKeyToPem(publicKey);

      const token = await user.getIdToken();
      const response = await fetch(`${API_BASE}/api/audio/${meetingId}?user_id=${user.email}`, {
        method: 'GET',
        headers: {
          'x-public-key': publicKeyPem.replace(/\r\n/g, ''),
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) throw new Error("Download failed");

      // 1. Extract Encrypted AES Key from Header
      const encryptedKeyB64 = response.headers.get('X-Encrypted-Key');
      if (!encryptedKeyB64) {
        throw new Error("Missing X-Encrypted-Key header. (Hint: Backend must Set 'Access-Control-Expose-Headers: X-Encrypted-Key')");
      }

      addLog('Header received. Decrypting key with RSA-OAEP (SHA-256)...');

      // 2. Decrypt AES Key & IV using Private Key
      // Explicitly using RSA-OAEP with SHA-256 as per backend spec
      const encryptedKeyBytes = forge.util.decode64(encryptedKeyB64);

      const decryptedKeyDataRaw = privateKey.decrypt(encryptedKeyBytes, 'RSA-OAEP', {
        md: forge.md.sha256.create()
      });

      const aesKey = decryptedKeyDataRaw.substring(0, 32);
      const iv = decryptedKeyDataRaw.substring(32, 48);

      // 3. Setup StreamSaver
      // Dynamic import to avoid SSR issues if this were Next.js, 
      // but for CRA we can import at top or here. To be safe/clean let's use dynamic or assume top-level import.
      // Since I can't easily change top-level imports in this specific tool call without reloading whole file,
      // I'll grab it from window if loaded via script, OR better:
      // I will assume I added the import statement at the top. 
      // WAIT: I cannot add the import at the top in this tool call easily if I only replace the function.
      // I will use dynamic import() here to be safe and self-contained for this block.
      const streamSaver = (await import('streamsaver')).default;

      // Configure StreamSaver (optional, but good for local dev if needed)
      // streamSaver.mitm = 'https://.../mitm.html'; 

      const fileStream = streamSaver.createWriteStream(`meeting_${meetingId}.mp4`);
      const writer = fileStream.getWriter();
      const reader = response.body.getReader();

      // 4. Setup AES Decrypter
      const decipher = forge.cipher.createDecipher('AES-CBC', forge.util.createBuffer(aesKey));
      decipher.start({ iv: forge.util.createBuffer(iv) });

      let receivedLength = 0;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        receivedLength += value.length;

        // Convert Uint8Array -> Binary String for Forge
        // For efficiency with large chunks, can use a loop or spread if size is safe.
        // Chunk size from fetch is usually reasonable (e.g. 64kb).
        // Using apply/map on 64kb is risky for stack.
        // Safest: loop or slight optimization. This is the bottleneck in JS crypto.
        let chunkStr = "";
        const len = value.length;
        // Batch convert to avoid call stack limits on large spreads
        for (let i = 0; i < len; i += 32768) {
          chunkStr += String.fromCharCode.apply(null, value.subarray(i, i + 32768));
        }

        decipher.update(forge.util.createBuffer(chunkStr));

        const outputBytes = decipher.output.getBytes();
        if (outputBytes.length > 0) {
          // Convert Binary String -> Uint8Array
          const outLen = outputBytes.length;
          const outBuf = new Uint8Array(outLen);
          for (let i = 0; i < outLen; i++) {
            outBuf[i] = outputBytes.charCodeAt(i);
          }
          await writer.write(outBuf);
        }
      }

      // Finish Decryption
      const success = decipher.finish();
      if (!success) throw new Error("Decryption failed at finish step");

      const finalBytes = decipher.output.getBytes();
      if (finalBytes.length > 0) {
        const outLen = finalBytes.length;
        const outBuf = new Uint8Array(outLen);
        for (let i = 0; i < outLen; i++) {
          outBuf[i] = finalBytes.charCodeAt(i);
        }
        await writer.write(outBuf);
      }

      await writer.close();
      addLog(`Download complete! Saved as meeting_${meetingId}.mp4`);
      setStatusMessage('Download complete');

    } catch (e) {
      console.error("Stream/Decryption Error:", e);
      addLog(`Error: ${e.message}`);
      alert(`Download Error: ${e.message}`);
    }
  };

  const reset = () => {
    setStatus('idle');
    setMeetingLink('');
    setMeetingId(null);
    setAudioUrl(null);
    setLogs([]);
    stopPolling();
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 p-6 md:p-8 text-white font-sans">
      <div className="max-w-3xl mx-auto">
        <header className="flex justify-between items-center mb-12">
          <div>
            <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-400">
              TalkTrace
            </h1>
            <p className="text-slate-400 mt-1">Secure Meeting Intelligence</p>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right hidden md:block">
              <p className="text-sm font-medium">{user?.email}</p>
              <p className="text-xs text-slate-500">Authenticated</p>
            </div>
            <button onClick={logout} className="p-2 hover:bg-white/10 rounded-full transition-colors">
              <LogOut className="w-5 h-5 text-slate-400" />
            </button>
          </div>
        </header>

        <main className="space-y-8">
          {/* Connection Card */}
          <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-8 backdrop-blur-sm">
            <h2 className="text-2xl font-semibold mb-6 flex items-center gap-3">
              <Mic className="w-6 h-6 text-blue-400" />
              Join Meeting
            </h2>

            <div className="space-y-6">
              <div className="relative">
                <div className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400">
                  <Link2 className="w-5 h-5" />
                </div>
                <input
                  type="text"
                  value={meetingLink}
                  onChange={(e) => setMeetingLink(e.target.value)}
                  placeholder="Paste Google Meet or Zoom URL..."
                  disabled={status !== 'idle'}
                  className="w-full bg-slate-900/80 border border-slate-600 rounded-xl py-4 pl-12 pr-4 text-white placeholder-slate-500 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all outline-none disabled:opacity-50"
                />
              </div>

              <div className="flex gap-4">
                {status === 'idle' ? (
                  <button
                    onClick={joinMeeting}
                    disabled={!meetingLink.trim()}
                    className="flex-1 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:hover:bg-blue-600 text-white font-semibold py-4 rounded-xl transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-900/20"
                  >
                    Deploy Bot
                  </button>
                ) : (
                  <button
                    onClick={reset}
                    className="flex-1 bg-slate-700 hover:bg-slate-600 text-white font-semibold py-4 rounded-xl transition-all border border-slate-600"
                  >
                    Reset / New Meeting
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Status & Actions Card */}
          {(status !== 'idle' || logs.length > 0) && (
            <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-8 backdrop-blur-sm animate-in fade-in slide-in-from-bottom-4 duration-500">
              <div className="flex justify-between items-center mb-6">
                <div className="flex items-center gap-4">
                  <h3 className="text-xl font-semibold">Session Status</h3>
                  <div className={`px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider ${status === 'joining' ? 'bg-yellow-500/10 text-yellow-400' :
                    status === 'active' ? 'bg-green-500/10 text-green-400' :
                      status === 'processing' ? 'bg-blue-500/10 text-blue-400' :
                        status === 'complete' ? 'bg-purple-500/10 text-purple-400' :
                          'bg-slate-700 text-slate-400'
                    }`}>
                    {status}
                  </div>
                </div>

                {status === 'active' && (
                  <button
                    onClick={stopRecording}
                    className="px-4 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-500 border border-red-500/50 rounded-lg text-sm font-medium transition-all flex items-center gap-2"
                  >
                    <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                    Stop Recording
                  </button>
                )}
              </div>

              {status === 'complete' && !audioUrl && (
                <button
                  onClick={downloadAndDecrypt}
                  className="w-full mb-6 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-4 rounded-xl transition-all flex items-center justify-center gap-2 shadow-lg shadow-emerald-900/20"
                >
                  <Download className="w-5 h-5" />
                  Download & Decrypt Audio
                </button>
              )}

              {audioUrl && (
                <div className="mb-6 p-4 bg-slate-900/50 rounded-xl border border-slate-700">
                  <p className="text-sm text-slate-400 mb-2">Decrypted Audit Ready</p>
                  <audio controls src={audioUrl} className="w-full" />
                  <div className="mt-4 flex justify-end">
                    <a
                      href={audioUrl}
                      download={`recording-${meetingId}.mp3`}
                      className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1"
                    >
                      <Download className="w-4 h-4" /> Save MP3
                    </a>
                  </div>
                </div>
              )}

              {/* Logs Console */}
              <div className="bg-slate-950 rounded-xl p-4 font-mono text-xs text-slate-400 h-48 overflow-y-auto border border-slate-800">
                {logs.map((log, i) => (
                  <div key={i} className="mb-1 border-b border-white/5 pb-1 last:border-0 last:pb-0">
                    <span className="text-slate-600 mr-2">&gt;</span>
                    {log}
                  </div>
                ))}
                {statusMessage && (
                  <div className={`mt-2 animate-pulse font-semibold ${status === 'error' ? 'text-red-400' :
                    status === 'complete' ? 'text-purple-400' :
                      status === 'joining' ? 'text-yellow-400' :
                        'text-blue-400'
                    }`}>
                    {statusMessage}
                  </div>
                )}
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

