import { useState, useEffect, useRef, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';
import { Mic, Link2, Download, LogOut, List, CheckCircle, Clock, Trash2 } from 'lucide-react';
import forge from 'node-forge';
import { jsPDF } from "jspdf";
import streamSaver from 'streamsaver';

export default function Dashboard() {
  const { user, logout } = useAuth();
  const [meetingLink, setMeetingLink] = useState('');
  const [status, setStatus] = useState('idle'); // idle, joining, active, processing, complete
  const [meetingId, setMeetingId] = useState(null);
  const [audioUrl, setAudioUrl] = useState(null);
  const [logs, setLogs] = useState([]);

  const [summary, setSummary] = useState(null);
  const [history, setHistory] = useState([]);
  const [isEditing, setIsEditing] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [editContent, setEditContent] = useState('');

  const [statusMessage, setStatusMessage] = useState('');
  const API_BASE = 'http://localhost:3002'; // Assuming this was missing and needs to be added

  // State for loaded key (replaces keyPairRef)
  // privateKey is now a WebCrypto CryptoKey object
  const [privateKey, setPrivateKey] = useState(null);
  const [publicKeyPem, setPublicKeyPem] = useState(null);
  const pollingIntervalRef = useRef(null);

  // New states for UI
  const [view, setView] = useState('new'); // 'new' or 'library'
  const [meetings, setMeetings] = useState([]); // For library view
  const [isHistorical, setIsHistorical] = useState(false); // To differentiate new vs historical loads
  const [transcript, setTranscript] = useState(''); // Transcript state
  const [activeTab, setActiveTab] = useState('transcript'); // 'transcript' or 'summary'

  // Generate RSA-OAEP Key Pair on Mount (Dynamic Session Handshake)
  useEffect(() => {
    const generateKeys = async () => {
      try {
        addLog('Generating secure session keys (RSA-OAEP 2048-bit)...');

        const keyPair = await window.crypto.subtle.generateKey(
          {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
          },
          true,
          ["decrypt", "unwrapKey"]
        );

        // Export Public Key to PEM for X-Public-Key header
        const spki = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
        const body = window.btoa(String.fromCharCode(...new Uint8Array(spki)));
        const pem = `-----BEGIN PUBLIC KEY-----\n${body.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;

        setPrivateKey(keyPair.privateKey);
        setPublicKeyPem(pem);
        addLog('Session keys generated successfully.');

        // 1. Refresh Persistence: Fetch meetings immediately to restore state
        fetchMeetings(keyPair.privateKey); // Pass key to allow immediate data fetching if needed, though mostly needed for fetchSecureAudio
      } catch (err) {
        console.error('Key generation failed:', err);
        addLog(`Error generating keys: ${err.message}`);
      }
    };

    generateKeys();

    return () => stopPolling();
  }, []);

  // Removed Initialize Worker and Hardware Detection useEffect

  const addLog = (message) => {
    setLogs((prevLogs) => [...prevLogs, message]);
  };

  const stopPolling = () => {
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = null;
    }
  };

  // Modified to optionally auto-resume
  const fetchMeetings = async () => {
    try {
      const token = await user.getIdToken();
      const response = await fetch(`${API_BASE}/api/meetings?user_id=${user.email}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        // Check filtering for invalid meetings without IDs which might crash UI
        const validMeetings = (data.meetings || []).filter(m => m.meeting_id);
        // Sort by date descending (Newest first)
        // Assuming m.created_at is ISO string, or m.date is parseable. 
        // If m.date is just "Jan 15", we might need m.created_at from backend. 
        // Fallback to meeting_id if no date (assuming IDs might be time-based or just stable).
        validMeetings.sort((a, b) => {
          const dateA = new Date(a.created_at || a.date || 0);
          const dateB = new Date(b.created_at || b.date || 0);
          return dateB - dateA;
        });
        setMeetings(validMeetings);

        // Auto-resume logic: Find most recent non-completed meeting?
        // Or just let user choose from library.
        // For now, if we are in 'idle' state, maybe show library or just load meetings.
      } else {
        console.warn("Fetch meetings failed, using empty list");
        setMeetings([]);
      }
    } catch (e) {
      console.error("Error fetching library:", e);
    }
  };

  const resumeProcessing = async (e, meetingId) => {
    e.stopPropagation(); // Prevent opening the meeting details immediately
    if (!meetingId) return;
    try {
      addLog(`Resuming processing for ${meetingId}...`);
      const token = await user.getIdToken();
      // 3. Resume / Retry Functionality
      const res = await fetch(`${API_BASE}/api/retry/${meetingId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      });

      const data = await res.json();
      if (data.success) {
        // Switch UI to processing mode for this meeting
        setMeetingId(meetingId);
        setView('new');
        setStatus('processing');
        setStatusMessage('Resuming processing...');
        addLog('Resume signal sent. Polling started.');
        startPolling(meetingId);
      } else {
        throw new Error(data.message || "Retry failed");
      }
    } catch (err) {
      console.error("Resume error:", err);
      alert(`Failed to resume: ${err.message}`);
    }
  };

  const saveEdit = async () => {
    try {
      addLog("Saving new version...");
      const token = await user.getIdToken();
      const res = await fetch(`${API_BASE}/api/edit/${meetingId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          text: editContent,
          user_id: user.email
        })
      });
      const data = await res.json();
      if (data.success) {
        setTranscript(editContent);
        setIsEditing(false);
        addLog("Version saved successfully.");
        fetchHistory(meetingId); // Refresh history
      } else {
        throw new Error(data.message || "Save failed");
      }
    } catch (e) {
      console.error("Save error:", e);
      addLog(`Save failed: ${e.message}`);
      alert("Failed to save changes.");
    }
  };

  const fetchHistory = async (id) => {
    try {
      const token = await user.getIdToken();
      const res = await fetch(`${API_BASE}/api/history/${id}?user_id=${user.email}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setHistory(data.history || []);
      }
    } catch (e) {
      console.error("History fetch error:", e);
    }
  };

  const loadHistoricalMeeting = (meeting) => {
    stopPolling(); // Ensure no background updates interfere
    setMeetingId(meeting.meeting_id);
    setView('new');
    setIsHistorical(true);
    setStatus('complete');
    setStatusMessage('Loaded from Library');
    setAudioUrl(null); // Clear previous audio
    setTranscript('');
    setSummary(null);
    setLogs([]); // Clear logs from previous session to avoid confusion

    // Fetch data immediately
    fetchSecureAudio(meeting.meeting_id);
    fetchData(meeting.meeting_id);
    fetchHistory(meeting.meeting_id);
  };

  const fetchData = async (id) => {
    if (!privateKey) { alert("Session Key invalid"); return; }
    try {
      addLog("Fetching secure transcript...");
      const token = await user.getIdToken();

      const response = await fetch(`${API_BASE}/api/data/${id}?user_id=${user.email}`, {
        headers: {
          'x-public-key': publicKeyPem.replace(/[\r\n]+/g, ''),
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) throw new Error("Fetch data failed");

      const encryptedKeyB64 = response.headers.get('X-Encrypted-Key');
      if (!encryptedKeyB64) {
        throw new Error("Missing encryption header");
      }

      // Decrypt AES Key
      const encryptedKeyBytes = Uint8Array.from(atob(encryptedKeyB64), c => c.charCodeAt(0));
      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedKeyBytes
      );
      const decryptedView = new Uint8Array(decryptedBuffer);
      const aesKeyStr = String.fromCharCode(...decryptedView.slice(0, 32));
      const ivStr = String.fromCharCode(...decryptedView.slice(32, 48));

      // Get encrypted body as ArrayBuffer (binary data, NOT base64 text)
      const encryptedData = await response.arrayBuffer();

      // Decrypt with AES-CBC
      const decipher = forge.cipher.createDecipher('AES-CBC', forge.util.createBuffer(aesKeyStr));
      decipher.start({ iv: forge.util.createBuffer(ivStr) });
      decipher.update(forge.util.createBuffer(encryptedData));
      decipher.finish();

      const jsonStr = decipher.output.toString();
      const data = JSON.parse(jsonStr);

      // Render
      setTranscript(data.transcript || "");
      setSummary(data.summary || null);
      addLog("Transcript decrypted and loaded.");

    } catch (e) {
      console.error("Data fetch error:", e);
      addLog(`Error loading data: ${e.message}`);
    }
  };

  const verifyDocument = async (file) => {
    try {
      addLog(`Verifying integrity of ${file.name}...`);
      let text = "";

      if (file.type === "application/pdf") {
        const arrayBuffer = await file.arrayBuffer();
        // Dynamic import pdfjs
        // eslint-disable-next-line
        const pdfjsLib = await import('pdfjs-dist/build/pdf.mjs');
        pdfjsLib.GlobalWorkerOptions.workerSrc = '/pdf.worker.min.mjs';

        const pdf = await pdfjsLib.getDocument(arrayBuffer).promise;
        let fullText = "";
        for (let i = 1; i <= pdf.numPages; i++) {
          const page = await pdf.getPage(i);
          const content = await page.getTextContent();
          fullText += content.items.map(item => item.str).join(" ");
        }
        text = fullText;
      } else {
        text = await file.text();
      }

      // Hash Logic (SHA-256)
      const msgBuffer = new TextEncoder().encode(text);
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      addLog(`Client-side Hash calculated: ${hashHex.substring(0, 8)}...`);

      // Send Hash to Backend
      const token = await user.getIdToken();
      const res = await fetch(`${API_BASE}/api/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ hash: hashHex, meeting_id: meetingId })
      });

      const result = await res.json();
      if (result.valid) {
        alert(`✅ Verified! Matches Version ${result.version} (${result.date})`);
        addLog("Verification Success: Document matches server record.");
      } else {
        alert("❌ Verification Failed: No match found.");
        addLog("Verification Failed: Document hash does not match.");
      }

    } catch (e) {
      console.error("Verification error:", e);
      addLog(`Verification Error: ${e.message}`);
      alert(`Verification Failed: ${e.message}`);
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
        // const serverStatus = data.status; // Unused
        // If data.raw_status exists, use it for specific messaging, otherwise fallback to data.status
        const effectiveStatus = data.raw_status || data.status;

        if (data.audio_ready || effectiveStatus === 'completed' || effectiveStatus === 'done') {
          stopPolling();
          setStatus('complete');
          setStatusMessage('Meeting ended. Audio ready!');
          addLog('Audio is ready. Fetching secure content...');
          fetchSecureAudio(currentMeetingId); // Phase 4: Auto-fetch audio for playback
          fetchData(currentMeetingId);        // Phase 5: Auto-fetch transcript
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
          // Handle granular processing states if backend provides them (Phase 2)
          if (data.process_state === 'downloading') {
            setStatus('processing');
            setStatusMessage("Downloading Audio from Recall...");
          } else if (data.process_state === 'transcribing') {
            setStatus('processing');
            setStatusMessage("Transcribing (Local AI)...");
          } else {
            setStatus('processing');
            setStatusMessage("Meeting ended. Processing audio...");
          }
        } else if (data.status === 'discarded') {
          // Backend deleted meeting due to no audio
          stopPolling();
          setStatus('idle');
          setStatusMessage('');
          addLog('Meeting discarded: No audio was recorded.');
          alert('⚠️ Meeting Discarded\n\nNo audio was recorded for this meeting. The meeting has been removed from your library.');
          // Remove from meetings list if present
          setMeetings(prev => prev.filter(m => m.meeting_id !== currentMeetingId));
          reset();
        } else if (data.status === 'failed' || data.error) {
          stopPolling();
          setStatus('error');
          setStatusMessage(`Error: ${data.error || 'Unknown error'}`);
          addLog(`Meeting processing failed: ${data.error || 'Unknown error'}`);
        }
      } catch (err) {
        console.error('Polling error:', err);
        // Handle 404 (meeting deleted/discarded)
        if (err.message?.includes('404') || err.status === 404) {
          stopPolling();
          addLog('Meeting not found. It may have been discarded.');
          setMeetings(prev => prev.filter(m => m.meeting_id !== currentMeetingId));
          reset();
        }
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

  // Phase 4: Secure Audio Retrieval (InMemory Blob for Playback)
  // Replaces direct downloadAndDecrypt for playback purposes
  const fetchSecureAudio = async (id) => {
    if (!privateKey) { alert('RSA Private Key not loaded.'); return; }

    try {
      addLog('Initiating secure audio stream (Phase 4)...');
      const token = await user.getIdToken();
      const response = await fetch(`${API_BASE}/api/audio/${id}?user_id=${user.email}`, {
        method: 'GET',
        headers: {
          'x-public-key': publicKeyPem.replace(/[\r\n]+/g, ''),
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) throw new Error(`Download failed: ${response.status}`);

      // 1. Extract Encrypted AES Key
      const encryptedKeyB64 = response.headers.get('X-Encrypted-Key');
      if (!encryptedKeyB64) throw new Error("Missing X-Encrypted-Key header.");

      // 2. Decrypt AES Key with WebCrypto
      const encryptedKeyBytes = Uint8Array.from(atob(encryptedKeyB64), c => c.charCodeAt(0));
      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedKeyBytes
      );
      const decryptedView = new Uint8Array(decryptedBuffer);
      const aesKey = String.fromCharCode(...decryptedView.slice(0, 32));
      const iv = String.fromCharCode(...decryptedView.slice(32, 48));

      // 3. Decrypt Body (Assuming Blob/Buffer)
      // For playback, we'll download all, decrypt, and Blob it.
      // NOTE: For very large files, this should be streaming (SourceBuffer), but per instruction:
      // "Tip: If real-time streaming decryption is complex, download... decrypt in one go... and play"
      const encryptedBlob = await response.blob();
      const encryptedData = await encryptedBlob.arrayBuffer();

      addLog('Decrypting audio buffer...');
      const decipher = forge.cipher.createDecipher('AES-CBC', forge.util.createBuffer(aesKey));
      decipher.start({ iv: forge.util.createBuffer(iv) });
      decipher.update(forge.util.createBuffer(encryptedData));

      const success = decipher.finish();
      if (!success) throw new Error('Audio decryption failed');

      // 4. Create Blob URL
      const decryptedBytes = decipher.output.getBytes();
      const byteArray = new Uint8Array(decryptedBytes.length);
      for (let i = 0; i < decryptedBytes.length; i++) byteArray[i] = decryptedBytes.charCodeAt(i);

      const audioBlob = new Blob([byteArray], { type: 'audio/mp3' });
      const url = URL.createObjectURL(audioBlob);
      setAudioUrl(url);
      addLog('Audio decrypted and ready for playback.');

    } catch (e) {
      console.error("Audio Secure Fetch Error:", e);
      addLog(`Audio Error: ${e.message}`);
    }
  };

  const downloadAndDecrypt = async () => {
    if (!privateKey) {
      alert('RSA Private Key not loaded. Check .env');
      return;
    }

    try {
      addLog('Initiating secure download (Streaming to Disk, RSA-OAEP)...');

      const token = await user.getIdToken();
      const response = await fetch(`${API_BASE}/api/audio/${meetingId}?user_id=${user.email}`, {
        method: 'GET',
        headers: {
          'x-public-key': publicKeyPem.replace(/[\r\n]+/g, ''),
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) {
        const errText = await response.text();
        throw new Error(`Download failed: ${response.status} - ${errText || response.statusText}`);
      }

      // 1. Extract Encrypted AES Key from Header
      const encryptedKeyB64 = response.headers.get('X-Encrypted-Key');
      if (!encryptedKeyB64) {
        throw new Error("Missing X-Encrypted-Key header.");
      }

      addLog('Header received. Decrypting key with WebCrypto RSA-OAEP...');

      // 2. Decrypt AES Key & IV using WebCrypto Private Key
      const encryptedKeyBytes = Uint8Array.from(atob(encryptedKeyB64), c => c.charCodeAt(0));

      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedKeyBytes
      );

      // decryptedBuffer contains 32 bytes AES Key + 16 bytes IV
      const decryptedView = new Uint8Array(decryptedBuffer);
      const aesKeyBytes = decryptedView.slice(0, 32);
      const ivBytes = decryptedView.slice(32, 48);

      // Convert to Forge buffers for stream decryption
      // Note: Forge buffers accept raw binary strings or existing buffers.
      // To be safe with Forge's buffer expectation:
      let aesKeyStr = "";
      for (let i = 0; i < aesKeyBytes.length; i++) aesKeyStr += String.fromCharCode(aesKeyBytes[i]);

      let ivStr = "";
      for (let i = 0; i < ivBytes.length; i++) ivStr += String.fromCharCode(ivBytes[i]);

      const aesKey = aesKeyStr;
      const iv = ivStr;

      // 3. Setup StreamSaver
      // Dynamic import to avoid SSR issues if this were Next.js,
      // but for CRA we can import at top or here. To be safe/clean let's use dynamic or assume top-level import.
      // Since I can't easily change top-level imports in this specific tool call without reloading whole file,
      // I will use dynamic import() here to be safe and self-contained for this block.
      // const streamSaver = (await import('streamsaver')).default; // Already imported at top

      // Configure StreamSaver (optional, but good for local dev if needed)
      // streamSaver.mitm = 'https://.../mitm.html';

      // Configure StreamSaver (optional, but good for local dev if needed)
      // streamSaver.mitm = 'https://.../mitm.html';

      const fileStream = streamSaver.createWriteStream(`meeting_${meetingId}.mp3`);
      const writer = fileStream.getWriter();
      const reader = response.body.getReader();

      // 4. Setup AES Decrypter
      const decipher = forge.cipher.createDecipher('AES-CBC', forge.util.createBuffer(aesKey));
      decipher.start({ iv: forge.util.createBuffer(iv) });

      let receivedLength = 0;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        // receivedLength += value.length;

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
      addLog(`Download complete! Saved as meeting_${meetingId}.mp3`);
      setStatusMessage('Download complete');

    } catch (e) {
      console.error("Stream/Decryption Error:", e);
      addLog(`Error: ${e.message}`);
      alert(`Download Error: ${e.message}`);
    }
  };

  const deleteMeeting = async (e, meetingId) => {
    e.stopPropagation(); // Prevent opening the meeting

    const confirmed = window.confirm('⚠️ Delete Meeting?\n\nThis will permanently delete all meeting data including audio, transcript, and summary. This action cannot be undone.\n\nAre you sure you want to continue?');

    if (!confirmed) return;

    try {
      addLog(`Deleting meeting ${meetingId}...`);
      const token = await user.getIdToken();

      const response = await fetch(`${API_BASE}/api/meeting/${meetingId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      const data = await response.json();

      if (response.ok) {
        // Remove from meetings list
        setMeetings(prev => prev.filter(m => m.meeting_id !== meetingId));
        addLog('Meeting deleted successfully.');

        // If we're currently viewing this meeting, reset
        if (meetingId === meetingId) {
          reset();
        }
      } else {
        throw new Error(data.error || 'Delete failed');
      }
    } catch (error) {
      console.error('Delete error:', error);
      addLog(`Failed to delete meeting: ${error.message}`);
      alert(`Failed to delete meeting: ${error.message}`);
    }
  };

  // Removed transcribeAudio function

  const reset = () => {
    setStatus('idle');
    setMeetingLink('');
    setMeetingId(null);
    setAudioUrl(null);
    setLogs([]);
    setTranscript('');
    setSummary(null);
    setIsHistorical(false);
    stopPolling();
  };

  // Render Helpers
  const renderLibrary = () => (
    <div className="animate-in fade-in slide-in-from-bottom-4">
      <h2 className="text-2xl font-semibold mb-6 flex items-center gap-3">
        <List className="w-6 h-6 text-purple-400" />
        Your Meeting Library
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {meetings.length === 0 ? (
          <div className="col-span-2 text-center py-12 bg-slate-800/50 rounded-xl border border-dashed border-slate-700">
            <p className="text-slate-400">No previous recordings found.</p>
          </div>
        ) : (
          meetings.map(m => (
            <div key={m.meeting_id}
              onClick={() => loadHistoricalMeeting(m)}
              className="bg-slate-800/50 hover:bg-slate-700/50 border border-slate-700 hover:border-blue-500/50 rounded-xl p-5 cursor-pointer transition-all group">
              <div className="flex justify-between items-start mb-2">
                <h3 className="font-semibold text-lg truncate pr-4">{m.title || `Meeting ${(m.meeting_id || '').substr(0, 8)}`}</h3>
                <div className="flex flex-col items-end gap-1">
                  <span className="text-xs font-mono bg-slate-900 px-2 py-1 rounded text-slate-400">{m.date || 'Jan 15'}</span>
                  <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${m.status === 'completed' ? 'bg-green-900 text-green-400' :
                    m.status === 'failed' ? 'bg-red-900 text-red-400' :
                      'bg-blue-900 text-blue-400'
                    }`}>
                    {m.status || 'Unknown'}
                  </span>
                </div>
              </div>
              <div className="flex items-center justify-between mt-2">
                <div className="flex items-center gap-2 text-sm text-slate-400">
                  <Clock className="w-4 h-4" />
                  <span>{m.duration || 'Unknown'}</span>
                </div>
                {/* Resume Button for Stuck Tasks */}
                {['downloaded', 'transcribing', 'processing', 'in_call_recording'].includes(m.status) && (
                  <button
                    onClick={(e) => resumeProcessing(e, m.meeting_id)}
                    className="px-3 py-1 bg-blue-600 hover:bg-blue-500 text-white text-xs rounded transition-colors"
                  >
                    Resume
                  </button>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 p-6 md:p-8 text-white font-sans">
      <div className="max-w-3xl mx-auto">
        <header className="flex flex-col md:flex-row justify-between items-center mb-8 gap-4">
          <div>
            <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-400">
              TalkTrace
            </h1>
            <p className="text-slate-400 mt-1">Secure Meeting Intelligence</p>
          </div>

          {/* Top Navigation */}
          <div className="bg-slate-800/50 p-1 rounded-xl border border-slate-700 flex gap-1">
            <button
              onClick={() => { setView('new'); reset(); }}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${view === 'new' ? 'bg-blue-600 text-white shadow-lg' : 'text-slate-400 hover:text-white hover:bg-white/5'}`}
            >
              <Mic className="w-4 h-4" />
              New Session
            </button>
            <button
              onClick={() => { setView('library'); fetchMeetings(); }}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${view === 'library' ? 'bg-purple-600 text-white shadow-lg' : 'text-slate-400 hover:text-white hover:bg-white/5'}`}
            >
              <List className="w-4 h-4" />
              Previous Work
            </button>
            {isHistorical && (
              <button
                onClick={reset}
                className="px-4 py-2 rounded-lg text-sm font-medium text-slate-400 hover:text-white hover:bg-white/5 flex items-center gap-2 border-l border-slate-700 ml-2"
              >
                <LogOut className="w-4 h-4 rotate-180" />
                Exit History
              </button>
            )}
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
          {view === 'library' ? renderLibrary() : (
            <>
              {/* Connection Card (Only show if no active meeting in 'new' view) */}
              {!meetingId && (
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
              )}
            </>
          )}


          {/* Status & Actions Card (Only show if we have a status/meetingId and view is NOT library) */}
          {/* Note: In 'library' view we renderLibrary called above. In 'new', we show this block if meetingId exists */}
          {/* Actually, my logic above hides Connection Card if meetingId exists. So here we show the rest. */}
          {/* We must wrap this to only show if view !== 'library' */}

          {view !== 'library' && (status !== 'idle' || logs.length > 0) && (
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
                <div className="flex gap-4 mb-6">
                  <div className="text-slate-400 text-sm animate-pulse">Decrypting Audio Stream...</div>
                </div>
              )}

              {/* Transcription Area with TABS */}
              {status === 'complete' && (
                <div className="mb-6 p-6 bg-slate-900/50 rounded-xl border border-slate-700">
                  {/* Tabs */}
                  <div className="flex items-center gap-6 mb-4 border-b border-slate-700/50 pb-2">
                    <button onClick={() => setActiveTab('transcript')} className={`text-sm font-semibold pb-2 border-b-2 transition-all ${activeTab === 'transcript' ? 'text-blue-400 border-blue-400' : 'text-slate-500 border-transparent hover:text-slate-300'}`}>
                      Transcript
                    </button>
                    <button onClick={() => setActiveTab('summary')} className={`text-sm font-semibold pb-2 border-b-2 transition-all ${activeTab === 'summary' ? 'text-purple-400 border-purple-400' : 'text-slate-500 border-transparent hover:text-slate-300'}`}>
                      Summary & Actions
                    </button>
                  </div>

                  <div className="flex justify-end items-center mb-4 gap-2">
                    {/* Dropdown removed as per backend protocol (Phase 3 & 5 says backend does it all) */}
                    {/* Only "Generate" is irrelevant now as we just fetch what backend pushed. */}
                    {/* We can show a status or refresh button? */}
                    <span className="text-xs text-slate-500 uppercase tracking-widest">
                      Secured by TalkTrace Private Pipeline
                    </span>
                  </div>

                  {/* Removed progress bar as backend does transcription */}

                  {transcript && (
                    <div className="animate-in fade-in slide-in-from-bottom-2">
                      {activeTab === 'transcript' ? (
                        <textarea
                          value={isEditing ? editContent : transcript}
                          onChange={(e) => setEditContent(e.target.value)}
                          readOnly={!isEditing}
                          className={`w-full h-48 bg-slate-950 p-4 rounded-lg text-slate-300 font-mono text-sm leading-relaxed border ${isEditing ? 'border-blue-500 focus:ring-1 focus:ring-blue-500' : 'border-slate-800 focus:border-purple-500/50'} outline-none resize-none transition-all`}
                        />
                      ) : (
                        <div className="w-full h-48 bg-slate-950 p-4 rounded-lg text-slate-300 font-mono text-sm leading-relaxed border border-slate-800 overflow-y-auto whitespace-pre-wrap">
                          {
                            summary ? (
                              typeof summary === 'string' ? summary : JSON.stringify(summary, null, 2)
                            ) : (
                              <p className="text-slate-500 italic">Summary generation in progress or not available...</p>
                            )}
                        </div>
                      )}

                      {/* Summary Action Bar */}
                      {activeTab === 'summary' && summary && (
                        <div className="flex justify-end items-center mt-2 gap-2">
                          <button
                            onClick={() => {
                              const text = typeof summary === 'string' ? summary : JSON.stringify(summary, null, 2);
                              const doc = new jsPDF();
                              doc.text(doc.splitTextToSize(text, 180), 10, 10);
                              doc.save(`summary_${meetingId}.pdf`);
                            }}
                            className="px-3 py-1 bg-slate-800 hover:bg-slate-700 rounded text-xs text-white border border-slate-600"
                          >
                            PDF
                          </button>
                          <button
                            onClick={() => {
                              const text = typeof summary === 'string' ? summary : JSON.stringify(summary, null, 2);
                              const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
                              const url = URL.createObjectURL(blob);
                              const a = document.createElement('a');
                              a.href = url;
                              a.download = `summary_${meetingId}.txt`;
                              a.click();
                              URL.revokeObjectURL(url);
                            }}
                            className="px-3 py-1 bg-slate-800 hover:bg-slate-700 rounded text-xs text-white border border-slate-600"
                          >
                            TXT
                          </button>
                        </div>
                      )}

                      {/* Action Bar */}
                      <div className="flex justify-between items-center mt-2 flex-wrap gap-2">
                        <div className="text-xs text-slate-500">
                          {isEditing ? 'Editing Mode...' : 'Securely rendered from memory.'}
                        </div>
                        <div className="flex gap-2">
                          {/* Edit Controls */}
                          {activeTab === 'transcript' && (
                            <>
                              {isEditing ? (
                                <>
                                  <button onClick={() => setIsEditing(false)} className="px-3 py-1 bg-red-900/50 hover:bg-red-900/80 text-red-200 rounded text-xs border border-red-800">
                                    Cancel
                                  </button>
                                  <button onClick={saveEdit} className="px-3 py-1 bg-green-600 hover:bg-green-500 text-white rounded text-xs border border-green-500">
                                    Save Verification
                                  </button>
                                </>
                              ) : (
                                <button onClick={() => { setEditContent(transcript); setIsEditing(true); }} className="px-3 py-1 bg-slate-800 hover:bg-slate-700 rounded text-xs text-white border border-slate-600">
                                  Edit
                                </button>
                              )}
                            </>
                          )}

                          <button onClick={() => setShowHistory(!showHistory)} className={`px-3 py-1 rounded text-xs border ${showHistory ? 'bg-purple-900/50 border-purple-500 text-purple-200' : 'bg-slate-800 hover:bg-slate-700 text-white border-slate-600'}`}>
                            History
                          </button>

                          <button
                            onClick={() => {
                              const doc = new jsPDF();
                              doc.text(transcript, 10, 10);
                              doc.save(`transcript_${meetingId}.pdf`);
                            }}
                            className="px-3 py-1 bg-slate-800 hover:bg-slate-700 rounded text-xs text-white border border-slate-600"
                          >
                            PDF
                          </button>
                          <button
                            onClick={() => navigator.clipboard.writeText(transcript)}
                            className="px-3 py-1 bg-slate-800 hover:bg-slate-700 rounded text-xs text-white border border-slate-600"
                          >
                            Copy
                          </button>
                        </div>
                      </div>

                      {/* History Panel */}
                      {showHistory && (
                        <div className="mt-4 p-4 bg-slate-900/80 rounded-lg border border-slate-700 max-h-40 overflow-y-auto">
                          <h4 className="text-xs font-semibold text-slate-400 mb-2 uppercase tracking-wide">Version History</h4>
                          <div className="space-y-2">
                            {history.length === 0 ? <span className="text-xs text-slate-500">No history available.</span> : null}
                            {history.map((ver, idx) => (
                              <div key={idx} className="flex justify-between items-center text-xs p-2 hover:bg-white/5 rounded cursor-pointer" onClick={() => setTranscript(ver.content)}>
                                <span className="text-slate-300">Version {ver.version}</span>
                                <span className="text-slate-500">{ver.date}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Integrity Check Dropzone (Historical Only) */}
                  {isHistorical && (
                    <div className="mt-8 pt-8 border-t border-slate-800">
                      <h4 className="text-sm font-semibold text-slate-400 mb-4 flex items-center gap-2">
                        <CheckCircle className="w-4 h-4" />
                        Metadata Integrity Check
                      </h4>
                      <div
                        className="border-2 border-dashed border-slate-700 rounded-xl p-6 text-center hover:border-blue-500/50 transition-colors"
                        onDragOver={(e) => e.preventDefault()}
                        onDrop={(e) => {
                          e.preventDefault();
                          if (e.dataTransfer.files[0]) verifyDocument(e.dataTransfer.files[0]);
                        }}
                      >
                        <p className="text-sm text-slate-400">
                          Drag & Drop a local PDF/TXT file here to verify its authenticity against the audit log.
                        </p>
                        <input
                          type="file"
                          className="hidden"
                          id="verify-upload"
                          onChange={(e) => {
                            if (e.target.files[0]) verifyDocument(e.target.files[0]);
                          }}
                        />
                        <label htmlFor="verify-upload" className="mt-4 inline-block px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-xs font-semibold cursor-pointer border border-slate-600">
                          Select File
                        </label>
                      </div>
                    </div>
                  )}
                </div>
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
      </div >
    </div >
  );
}

