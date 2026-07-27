const { jsPDF } = require('jspdf');
const fs = require('fs');
const path = require('path');

const doc = new jsPDF({
  orientation: 'portrait',
  unit: 'mm',
  format: 'a4'
});

const pageWidth = doc.internal.pageSize.getWidth();
const pageHeight = doc.internal.pageSize.getHeight();
const margin = 14;
const contentWidth = pageWidth - (margin * 2);

let y = 16;

function checkPageBreak(neededHeight = 25) {
  if (y + neededHeight > pageHeight - margin) {
    doc.addPage();
    y = 16;
  }
}

// Draw Document Header
doc.setFillColor(24, 43, 73); // Dark Navy Blue Header
doc.rect(0, 0, pageWidth, 28, 'F');

doc.setFont('helvetica', 'bold');
doc.setFontSize(16);
doc.setTextColor(255, 255, 255);
doc.text('TalkTrace Complete System Architecture & Database Spec', margin, 18);

doc.setFont('helvetica', 'normal');
doc.setFontSize(9);
doc.setTextColor(200, 220, 245);
doc.text('Combined Unified Document: Frontend (Web Client) + Backend (Node & Python Engine)', margin, 24);

y = 36;

// SECTION 1: SYSTEM OVERVIEW
doc.setFont('helvetica', 'bold');
doc.setFontSize(13);
doc.setTextColor(24, 43, 73);
doc.text('SECTION 1: SYSTEM OVERVIEW & REPOSITORY STRUCTURE', margin, y);
y += 6;

doc.setFont('helvetica', 'normal');
doc.setFontSize(8.5);
doc.setTextColor(50, 60, 75);
const overviewText = [
  'TalkTrace is an enterprise-grade, zero-trust meeting intelligence application.',
  'It provides real-time audio capture, local Whisper transcription, Pyannote speaker diarization,',
  'Google Translate language detection, client-side sentence embedding vector RAG search,',
  'LLM executive minutes extraction, task management, and Google/Outlook calendar auto-joins.'
];
overviewText.forEach(line => {
  doc.text(line, margin, y);
  y += 4.5;
});
y += 4;

// SECTION 2: FRONTEND COMPONENT ARCHITECTURE (talktrace-web)
checkPageBreak(30);
doc.setFont('helvetica', 'bold');
doc.setFontSize(13);
doc.setTextColor(24, 43, 73);
doc.text('SECTION 2: FRONTEND WEB ARCHITECTURE (talktrace-web)', margin, y);
y += 6;

const feTable = {
  title: 'Frontend Component Specs & State Architecture',
  desc: 'Overview of React UI components, security layers, client-side vector search engines, and auth contexts.',
  headers: ['No', 'Component / Module', 'Type', 'Responsibilities', 'Security / Tech Stack'],
  widths: [10, 40, 30, 60, 44],
  rows: [
    ['1', 'Dashboard.js', 'React View', 'Core workspace UI, loading stepper, summary minutes, export PDF/TXT', 'Tailwind, Lucide, jsPDF'],
    ['2', 'GlobalSearch.js', 'React Search', '128-d sentence vector embeddings & Cosine similarity RAG search', 'IndexedDB, Math Vector'],
    ['3', 'CalendarSync.js', 'React Module', 'Google & Outlook calendar meeting sync, bot auto-join scheduler', 'REST API, Token Auth'],
    ['4', 'TaskManager.js', 'React Module', 'AI action item extraction board, completion progress bar, CSV/Jira export', 'Local State, Exporters'],
    ['5', 'Analytics.js', 'React View', 'Speaker talk-time charts, WPM speeds, sentiment analysis, gap stats', 'Canvas, Math Metrics'],
    ['6', 'AuthContext.js', 'React Context', 'Firebase authentication, email verification workflow, route protection', 'Firebase Auth SDK'],
    ['7', 'Login.js / Signup.js', 'React Views', 'User registration with email verification link dispatch & resend', 'Firebase Auth']
  ]
};

// Render FE Table
doc.setFont('helvetica', 'bold');
doc.setFontSize(10);
doc.setTextColor(24, 43, 73);
doc.text(feTable.title, margin, y);
y += 4;

doc.setFont('helvetica', 'italic');
doc.setFontSize(8);
doc.setTextColor(80, 90, 105);
const feDescLines = doc.splitTextToSize(feTable.desc, contentWidth);
doc.text(feDescLines, margin, y);
y += (feDescLines.length * 4) + 2;

// Header
let rowHeight = 7;
doc.setFillColor(30, 65, 110);
doc.rect(margin, y, contentWidth, rowHeight, 'F');
doc.setFont('helvetica', 'bold');
doc.setFontSize(8);
doc.setTextColor(255, 255, 255);
let currentX = margin;
feTable.headers.forEach((h, colIdx) => {
  doc.text(h, currentX + 2, y + 4.8);
  currentX += feTable.widths[colIdx];
});
y += rowHeight;

// Rows
doc.setFont('helvetica', 'normal');
doc.setFontSize(7.5);
feTable.rows.forEach((r, rIdx) => {
  if (rIdx % 2 === 0) doc.setFillColor(245, 248, 252);
  else doc.setFillColor(255, 255, 255);
  doc.rect(margin, y, contentWidth, rowHeight, 'F');
  doc.setDrawColor(220, 228, 238);
  doc.line(margin, y + rowHeight, margin + contentWidth, y + rowHeight);

  currentX = margin;
  r.forEach((cell, cIdx) => {
    doc.setTextColor(40, 50, 65);
    const truncated = cell.length > 34 ? cell.substring(0, 32) + '...' : cell;
    doc.text(truncated, currentX + 2, y + 4.8);
    currentX += feTable.widths[cIdx];
  });
  y += rowHeight;
});
y += 8;

// SECTION 3: BACKEND ENGINE ARCHITECTURE (Talktrace_backend)
checkPageBreak(30);
doc.setFont('helvetica', 'bold');
doc.setFontSize(13);
doc.setTextColor(24, 43, 73);
doc.text('SECTION 3: BACKEND SERVICE & ENGINE ARCHITECTURE', margin, y);
y += 6;

const beTable = {
  title: 'Backend Modules, Pipelines & AI Engines',
  desc: 'Server REST endpoints, zero-trust vault storage, Python diarization, local Ollama NLP, and calendar sync.',
  headers: ['No', 'Backend Module', 'Tech / Runtime', 'Description & Functions', 'Key Security Layer'],
  widths: [10, 38, 30, 62, 44],
  rows: [
    ['1', 'server.js', 'Node.js Express', 'REST API server, RSA/AES key exchange, calendar routes, delete shredding', 'Bearer Token Auth'],
    ['2', 'pipeline_manager.js', 'Node.js Stream', 'FFmpeg ingestion, temp audio cleanup, duplicate check, NLP trigger', 'Stream Encryption'],
    ['3', 'storage_enc.js', 'Node.js Crypto', 'Local zero-trust storage vault, AES-256-CBC stream encryption', 'AES-256 Cryptography'],
    ['4', 'database.js', 'SQLite3', 'Database layer for meetings, keys, revisions, speaker profiles', 'Encrypted Blob Vault'],
    ['5', 'diarize.py', 'Python 3.10', 'WhisperX transcription, Pyannote diarization, Google Translate GTX detect', 'Torch CUDA/CPU int8'],
    ['6', 'nlp_local.js', 'Node.js / Ollama', 'Executes Llama 3.2 / Mistral for executive minutes & action items', 'Local Airgapped LLM'],
    ['7', 'calendar_sync.js', 'Node.js', 'Google Calendar & Outlook Graph API event sync, auto-join bot trigger', 'OAuth Tokens'],
    ['8', 'recall.js', 'Node.js Axios', 'Recall.ai bot launcher, meeting room auto-join, audio stream download', 'API Token Vault']
  ]
};

// Render BE Table
doc.setFont('helvetica', 'bold');
doc.setFontSize(10);
doc.setTextColor(24, 43, 73);
doc.text(beTable.title, margin, y);
y += 4;

doc.setFont('helvetica', 'italic');
doc.setFontSize(8);
doc.setTextColor(80, 90, 105);
const beDescLines = doc.splitTextToSize(beTable.desc, contentWidth);
doc.text(beDescLines, margin, y);
y += (beDescLines.length * 4) + 2;

// Header
doc.setFillColor(30, 65, 110);
doc.rect(margin, y, contentWidth, rowHeight, 'F');
doc.setFont('helvetica', 'bold');
doc.setFontSize(8);
doc.setTextColor(255, 255, 255);
currentX = margin;
beTable.headers.forEach((h, colIdx) => {
  doc.text(h, currentX + 2, y + 4.8);
  currentX += beTable.widths[colIdx];
});
y += rowHeight;

// Rows
doc.setFont('helvetica', 'normal');
doc.setFontSize(7.5);
beTable.rows.forEach((r, rIdx) => {
  if (rIdx % 2 === 0) doc.setFillColor(245, 248, 252);
  else doc.setFillColor(255, 255, 255);
  doc.rect(margin, y, contentWidth, rowHeight, 'F');
  doc.setDrawColor(220, 228, 238);
  doc.line(margin, y + rowHeight, margin + contentWidth, y + rowHeight);

  currentX = margin;
  r.forEach((cell, cIdx) => {
    doc.setTextColor(40, 50, 65);
    const truncated = cell.length > 34 ? cell.substring(0, 32) + '...' : cell;
    doc.text(truncated, currentX + 2, y + 4.8);
    currentX += beTable.widths[cIdx];
  });
  y += rowHeight;
});
y += 8;

// SECTION 4: DATABASE SCHEMA SPECIFICATION
checkPageBreak(30);
doc.setFont('helvetica', 'bold');
doc.setFontSize(13);
doc.setTextColor(24, 43, 73);
doc.text('SECTION 4: COMPLETE DATABASE SCHEMA SPECIFICATION', margin, y);
y += 6;

const dbTables = [
  {
    title: 'TABLE 1: users (System User Accounts)',
    desc: 'Stores core account information for system users across all roles. Manages unique login credentials, email verification status, and security parameters.',
    headers: ['No', 'Column Name', 'Data Type', 'Key / Constraint', 'Description'],
    widths: [10, 32, 38, 42, 60],
    rows: [
      ['1', 'uid', 'VARCHAR(128)', 'PK', 'Unique Firebase / Auth User Identifier'],
      ['2', 'name', 'VARCHAR(100)', 'NOT NULL', 'Full Name of User'],
      ['3', 'email', 'VARCHAR(150)', 'UNIQUE, NOT NULL', 'Login Email Address'],
      ['4', 'emailVerified', 'BOOLEAN', 'DEFAULT FALSE', 'Email Verification Confirmation Flag'],
      ['5', 'role', 'ENUM(admin,user)', 'DEFAULT user', 'Access Control Role'],
      ['6', 'createdAt', 'TIMESTAMP', 'DEFAULT NOW()', 'Account Creation Date']
    ]
  },
  {
    title: 'TABLE 2: meetings (Meeting Sessions & Audio Meta)',
    desc: 'Holds metadata for recorded meeting sessions, including language auto-detection, audio duration, processing lifecycle state, and owner association.',
    headers: ['No', 'Column Name', 'Data Type', 'Key / Constraint', 'Description'],
    widths: [10, 32, 38, 42, 60],
    rows: [
      ['1', 'id', 'VARCHAR(128)', 'PK', 'Unique Meeting UUID'],
      ['2', 'user_id', 'VARCHAR(128)', 'FK (users.uid)', 'Owner User Identifier'],
      ['3', 'bot_id', 'VARCHAR(128)', 'NULLABLE', 'Recall.ai Note-Taker Bot ID'],
      ['4', 'status', 'VARCHAR(50)', 'DEFAULT processing', 'Overall Status (processing, complete)'],
      ['5', 'process_state', 'VARCHAR(50)', 'DEFAULT initializing', 'Detailed Pipeline State (transcribing)'],
      ['6', 'language', 'VARCHAR(10)', 'DEFAULT auto', 'Google / Whisper Verified Language Code'],
      ['7', 'duration_seconds', 'INTEGER', 'DEFAULT 0', 'Audio Duration in Seconds'],
      ['8', 'created_at', 'BIGINT', 'NOT NULL', 'Session Epoch Timestamp (ms)']
    ]
  },
  {
    title: 'TABLE 3: meeting_keys (Zero-Trust Cryptographic Key Vault)',
    desc: 'Encrypted vault storing AES-256 keys and initialization vectors (IV) for local zero-trust audio and transcript encryption.',
    headers: ['No', 'Column Name', 'Data Type', 'Key / Constraint', 'Description'],
    widths: [10, 32, 38, 42, 60],
    rows: [
      ['1', 'meeting_id', 'VARCHAR(128)', 'PK, FK (meetings.id)', 'Associated Meeting ID'],
      ['2', 'encrypted_key_blob', 'TEXT', 'NOT NULL', 'Protected Key Vault Blob (AES/RSA)']
    ]
  },
  {
    title: 'TABLE 4: transcript_revisions (Version History & Hash Audit Log)',
    desc: 'Tracks version history and SHA-256 cryptographic hashes for transcripts and executive summaries to guarantee audit immutability.',
    headers: ['No', 'Column Name', 'Data Type', 'Key / Constraint', 'Description'],
    widths: [10, 32, 38, 42, 60],
    rows: [
      ['1', 'id', 'INTEGER', 'PK, AUTOINCREMENT', 'Revision Record ID'],
      ['2', 'meeting_id', 'VARCHAR(128)', 'FK (meetings.id)', 'Associated Meeting ID'],
      ['3', 'version', 'INTEGER', 'NOT NULL', 'Revision Version Number (1, 2, 3)'],
      ['4', 'type', 'ENUM(transcript, summary)', 'NOT NULL', 'Revision Artifact Type'],
      ['5', 'content_hash', 'VARCHAR(64)', 'NOT NULL', 'SHA-256 Cryptographic Hash'],
      ['6', 'file_path', 'VARCHAR(255)', 'NOT NULL', 'Encrypted Vault File Path'],
      ['7', 'edited_at', 'BIGINT', 'NOT NULL', 'Revision Edit Timestamp (ms)']
    ]
  },
  {
    title: 'TABLE 5: speaker_profiles (Recurring Speaker Voice & Name Registry)',
    desc: 'Stores persistent participant voice profiles and custom name mappings across meetings for automated Pyannote speaker recognition.',
    headers: ['No', 'Column Name', 'Data Type', 'Key / Constraint', 'Description'],
    widths: [10, 32, 38, 42, 60],
    rows: [
      ['1', 'id', 'INTEGER', 'PK, AUTOINCREMENT', 'Profile Record ID'],
      ['2', 'user_id', 'VARCHAR(128)', 'FK (users.uid)', 'Owner User ID'],
      ['3', 'speaker_label', 'VARCHAR(50)', 'NOT NULL', 'Pyannote Diarization Label'],
      ['4', 'speaker_name', 'VARCHAR(100)', 'NOT NULL', 'Real Human Name (e.g. Abin George)'],
      ['5', 'voice_signature', 'TEXT', 'NULLABLE', 'Dense Voice Embedding Vector'],
      ['6', 'updated_at', 'BIGINT', 'NOT NULL', 'Last Update Timestamp (ms)']
    ]
  },
  {
    title: 'TABLE 6: action_items (AI Action Items & Task Manager Board)',
    desc: 'Contains structured tasks automatically extracted by local LLMs (Ollama) from meeting transcripts, with priorities.',
    headers: ['No', 'Column Name', 'Data Type', 'Key / Constraint', 'Description'],
    widths: [10, 32, 38, 42, 60],
    rows: [
      ['1', 'id', 'VARCHAR(128)', 'PK', 'Action Item Unique ID'],
      ['2', 'meeting_id', 'VARCHAR(128)', 'FK (meetings.id)', 'Originating Meeting ID'],
      ['3', 'task', 'TEXT', 'NOT NULL', 'Action Item Task Description'],
      ['4', 'assignee', 'VARCHAR(100)', 'DEFAULT Unassigned', 'Responsible Participant'],
      ['5', 'deadline', 'VARCHAR(50)', 'DEFAULT ASAP', 'Targeted Due Date / Timeframe'],
      ['6', 'priority', 'ENUM(High,Medium,Low)', 'DEFAULT Medium', 'Task Urgency Rating'],
      ['7', 'completed', 'BOOLEAN', 'DEFAULT FALSE', 'Task Completion Status'],
      ['8', 'confidence', 'FLOAT', 'DEFAULT 0.95', 'LLM Extraction Confidence Score']
    ]
  },
  {
    title: 'TABLE 7: calendar_events (Google & Outlook Synced Meetings)',
    desc: 'Stores synced calendar events from Google Calendar and Microsoft Outlook Graph APIs for automated bot scheduling.',
    headers: ['No', 'Column Name', 'Data Type', 'Key / Constraint', 'Description'],
    widths: [10, 32, 38, 42, 60],
    rows: [
      ['1', 'id', 'VARCHAR(128)', 'PK', 'Calendar Event Unique ID'],
      ['2', 'user_id', 'VARCHAR(128)', 'FK (users.uid)', 'Associated User Account'],
      ['3', 'title', 'VARCHAR(255)', 'NOT NULL', 'Meeting Title / Subject'],
      ['4', 'start_time', 'TIMESTAMP', 'NOT NULL', 'Scheduled Start DateTime'],
      ['5', 'meeting_link', 'TEXT', 'NOT NULL', 'Google Meet / Teams / Zoom URL'],
      ['6', 'source', 'ENUM(Google, Outlook)', 'NOT NULL', 'Calendar Source API'],
      ['7', 'bot_scheduled', 'BOOLEAN', 'DEFAULT FALSE', 'Auto-Join Bot Scheduled Flag']
    ]
  },
  {
    title: 'TABLE 8: search_history (Natural Language Vector RAG Query Logs)',
    desc: 'Stores natural language search queries and 128-dimensional sentence embedding vector logs for client-side search audit.',
    headers: ['No', 'Column Name', 'Data Type', 'Key / Constraint', 'Description'],
    widths: [10, 32, 38, 42, 60],
    rows: [
      ['1', 'id', 'INTEGER', 'PK, AUTOINCREMENT', 'Log ID'],
      ['2', 'user_id', 'VARCHAR(128)', 'FK (users.uid)', 'Query User ID'],
      ['3', 'query', 'TEXT', 'NOT NULL', 'Natural Language Search String'],
      ['4', 'created_at', 'BIGINT', 'NOT NULL', 'Search Timestamp (ms)']
    ]
  }
];

dbTables.forEach((t) => {
  const estimatedHeight = 22 + (t.rows.length * 8);
  checkPageBreak(estimatedHeight);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(24, 43, 73);
  doc.text(t.title, margin, y);
  y += 4.5;

  doc.setFont('helvetica', 'italic');
  doc.setFontSize(8);
  doc.setTextColor(80, 90, 105);
  const descLines = doc.splitTextToSize(t.desc, contentWidth);
  doc.text(descLines, margin, y);
  y += (descLines.length * 3.8) + 2;

  // Header Box
  doc.setFillColor(30, 65, 110);
  doc.rect(margin, y, contentWidth, rowHeight, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(255, 255, 255);

  currentX = margin;
  t.headers.forEach((h, colIdx) => {
    doc.text(h, currentX + 2, y + 4.8);
    currentX += t.widths[colIdx];
  });

  y += rowHeight;

  // Rows
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);

  t.rows.forEach((r, rIdx) => {
    if (rIdx % 2 === 0) doc.setFillColor(245, 248, 252);
    else doc.setFillColor(255, 255, 255);
    doc.rect(margin, y, contentWidth, rowHeight, 'F');
    doc.setDrawColor(220, 228, 238);
    doc.line(margin, y + rowHeight, margin + contentWidth, y + rowHeight);

    currentX = margin;
    r.forEach((cell, cIdx) => {
      if (cIdx === 3 && cell.includes('PK')) {
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(190, 30, 30);
      } else {
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(40, 50, 65);
      }

      const truncated = cell.length > 32 ? cell.substring(0, 30) + '...' : cell;
      doc.text(truncated, currentX + 2, y + 4.8);
      currentX += t.widths[cIdx];
    });

    y += rowHeight;
  });

  y += 7;
});

// Output PDF Paths
const pdfData = doc.output('arraybuffer');
const buffer = Buffer.from(pdfData);

const filename = 'TalkTrace_Full_System_Architecture_and_Database_Specification.pdf';
const pathsToSave = [
  path.join('C:\\Users\\ajint\\.gemini\\antigravity-ide\\brain\\ffbd9642-5869-4147-ad6a-4b76d2556748', filename),
  path.join('d:\\talktrace-web-main', filename),
  path.join('d:\\Talktrace_backend-main', filename)
];

pathsToSave.forEach((p) => {
  fs.writeFileSync(p, buffer);
  console.log(`[Combined PDF Generator] Successfully generated PDF at: ${p}`);
});
