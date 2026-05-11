const crypto = require('crypto');

function calculateHash(content) {
    return crypto.createHash('sha256').update(content).digest('hex');
}

// Mock DB data
const json = {
    text: "RAW TEXT HERE",
    segments: [
        { speaker: "Speaker 1", start: 61.5, text: "Hello there." },
        { speaker: "Speaker 2", start: 70.9, text: "Hi!" }
    ]
};

// 1. Frontend Download (TXT)
let text = "";
text = json.segments.map(s => {
    const t = new Date(s.start * 1000).toISOString().substr(14, 5);
    return `[${t}] ${s.speaker}: ${s.text}`;
}).join('\n\n');

console.log("=== FRONTEND EXPORTED CONTENT ===");
console.log(text);

// 2. Frontend Candidates
let variants = [
    text,
    text.replace(/\r\n/g, '\n'),
    text.replace(/\s+/g, ' ').trim()
];
const candidates = variants.map(v => calculateHash(v));
console.log("Frontend Collapsed Hash:", candidates[2]);

// 3. Backend Verification
const formatTime = (secs) => {
    const m = Math.floor(secs / 60);
    const s = Math.floor(secs % 60);
    return `${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
};

const formattedLines = json.segments.map(seg =>
    `[${formatTime(seg.start)}] ${seg.speaker || 'Speaker'}: ${seg.text ? seg.text.trim() : ''}`
).join('\n\n');

console.log("\n=== BACKEND RECONSTRUCTED ===");
console.log(formattedLines);

const formattedCollapsedHash = calculateHash(formattedLines.replace(/\s+/g, ' ').trim());
console.log("Backend Collapsed Hash: ", formattedCollapsedHash);

console.log("MATCH:", candidates.includes(formattedCollapsedHash));
