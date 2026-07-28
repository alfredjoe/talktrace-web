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

let y = 16;

// Header (Handwritten Style)
doc.setFont('helvetica', 'bold');
doc.setFontSize(22);
doc.setTextColor(18, 30, 49);
doc.text('Activity diagram', pageWidth / 2, y, { align: 'center' });
y += 10;

// Helper to draw Arrow Line
function drawArrow(x1, y1, x2, y2, label = '') {
  doc.setLineWidth(0.4);
  doc.setDrawColor(30, 90, 180);
  doc.line(x1, y1, x2, y2);

  // Arrowhead
  const angle = Math.atan2(y2 - y1, x2 - x1);
  const headLen = 2.5;
  const arrowX1 = x2 - headLen * Math.cos(angle - Math.PI / 6);
  const arrowY1 = y2 - headLen * Math.sin(angle - Math.PI / 6);
  const arrowX2 = x2 - headLen * Math.cos(angle + Math.PI / 6);
  const arrowY2 = y2 - headLen * Math.sin(angle + Math.PI / 6);

  doc.setFillColor(30, 90, 180);
  doc.triangle(x2, y2, arrowX1, arrowY1, arrowX2, arrowY2, 'FD');

  if (label) {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(30, 90, 180);
    doc.text(label, ((x1 + x2) / 2) + 2, ((y1 + y2) / 2) - 1);
  }
}

// Helper to draw Action Box
function drawActionBox(text, x, startY, width = 64, height = 9) {
  doc.setLineWidth(0.4);
  doc.setDrawColor(24, 43, 73);
  doc.setFillColor(255, 255, 255);
  doc.roundedRect(x, startY, width, height, 2, 2, 'FD');

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(24, 43, 73);
  doc.text(text, x + (width / 2), startY + (height / 2) + 1.2, { align: 'center' });

  return { x, y: startY, width, height };
}

// Helper to draw Decision Diamond
function drawDecisionDiamond(text, centerX, centerY, width = 32, height = 12) {
  doc.setLineWidth(0.4);
  doc.setDrawColor(24, 43, 73);

  const top = { x: centerX, y: centerY - (height / 2) };
  const right = { x: centerX + (width / 2), y: centerY };
  const bottom = { x: centerX, y: centerY + (height / 2) };
  const left = { x: centerX - (width / 2), y: centerY };

  doc.line(top.x, top.y, right.x, right.y);
  doc.line(right.x, right.y, bottom.x, bottom.y);
  doc.line(bottom.x, bottom.y, left.x, left.y);
  doc.line(left.x, left.y, top.x, top.y);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(6.5);
  doc.setTextColor(24, 43, 73);
  doc.text(text, centerX, centerY + 1, { align: 'center' });

  return { top, right, bottom, left, width, height, centerX, centerY };
}

const centerX = pageWidth / 2;

// 1. Start Node (Solid Circle)
doc.setFillColor(24, 43, 73);
doc.circle(centerX, y, 3, 'F');

let prevY = y + 3;
y += 10;

// 2. User Authentication
drawArrow(centerX, prevY, centerX, y);
const b0 = drawActionBox('User Logs In / Authenticates Account', centerX - 32, y);
prevY = b0.y + b0.height;
y = prevY + 9;

// 3. Submit Meeting URL
drawArrow(centerX, prevY, centerX, y);
const b1 = drawActionBox('Submit Meeting URL or Select Audio Recording', centerX - 34, y, 68);
prevY = b1.y + b1.height;
y = prevY + 9;

// 4. Deploy Assistant Bot
drawArrow(centerX, prevY, centerX, y);
const b2 = drawActionBox('Deploy AI Assistant Bot to Meeting Room', centerX - 32, y);
prevY = b2.y + b2.height;
y = prevY + 9;

// 5. Secure Stream Audio
drawArrow(centerX, prevY, centerX, y);
const b3 = drawActionBox('Secure Audio Stream in Encrypted Vault', centerX - 32, y);
prevY = b3.y + b3.height;
y = prevY + 11;

// 6. Decision: Duplicate Meeting?
drawArrow(centerX, prevY, centerX, y - 6);
const d1 = drawDecisionDiamond('Duplicate?', centerX, y);

// Branch No (Continue down)
drawArrow(centerX, d1.bottom.y, centerX, d1.bottom.y + 9, 'No');
prevY = d1.bottom.y + 9;
y = prevY;

// Branch Yes (Side Alert)
const rejectBox = drawActionBox('Display Duplicate Warning Alert', centerX - 75, d1.centerY - 4.5, 36, 9);
drawArrow(d1.left.x, d1.centerY, rejectBox.x + rejectBox.width, d1.centerY, 'Yes');

// 7. Speech & Voice Separation
const b4 = drawActionBox('Process Speech & Separate Speaker Voices', centerX - 34, y, 68);
prevY = b4.y + b4.height;
y = prevY + 9;

// 8. Detect Meeting Language
drawArrow(centerX, prevY, centerX, y);
const b5 = drawActionBox('Detect Meeting Language Automatically', centerX - 32, y);
prevY = b5.y + b5.height;
y = prevY + 9;

// 9. Generate Executive Minutes & Tasks
drawArrow(centerX, prevY, centerX, y);
const b6 = drawActionBox('Generate Executive Minutes & Action Items', centerX - 34, y, 68);
prevY = b6.y + b6.height;
y = prevY + 9;

// 10. Index Search Content
drawArrow(centerX, prevY, centerX, y);
const b7 = drawActionBox('Index Meeting Content for Natural Language Search', centerX - 38, y, 76);
prevY = b7.y + b7.height;
y = prevY + 9;

// 11. Render Transcript & Analytics
drawArrow(centerX, prevY, centerX, y);
const b8 = drawActionBox('Display Decrypted Timeline, Speaker Charts & Task Board', centerX - 42, y, 84);
prevY = b8.y + b8.height;
y = prevY + 10;

// 12. End Node (Bullseye Circle)
drawArrow(centerX, prevY, centerX, y);
doc.setLineWidth(0.5);
doc.setDrawColor(24, 43, 73);
doc.setFillColor(255, 255, 255);
doc.circle(centerX, y + 4, 4, 'FD');
doc.setFillColor(24, 43, 73);
doc.circle(centerX, y + 4, 2, 'F');

// Output PDF Files
const pdfData = doc.output('arraybuffer');
const buffer = Buffer.from(pdfData);

const filename = 'TalkTrace_Activity_Diagram_Functional.pdf';
const pathsToSave = [
  path.join('C:\\Users\\ajint\\.gemini\\antigravity-ide\\brain\\ffbd9642-5869-4147-ad6a-4b76d2556748', filename),
  path.join('d:\\talktrace-web-main', filename),
  path.join('d:\\Talktrace_backend-main', filename)
];

pathsToSave.forEach((p) => {
  fs.writeFileSync(p, buffer);
  console.log(`[Functional Activity Diagram PDF Generator] Successfully generated PDF at: ${p}`);
});
