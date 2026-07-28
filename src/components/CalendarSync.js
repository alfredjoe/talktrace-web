import React, { useState, useEffect } from 'react';
import { Calendar, Bot, Mail, CheckCircle2, Clock, Video, Sparkles, Send, CalendarPlus } from 'lucide-react';

export default function CalendarSync({ user }) {
  const [events, setEvents] = useState([]);
  const [followupDrafts, setFollowupDrafts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scheduledBots, setScheduledBots] = useState({});
  const [dispatchedEmails, setDispatchedEmails] = useState({});
  const API_BASE = (process.env.REACT_APP_API_URL || 'http://localhost:3002').replace(/\/+$/, '');

  useEffect(() => {
    const fetchCalendarData = async () => {
      setLoading(true);
      try {
        const token = user ? await user.getIdToken() : '';
        const res = await fetch(`${API_BASE}/api/calendar/events`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
          const data = await res.json();
          setEvents(data.events || []);
        }

        // Fetch Follow-up Meeting Drafts for Action Items
        const draftRes = await fetch(`${API_BASE}/api/calendar/followup-drafts`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action_items: [] })
        });
        if (draftRes.ok) {
          const draftData = await draftRes.json();
          setFollowupDrafts(draftData.drafts || []);
        }
      } catch (e) {
        console.error("Calendar fetch error:", e);
      }
      setLoading(false);
    };

    fetchCalendarData();
  }, [user, API_BASE]);

  const scheduleAutoJoin = async (event) => {
    try {
      const token = user ? await user.getIdToken() : '';
      const res = await fetch(`${API_BASE}/api/calendar/auto-join`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ event })
      });
      if (res.ok) {
        const data = await res.json();
        setScheduledBots(prev => ({ ...prev, [event.id]: data.meetingId || true }));
      }
    } catch (e) {
      console.error("Auto-join schedule error:", e);
    }
  };

  const dispatchReport = async (event) => {
    try {
      const token = user ? await user.getIdToken() : '';
      const res = await fetch(`${API_BASE}/api/calendar/dispatch-report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ eventId: event.id, attendees: event.attendees })
      });
      if (res.ok) {
        setDispatchedEmails(prev => ({ ...prev, [event.id]: true }));
      }
    } catch (e) {
      console.error("Dispatch report error:", e);
    }
  };

  return (
    <div className="sleek-card p-6 border border-slate-800 rounded-2xl bg-slate-900/80 backdrop-blur-xl shadow-2xl space-y-6">
      {/* Module Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 pb-4 border-b border-slate-800">
        <div>
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Calendar className="w-4 h-4 text-cyan-400" /> Google & Outlook Calendar Integration
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Automated room auto-joins, attendee email summary dispatch, and free/busy follow-up drafts.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 px-3 py-1.5 rounded-full font-semibold">
          <Sparkles className="w-3.5 h-3.5" /> Auto-Join & Free/Busy Sync Active
        </div>
      </div>

      {/* Action Item Follow-up Meeting Drafts Section */}
      {followupDrafts.length > 0 && (
        <div className="space-y-3 bg-slate-950/60 p-4 rounded-xl border border-amber-500/20">
          <h4 className="text-xs font-bold text-amber-400 flex items-center gap-2">
            <CalendarPlus className="w-4 h-4" /> AI Action Item Follow-Up Meeting Drafts (Free/Busy Matched)
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {followupDrafts.map(draft => (
              <div key={draft.id} className="p-3 bg-slate-900 rounded-lg border border-slate-800 space-y-2">
                <div>
                  <h5 className="text-xs font-bold text-white">{draft.title}</h5>
                  <p className="text-[10px] text-slate-400">Assignee: {draft.assignee} | Due: {draft.deadline}</p>
                </div>
                <div className="text-[10px] font-mono text-emerald-400">
                  Suggested Slot: {draft.suggested_time} ({draft.free_busy_status})
                </div>
                <div className="flex gap-2 pt-1">
                  <a
                    href={draft.google_invite_url}
                    target="_blank"
                    rel="noreferrer"
                    className="flex-1 text-center py-1 bg-blue-600 hover:bg-blue-500 text-white rounded text-[11px] font-bold transition-all"
                  >
                    📅 Google Invite
                  </a>
                  <a
                    href={draft.outlook_invite_url}
                    target="_blank"
                    rel="noreferrer"
                    className="flex-1 text-center py-1 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-[11px] font-bold transition-all"
                  >
                    ✉️ Outlook Draft
                  </a>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Events List */}
      <div className="space-y-3">
        {loading ? (
          <p className="text-xs text-slate-400 italic py-4 text-center">Syncing upcoming calendar events...</p>
        ) : events.length === 0 ? (
          <p className="text-xs text-slate-500 italic py-4 text-center">No upcoming calendar meetings found.</p>
        ) : (
          events.map(evt => (
            <div key={evt.id} className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-cyan-500/40 transition-all flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <h4 className="text-xs font-bold text-slate-200">{evt.title}</h4>
                  <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${evt.source === 'Google Calendar' ? 'bg-blue-500/15 text-blue-400 border border-blue-500/30' : 'bg-indigo-500/15 text-indigo-400 border border-indigo-500/30'}`}>
                    {evt.source}
                  </span>
                </div>

                <div className="flex items-center gap-3 mt-1.5 text-[11px] text-slate-400">
                  <span className="flex items-center gap-1"><Clock className="w-3 h-3 text-cyan-400" /> {new Date(evt.start).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  <span className="flex items-center gap-1"><Video className="w-3 h-3 text-emerald-400" /> {evt.link}</span>
                  <span className="flex items-center gap-1"><Mail className="w-3 h-3 text-purple-400" /> {(evt.attendees || []).length} Attendees</span>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {scheduledBots[evt.id] ? (
                  <span className="px-3 py-1.5 bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 rounded-lg text-xs font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Bot Scheduled
                  </span>
                ) : (
                  <button
                    onClick={() => scheduleAutoJoin(evt)}
                    className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-bold transition-all shadow-md flex items-center gap-1 cursor-pointer"
                  >
                    <Bot className="w-3.5 h-3.5" /> Schedule Auto-Join
                  </button>
                )}

                {dispatchedEmails[evt.id] ? (
                  <span className="px-3 py-1.5 bg-blue-500/15 border border-blue-500/30 text-blue-400 rounded-lg text-xs font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Report Sent
                  </span>
                ) : (
                  <button
                    onClick={() => dispatchReport(evt)}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-bold transition-all border border-slate-700 flex items-center gap-1 cursor-pointer"
                  >
                    <Send className="w-3.5 h-3.5" /> Send Email Report
                  </button>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
