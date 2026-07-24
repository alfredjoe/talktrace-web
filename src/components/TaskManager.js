import React, { useState } from 'react';
import { CheckSquare, Square, Edit2, Sparkles } from 'lucide-react';

export default function TaskManager({ actions = [], meetingId = 'meeting' }) {
  const [taskList, setTaskList] = useState(() => {
    return (actions || []).map((act, idx) => {
      const isString = typeof act === 'string';
      return {
        id: idx,
        task: isString ? act : (act.task || act.action || "Task Item"),
        assignee: isString ? "Unassigned" : (act.assignee || act.with || "Unassigned"),
        deadline: isString ? "ASAP" : (act.deadline || act.details || "ASAP"),
        priority: isString ? "Medium" : (act.priority || "Medium"),
        completed: false
      };
    });
  });

  const [editingId, setEditingId] = useState(null);
  const [editText, setEditText] = useState('');
  const [filterPriority, setFilterPriority] = useState('All');

  const toggleTask = (id) => {
    setTaskList(prev => prev.map(t => t.id === id ? { ...t, completed: !t.completed } : t));
  };

  const startEdit = (taskObj) => {
    setEditingId(taskObj.id);
    setEditText(taskObj.task);
  };

  const saveEdit = (id) => {
    setTaskList(prev => prev.map(t => t.id === id ? { ...t, task: editText } : t));
    setEditingId(null);
  };

  const exportGitHubMarkdown = () => {
    const markdown = `# Task List Extracted from TalkTrace (${meetingId})\n\n` +
      taskList.map(t => `- [${t.completed ? 'x' : ' '}] **${t.task}** (Assignee: @${t.assignee}, Priority: ${t.priority}, Due: ${t.deadline})`).join('\n');
    
    const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `talktrace_github_issues_${meetingId}.md`;
    a.click();
  };

  const exportJiraPayload = () => {
    const payload = {
      issues: taskList.map(t => ({
        fields: {
          project: { key: "TT" },
          summary: t.task,
          description: `Extracted from TalkTrace Meeting ${meetingId}`,
          priority: { name: t.priority },
          assignee: { displayName: t.assignee },
          duedate: t.deadline
        }
      }))
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `talktrace_jira_payload_${meetingId}.json`;
    a.click();
  };

  const exportTrelloPayload = () => {
    const payload = {
      name: `TalkTrace Session ${meetingId}`,
      cards: taskList.map(t => ({
        name: t.task,
        desc: `Assignee: ${t.assignee}\nPriority: ${t.priority}\nDeadline: ${t.deadline}`,
        closed: t.completed
      }))
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `talktrace_trello_cards_${meetingId}.json`;
    a.click();
  };

  const filteredTasks = filterPriority === 'All'
    ? taskList
    : taskList.filter(t => t.priority === filterPriority);

  const completedCount = taskList.filter(t => t.completed).length;
  const totalCount = taskList.length;
  const progressPercent = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 0;

  return (
    <div className="space-y-4">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 bg-slate-900/80 p-4 rounded-xl border border-slate-800">
        <div className="w-full sm:w-auto">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-purple-400" /> AI Action Item Extraction & Task Sync
          </h3>
          <div className="flex items-center gap-3 mt-1.5">
            <div className="w-36 h-2 bg-slate-950 rounded-full border border-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-blue-500 via-indigo-500 to-emerald-400 transition-all duration-500 rounded-full"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
            <span className="text-[11px] font-bold text-slate-300">
              {completedCount} / {totalCount} Completed ({progressPercent}%)
            </span>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            onClick={exportGitHubMarkdown}
            className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold border border-slate-700 transition-colors flex items-center gap-1 cursor-pointer"
          >
            🐙 GitHub Issues
          </button>
          <button
            onClick={exportJiraPayload}
            className="px-2.5 py-1.5 bg-blue-900/40 hover:bg-blue-800/60 text-blue-200 rounded-lg text-xs font-semibold border border-blue-700/50 transition-colors flex items-center gap-1 cursor-pointer"
          >
            🔷 Jira API
          </button>
          <button
            onClick={exportTrelloPayload}
            className="px-2.5 py-1.5 bg-indigo-900/40 hover:bg-indigo-800/60 text-indigo-200 rounded-lg text-xs font-semibold border border-indigo-700/50 transition-colors flex items-center gap-1 cursor-pointer"
          >
            📋 Trello Board
          </button>
        </div>
      </div>

      {/* Priority Filter Bar */}
      <div className="flex items-center gap-2 text-xs">
        <span className="text-slate-400 font-semibold uppercase tracking-wider text-[10px]">Filter Priority:</span>
        {['All', 'High', 'Medium', 'Low'].map(p => (
          <button
            key={p}
            onClick={() => setFilterPriority(p)}
            className={`px-3 py-1 rounded-full font-bold transition-all text-[11px] cursor-pointer ${filterPriority === p ? 'bg-purple-600 text-white shadow-md shadow-purple-500/20' : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'}`}
          >
            {p}
          </button>
        ))}
      </div>

      {/* Task List */}
      <div className="space-y-2 max-h-96 overflow-y-auto">
        {filteredTasks.length === 0 ? (
          <p className="text-xs text-slate-500 italic py-4 text-center">No action items found for priority level "{filterPriority}".</p>
        ) : (
          filteredTasks.map(t => (
            <div
              key={t.id}
              className={`p-3.5 rounded-xl border transition-all flex items-start justify-between gap-3 ${t.completed ? 'bg-slate-950/40 border-slate-900 opacity-60' : 'bg-slate-900/90 border-slate-800 hover:border-purple-500/40'}`}
            >
              <div className="flex items-start gap-3 flex-1">
                <button
                  onClick={() => toggleTask(t.id)}
                  className="mt-0.5 text-purple-400 hover:text-purple-300 transition-colors cursor-pointer"
                >
                  {t.completed ? <CheckSquare className="w-4 h-4 text-emerald-400" /> : <Square className="w-4 h-4 text-slate-500" />}
                </button>

                <div className="flex-1">
                  {editingId === t.id ? (
                    <div className="flex gap-2 items-center">
                      <input
                        type="text"
                        value={editText}
                        onChange={(e) => setEditText(e.target.value)}
                        className="bg-slate-950 border border-purple-500 text-white text-xs p-1.5 rounded flex-1 outline-none"
                      />
                      <button onClick={() => saveEdit(t.id)} className="p-1.5 bg-emerald-600 text-white rounded text-xs font-bold">Save</button>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2">
                      <p className={`text-xs font-semibold ${t.completed ? 'line-through text-slate-500' : 'text-slate-200'}`}>{t.task}</p>
                      <button onClick={() => startEdit(t)} className="text-slate-500 hover:text-blue-400 transition-colors">
                        <Edit2 className="w-3 h-3" />
                      </button>
                    </div>
                  )}

                  <div className="flex items-center gap-2 mt-2">
                    <span className="text-[10px] bg-blue-500/15 border border-blue-500/30 text-blue-400 px-2 py-0.5 rounded font-semibold">
                      👤 {t.assignee}
                    </span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${t.priority === 'High' ? 'bg-red-500/15 text-red-400 border border-red-500/30' : t.priority === 'Medium' ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30' : 'bg-slate-800 text-slate-400'}`}>
                      ⚡ {t.priority}
                    </span>
                    <span className="text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded font-medium">
                      ⏰ {t.deadline}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
