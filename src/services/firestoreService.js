import { db } from '../firebase';
import { 
  collection, 
  doc, 
  setDoc, 
  getDoc, 
  getDocs, 
  query, 
  where, 
  deleteDoc, 
  serverTimestamp 
} from 'firebase/firestore';

// 1. COLLECTION: users
export const createUserProfile = async (uid, userData) => {
  const userRef = doc(db, 'users', uid);
  await setDoc(userRef, {
    uid,
    name: userData.name || '',
    email: userData.email || '',
    emailVerified: userData.emailVerified || false,
    role: userData.role || 'user',
    createdAt: serverTimestamp()
  }, { merge: true });
};

export const getUserProfile = async (uid) => {
  const userRef = doc(db, 'users', uid);
  const snap = await getDoc(userRef);
  return snap.exists() ? snap.data() : null;
};

// 2. COLLECTION: meetings
export const saveMeetingRecord = async (meetingData) => {
  const meetingRef = doc(db, 'meetings', meetingData.id);
  await setDoc(meetingRef, {
    id: meetingData.id,
    user_id: meetingData.user_id,
    bot_id: meetingData.bot_id || null,
    status: meetingData.status || 'processing',
    process_state: meetingData.process_state || 'transcribing',
    language: meetingData.language || 'auto',
    duration_seconds: meetingData.duration_seconds || 0,
    created_at: meetingData.created_at || Date.now()
  }, { merge: true });
};

export const getUserMeetingsFromFirestore = async (userId) => {
  const q = query(collection(db, 'meetings'), where('user_id', '==', userId));
  const querySnap = await getDocs(q);
  const meetings = [];
  querySnap.forEach((doc) => {
    meetings.push(doc.data());
  });
  return meetings;
};

export const deleteMeetingRecordFromFirestore = async (meetingId) => {
  await deleteDoc(doc(db, 'meetings', meetingId));
  await deleteDoc(doc(db, 'meeting_keys', meetingId));
};

// 3. COLLECTION: meeting_keys
export const saveMeetingKeyToFirestore = async (meetingId, encryptedKeyBlob) => {
  const keyRef = doc(db, 'meeting_keys', meetingId);
  await setDoc(keyRef, {
    meeting_id: meetingId,
    encrypted_key_blob: encryptedKeyBlob
  });
};

// 4. COLLECTION: transcript_revisions
export const saveTranscriptRevisionToFirestore = async (revisionData) => {
  const revRef = doc(collection(db, 'transcript_revisions'));
  await setDoc(revRef, {
    id: revRef.id,
    meeting_id: revisionData.meeting_id,
    version: revisionData.version || 1,
    type: revisionData.type || 'transcript',
    content_hash: revisionData.content_hash,
    file_path: revisionData.file_path,
    edited_at: Date.now()
  });
};

// 5. COLLECTION: speaker_profiles
export const saveSpeakerProfileToFirestore = async (profileData) => {
  const profRef = doc(collection(db, 'speaker_profiles'));
  await setDoc(profRef, {
    id: profRef.id,
    user_id: profileData.user_id,
    speaker_label: profileData.speaker_label,
    speaker_name: profileData.speaker_name,
    voice_signature: profileData.voice_signature || null,
    updated_at: Date.now()
  });
};

// 6. COLLECTION: action_items
export const saveActionItemToFirestore = async (taskData) => {
  const taskRef = doc(db, 'action_items', taskData.id);
  await setDoc(taskRef, {
    id: taskData.id,
    meeting_id: taskData.meeting_id,
    task: taskData.task,
    assignee: taskData.assignee || 'Unassigned',
    deadline: taskData.deadline || 'ASAP',
    priority: taskData.priority || 'Medium',
    completed: taskData.completed || false,
    confidence: taskData.confidence || 0.95
  }, { merge: true });
};

// 7. COLLECTION: calendar_events
export const saveCalendarEventToFirestore = async (eventData) => {
  const eventRef = doc(db, 'calendar_events', eventData.id);
  await setDoc(eventRef, {
    id: eventData.id,
    user_id: eventData.user_id,
    title: eventData.title,
    start_time: eventData.start_time,
    meeting_link: eventData.meeting_link,
    source: eventData.source || 'Google',
    bot_scheduled: eventData.bot_scheduled || false
  }, { merge: true });
};

// 8. COLLECTION: search_history
export const logSearchQueryToFirestore = async (userId, queryText) => {
  const searchRef = doc(collection(db, 'search_history'));
  await setDoc(searchRef, {
    id: searchRef.id,
    user_id: userId,
    query: queryText,
    created_at: Date.now()
  });
};
