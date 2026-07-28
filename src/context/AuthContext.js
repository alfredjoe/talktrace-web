import { createContext, useContext, useEffect, useState } from 'react';
import { onAuthStateChanged, signOut, sendEmailVerification } from 'firebase/auth';
import { auth } from '../firebase';
import { createUserProfile, getUserProfile } from '../services/firestoreService';

const AuthContext = createContext(null);
export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (u) => {
      setUser(u);
      if (u) {
        // Sync profile to Firestore users collection
        await createUserProfile(u.uid, {
          email: u.email,
          name: u.displayName || u.email.split('@')[0],
          emailVerified: u.emailVerified
        });
        const userProf = await getUserProfile(u.uid);
        setProfile(userProf);
      } else {
        setProfile(null);
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const resendVerificationEmail = async () => {
    if (auth.currentUser) {
      await sendEmailVerification(auth.currentUser);
    }
  };

  const logout = () => signOut(auth);

  return (
    <AuthContext.Provider value={{ user, profile, loading, logout, resendVerificationEmail }}>
      {children}
    </AuthContext.Provider>
  );
}
