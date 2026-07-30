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
    const unsubscribe = onAuthStateChanged(auth, (u) => {
      setUser(u);
      setLoading(false);

      if (u) {
        // Sync profile in background without blocking Auth loading state
        createUserProfile(u.uid, {
          email: u.email,
          name: u.displayName || u.email.split('@')[0],
          emailVerified: u.emailVerified
        })
          .then(() => getUserProfile(u.uid))
          .then((userProf) => {
            if (userProf) setProfile(userProf);
          })
          .catch((err) => {
            console.warn("Firestore user profile sync warning:", err);
          });
      } else {
        setProfile(null);
      }
    });

    // Fallback safety timeout: ensure loading state is cleared after 1.5s max
    const timer = setTimeout(() => {
      setLoading(false);
    }, 1500);

    return () => {
      unsubscribe();
      clearTimeout(timer);
    };
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
