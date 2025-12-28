// src/firebase.js
import { initializeApp } from 'firebase/app';
import { getAuth } from 'firebase/auth';

const firebaseConfig = {
  apiKey: "AIzaSyDZz5SJE7dCTz0kW56xIvQ_7hlCAdEZjic",
  authDomain: "talktrace-demo.firebaseapp.com",
  projectId: "talktrace-demo",
  storageBucket: "talktrace-demo.firebasestorage.app",
  messagingSenderId: "62110537544",
  appId: "1:62110537544:web:e49486b16c8806b644457d"
};


const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
