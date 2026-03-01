// Firebase Configuration
// Get these values from: Firebase Console > Project Settings > Your Apps > Web App

const firebaseConfig = {
    apiKey: "AIzaSyCBZfW2em-aTE4fmtJyg4FTjwoPnYrmAzI",
    authDomain: "vulncheck-3d5b7.firebaseapp.com",
    projectId: "vulncheck-3d5b7",
    storageBucket: "vulncheck-3d5b7.firebasestorage.app",
    messagingSenderId: "859782962507",
    appId: "1:859782962507:web:ab1525957517aabc849cce"
};

// Initialize Firebase
firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const db = firebase.firestore();

// Authentication providers
const googleProvider = new firebase.auth.GoogleAuthProvider();
const githubProvider = new firebase.auth.GithubAuthProvider();
