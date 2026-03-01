// Firebase Authentication Service

const AuthService = {
    // Current user cache
    currentUser: null,
    unsubscribe: null,

    // Initialize auth state listener
    init(callback) {
        auth.onAuthStateChanged(async (user) => {
            if (user) {
                // Get additional user data from Firestore
                const userData = await AuthService.getUserData(user.uid);
                this.currentUser = {
                    uid: user.uid,
                    email: user.email,
                    displayName: user.displayName || userData?.fullName || user.email.split('@')[0],
                    photoURL: user.photoURL,
                    fullName: userData?.fullName || user.displayName || '',
                    createdAt: userData?.createdAt || null,
                    notificationPreferences: userData?.notificationPreferences || {
                        emailAlerts: true,
                        scanCompletion: true,
                        weeklyReports: false
                    }
                };
            } else {
                this.currentUser = null;
            }
            callback(this.currentUser);
        });
    },

    // Sign up with email and password
    async signup(email, password, fullName) {
        try {
            const userCredential = await auth.createUserWithEmailAndPassword(email, password);
            const user = userCredential.user;

            // Create user profile in Firestore
            await db.collection('users').doc(user.uid).set({
                fullName: fullName,
                email: email,
                createdAt: firebase.firestore.FieldValue.serverTimestamp(),
                notificationPreferences: {
                    emailAlerts: true,
                    scanCompletion: true,
                    weeklyReports: false
                }
            });

            // Update display name
            await user.updateProfile({ displayName: fullName });

            return { success: true, user };
        } catch (error) {
            return { success: false, error: error.message };
        }
    },

    // Sign in with email and password
    async login(email, password) {
        try {
            const userCredential = await auth.signInWithEmailAndPassword(email, password);
            return { success: true, user: userCredential.user };
        } catch (error) {
            return { success: false, error: error.message };
        }
    },

    // Sign in with Google
    async signInWithGoogle() {
        try {
            const result = await auth.signInWithPopup(googleProvider);
            
            // Check if user profile exists, create if not
            const userDoc = await db.collection('users').doc(result.user.uid).get();
            if (!userDoc.exists) {
                await db.collection('users').doc(result.user.uid).set({
                    fullName: result.user.displayName,
                    email: result.user.email,
                    createdAt: firebase.firestore.FieldValue.serverTimestamp(),
                    notificationPreferences: {
                        emailAlerts: true,
                        scanCompletion: true,
                        weeklyReports: false
                    }
                });
            }
            
            return { success: true, user: result.user };
        } catch (error) {
            return { success: false, error: error.message };
        }
    },

    // Sign in with GitHub
    async signInWithGithub() {
        try {
            const result = await auth.signInWithPopup(githubProvider);
            
            const userDoc = await db.collection('users').doc(result.user.uid).get();
            if (!userDoc.exists) {
                await db.collection('users').doc(result.user.uid).set({
                    fullName: result.user.displayName || result.user.email.split('@')[0],
                    email: result.user.email,
                    createdAt: firebase.firestore.FieldValue.serverTimestamp(),
                    notificationPreferences: {
                        emailAlerts: true,
                        scanCompletion: true,
                        weeklyReports: false
                    }
                });
            }
            
            return { success: true, user: result.user };
        } catch (error) {
            return { success: false, error: error.message };
        }
    },

    // Sign out
    async logout() {
        try {
            await auth.signOut();
            this.currentUser = null;
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    },

    // Password reset
    async resetPassword(email) {
        try {
            await auth.sendPasswordResetEmail(email);
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    },

    // Get user data from Firestore
    async getUserData(uid) {
        try {
            const doc = await db.collection('users').doc(uid).get();
            return doc.exists ? doc.data() : null;
        } catch (error) {
            console.error('Error getting user data:', error);
            return null;
        }
    },

    // Update user profile
    async updateProfile(uid, data) {
        try {
            await db.collection('users').doc(uid).update(data);
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    },

    // Update notification preferences
    async updateNotificationPreferences(uid, preferences) {
        try {
            await db.collection('users').doc(uid).update({
                notificationPreferences: preferences
            });
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    },

    // Get current user
    getCurrentUser() {
        return this.currentUser;
    },

    // Check if user is logged in
    isLoggedIn() {
        return !!this.currentUser;
    }
};

// Scan Service for Firestore
const ScanService = {
    // Save a scan to Firestore
    async saveScan(userId, scanData) {
        try {
            const scanRef = await db.collection('scans').add({
                userId: userId,
                targetUrl: scanData.targetUrl,
                scanMode: scanData.scanMode,
                startedAt: firebase.firestore.FieldValue.serverTimestamp(),
                completedAt: null,
                status: 'running',
                summary: scanData.summary || null,
                vulnerabilities: [],
                riskScore: scanData.riskScore || 0
            });
            return { success: true, scanId: scanRef.id };
        } catch (error) {
            return { success: false, error: error.message };
        }
    },

    // Update scan with results
    async updateScanResults(scanId, results) {
        try {
            await db.collection('scans').doc(scanId).update({
                completedAt: firebase.firestore.FieldValue.serverTimestamp(),
                status: 'completed',
                summary: results.risk_score_summary,
                vulnerabilities: results.vulnerabilities || [],
                riskScore: results.risk_score_summary?.total_risk_score || 0
            });
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    },

    // Get user's scans
    async getUserScans(userId, limit = 50) {
        try {
            const snapshot = await db.collection('scans')
                .where('userId', '==', userId)
                .orderBy('startedAt', 'desc')
                .limit(limit)
                .get();
            
            return {
                success: true,
                scans: snapshot.docs.map(doc => ({
                    id: doc.id,
                    ...doc.data(),
                    startedAt: doc.data().startedAt?.toDate()?.toISOString(),
                    completedAt: doc.data().completedAt?.toDate()?.toISOString()
                }))
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    },

    // Get single scan
    async getScan(scanId) {
        try {
            const doc = await db.collection('scans').doc(scanId).get();
            if (!doc.exists) {
                return { success: false, error: 'Scan not found' };
            }
            return {
                success: true,
                scan: {
                    id: doc.id,
                    ...doc.data(),
                    startedAt: doc.data().startedAt?.toDate()?.toISOString(),
                    completedAt: doc.data().completedAt?.toDate()?.toISOString()
                }
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    },

    // Delete a scan
    async deleteScan(scanId) {
        try {
            await db.collection('scans').doc(scanId).delete();
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    },

    // Get scan statistics
    async getUserStats(userId) {
        try {
            const snapshot = await db.collection('scans')
                .where('userId', '==', userId)
                .get();
            
            const scans = snapshot.docs.map(doc => doc.data());
            const totalScans = scans.length;
            const completedScans = scans.filter(s => s.status === 'completed').length;
            
            // Count vulnerabilities
            let totalVulns = 0;
            let criticalCount = 0;
            let highCount = 0;
            
            scans.forEach(scan => {
                if (scan.summary) {
                    totalVulns += (scan.summary.critical || 0) + (scan.summary.high || 0) + 
                                  (scan.summary.medium || 0) + (scan.summary.low || 0);
                    criticalCount += scan.summary.critical || 0;
                    highCount += scan.summary.high || 0;
                }
            });

            return {
                success: true,
                stats: {
                    totalScans,
                    completedScans,
                    totalVulnerabilities: totalVulns,
                    criticalFindings: criticalCount,
                    highFindings: highCount
                }
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }
};
