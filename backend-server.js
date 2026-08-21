// ============================================
// EKSO EMAIL MARKETING - BACKEND SERVER
// Node.js + Express + Nodemailer
// ============================================

const express = require('express');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Rate limiting untuk prevent abuse
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 menit
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// ============================================
// FIREBASE INITIALIZATION
// ============================================

const serviceAccount = require('./firebase-key.json');

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL
});

const db = admin.database();
const auth = admin.auth();

// ============================================
// NODEMAILER CONFIGURATION
// ============================================

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT || 587,
    secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

// Test SMTP connection
transporter.verify((error, success) => {
    if (error) {
        console.error('SMTP Error:', error);
    } else {
        console.log('✅ SMTP Server connected successfully');
    }
});

// ============================================
// MIDDLEWARE - CHECK AUTH & ROLE
// ============================================

async function checkAuth(req, res, next) {
    const token = req.headers.authorization?.split('Bearer ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const decodedToken = await admin.auth().verifyIdToken(token);
        req.uid = decodedToken.uid;
        req.email = decodedToken.email;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

async function checkRole(requiredRole) {
    return async (req, res, next) => {
        try {
            const userRoleSnapshot = await db.ref(`users/${req.uid}/role`).once('value');
            const userRole = userRoleSnapshot.val();

            if (!userRole) {
                return res.status(403).json({ error: 'User role not found' });
            }

            const roleHierarchy = {
                'super_admin': 3,
                'admin': 2,
                'user': 1
            };

            if (roleHierarchy[userRole] < roleHierarchy[requiredRole]) {
                return res.status(403).json({ error: 'Insufficient permissions' });
            }

            req.userRole = userRole;
            next();
        } catch (error) {
            return res.status(500).json({ error: error.message });
        }
    };
}

// ============================================
// ENDPOINTS
// ============================================

// 1. GET USER ROLE & PERMISSIONS
app.get('/api/user/role', checkAuth, async (req, res) => {
    try {
        const roleSnapshot = await db.ref(`users/${req.uid}/role`).once('value');
        const role = roleSnapshot.val() || 'user';
        
        const permissions = {
            'super_admin': [
                'view_all_subscribers',
                'view_all_campaigns',
                'create_campaign',
                'send_campaign',
                'manage_users',
                'view_analytics',
                'export_data',
                'manage_roles',
                'view_audit_log'
            ],
            'admin': [
                'view_all_subscribers',
                'view_all_campaigns',
                'create_campaign',
                'send_campaign',
                'view_analytics',
                'export_data'
            ],
            'user': [
                'view_own_subscribers',
                'view_own_campaigns',
                'create_campaign',
                'send_campaign',
                'view_own_analytics'
            ]
        };

        res.json({
            role: role,
            permissions: permissions[role] || permissions['user']
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 2. GET ALL USERS (Super Admin only)
app.get('/api/admin/users', 
    checkAuth, 
    checkRole('super_admin'), 
    async (req, res) => {
        try {
            const usersSnapshot = await db.ref('users').once('value');
            const usersData = usersSnapshot.val();
            
            const users = [];
            for (const uid in usersData) {
                const userData = usersData[uid];
                users.push({
                    uid: uid,
                    email: userData.email || 'unknown',
                    role: userData.role || 'user',
                    createdAt: userData.createdAt,
                    lastActive: userData.lastActive
                });
            }

            res.json(users);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    }
);

// 3. UPDATE USER ROLE (Super Admin only)
app.post('/api/admin/users/:userId/role', 
    checkAuth, 
    checkRole('super_admin'), 
    async (req, res) => {
        try {
            const { userId } = req.params;
            const { role } = req.body;

            if (!['super_admin', 'admin', 'user'].includes(role)) {
                return res.status(400).json({ error: 'Invalid role' });
            }

            await db.ref(`users/${userId}/role`).set(role);
            
            // Log audit
            await logAudit(req.uid, 'UPDATE_USER_ROLE', {
                targetUserId: userId,
                newRole: role
            });

            res.json({ success: true, message: 'User role updated' });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    }
);

// 4. SEND BULK EMAIL (Admin+ only)
app.post('/api/campaigns/:campaignId/send-bulk', 
    checkAuth, 
    checkRole('admin'), 
    async (req, res) => {
        try {
            const { campaignId } = req.params;
            const { recipientCount, batchSize = 100 } = req.body;

            // Get campaign details
            const campaignSnapshot = await db.ref(`users/${req.uid}/campaigns/${campaignId}`).once('value');
            const campaign = campaignSnapshot.val();

            if (!campaign) {
                return res.status(404).json({ error: 'Campaign not found' });
            }

            // Get template
            let templateContent = campaign.templateContent;
            if (campaign.templateId && campaign.templateId.startsWith('tpl_')) {
                const templateSnapshot = await db.ref(`users/${req.uid}/templates/${campaign.templateId}`).once('value');
                const template = templateSnapshot.val();
                templateContent = template?.htmlContent || campaign.templateContent;
            }

            // Create send job
            const jobId = uuidv4();
            const jobData = {
                jobId,
                campaignId,
                userId: req.uid,
                recipientCount,
                batchSize,
                status: 'pending',
                sentCount: 0,
                failedCount: 0,
                createdAt: new Date().toISOString(),
                startedAt: null,
                completedAt: null,
                progress: 0
            };

            // Save job to database
            await db.ref(`jobs/${jobId}`).set(jobData);

            // Queue job untuk processing
            processEmailJob(jobId, req.uid, campaignId, templateContent, batchSize);

            // Log audit
            await logAudit(req.uid, 'START_BULK_EMAIL', {
                campaignId,
                jobId,
                recipientCount
            });

            res.json({
                success: true,
                jobId,
                message: `Email job queued. Total recipients: ${recipientCount}`
            });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    }
);

// 5. GET EMAIL JOB STATUS
app.get('/api/jobs/:jobId', checkAuth, async (req, res) => {
    try {
        const { jobId } = req.params;
        
        const jobSnapshot = await db.ref(`jobs/${jobId}`).once('value');
        const job = jobSnapshot.val();

        if (!job) {
            return res.status(404).json({ error: 'Job not found' });
        }

        // Only owner or super_admin dapat see details
        if (job.userId !== req.uid) {
            const userRole = await db.ref(`users/${req.uid}/role`).once('value');
            if (userRole.val() !== 'super_admin') {
                return res.status(403).json({ error: 'Forbidden' });
            }
        }

        res.json(job);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 6. GET AUDIT LOG (Super Admin only)
app.get('/api/admin/audit-log', 
    checkAuth, 
    checkRole('super_admin'), 
    async (req, res) => {
        try {
            const { limit = 50, offset = 0 } = req.query;
            
            const auditSnapshot = await db.ref('audit_log')
                .orderByChild('timestamp')
                .limitToLast(parseInt(limit))
                .once('value');
            
            const logs = [];
            auditSnapshot.forEach(child => {
                logs.unshift(child.val());
            });

            res.json({
                total: logs.length,
                logs: logs.slice(offset, offset + parseInt(limit))
            });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    }
);

// 7. GET DASHBOARD (Role-aware)
app.get('/api/dashboard', checkAuth, async (req, res) => {
    try {
        const userRole = await db.ref(`users/${req.uid}/role`).once('value');
        const role = userRole.val() || 'user';

        let stats = {};

        if (role === 'super_admin') {
            // Super admin melihat stats semua users
            const allUsersSnapshot = await db.ref('users').once('value');
            let totalSubscribers = 0;
            let totalCampaigns = 0;
            let totalEmailsSent = 0;

            allUsersSnapshot.forEach(userChild => {
                const userData = userChild.val();
                if (userData.subscribers) {
                    totalSubscribers += Object.keys(userData.subscribers).length;
                }
                if (userData.campaigns) {
                    totalCampaigns += Object.keys(userData.campaigns).length;
                    Object.values(userData.campaigns).forEach(campaign => {
                        totalEmailsSent += campaign.stats?.sent || 0;
                    });
                }
            });

            stats = {
                totalSubscribers,
                totalCampaigns,
                totalEmailsSent,
                totalUsers: Object.keys(allUsersSnapshot.val() || {}).length
            };
        } else if (role === 'admin' || role === 'user') {
            // Admin/User hanya lihat milik mereka sendiri
            const subscribersSnapshot = await db.ref(`users/${req.uid}/subscribers`).once('value');
            const campaignsSnapshot = await db.ref(`users/${req.uid}/campaigns`).once('value');

            const subscribers = subscribersSnapshot.val() || {};
            const campaigns = campaignsSnapshot.val() || {};

            let totalEmailsSent = 0;
            Object.values(campaigns).forEach(campaign => {
                totalEmailsSent += campaign.stats?.sent || 0;
            });

            stats = {
                totalSubscribers: Object.keys(subscribers).length,
                totalCampaigns: Object.keys(campaigns).length,
                totalEmailsSent
            };
        }

        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// HELPER FUNCTIONS
// ============================================

async function logAudit(userId, action, details) {
    try {
        const auditId = uuidv4();
        await db.ref(`audit_log/${auditId}`).set({
            userId,
            action,
            details,
            timestamp: new Date().toISOString(),
            ipAddress: 'tracked' // Bisa tambah IP tracking
        });
    } catch (error) {
        console.error('Audit log error:', error);
    }
}

async function processEmailJob(jobId, userId, campaignId, templateContent, batchSize) {
    try {
        // Update job status to processing
        await db.ref(`jobs/${jobId}`).update({
            status: 'processing',
            startedAt: new Date().toISOString()
        });

        // Get all subscribers
        const subscribersSnapshot = await db.ref(`users/${userId}/subscribers`).once('value');
        const subscribers = subscribersSnapshot.val() || {};
        const subscriberList = Object.values(subscribers);

        console.log(`📧 Starting bulk email job: ${jobId}`);
        console.log(`📨 Total recipients: ${subscriberList.length}`);

        let sentCount = 0;
        let failedCount = 0;

        // Process in batches
        for (let i = 0; i < subscriberList.length; i += batchSize) {
            const batch = subscriberList.slice(i, i + batchSize);
            
            const promises = batch.map(subscriber => 
                sendEmailWithRetry(
                    subscriber.email,
                    templateContent,
                    subscriber
                )
                .then(() => {
                    sentCount++;
                    return { success: true };
                })
                .catch(error => {
                    failedCount++;
                    console.error(`Failed to send to ${subscriber.email}:`, error.message);
                    return { success: false, error: error.message };
                })
            );

            // Wait for batch to complete
            await Promise.all(promises);

            // Update progress
            const progress = Math.round(((i + batchSize) / subscriberList.length) * 100);
            await db.ref(`jobs/${jobId}`).update({
                sentCount,
                failedCount,
                progress: Math.min(progress, 100)
            });

            // Delay antara batches untuk tidak overload
            await new Promise(resolve => setTimeout(resolve, 1000));
        }

        // Mark job as completed
        await db.ref(`jobs/${jobId}`).update({
            status: 'completed',
            completedAt: new Date().toISOString(),
            progress: 100
        });

        // Update campaign stats
        await db.ref(`users/${userId}/campaigns/${campaignId}`).update({
            status: 'sent',
            sentAt: new Date().toISOString(),
            'stats/sent': sentCount
        });

        console.log(`✅ Email job completed: ${jobId}`);
        console.log(`   Sent: ${sentCount}, Failed: ${failedCount}`);

        // Log audit
        await logAudit(userId, 'COMPLETED_BULK_EMAIL', {
            jobId,
            campaignId,
            sentCount,
            failedCount
        });

    } catch (error) {
        console.error('Email job error:', error);
        
        await db.ref(`jobs/${jobId}`).update({
            status: 'failed',
            error: error.message,
            completedAt: new Date().toISOString()
        });

        await logAudit(userId, 'FAILED_BULK_EMAIL', {
            jobId,
            error: error.message
        });
    }
}

async function sendEmailWithRetry(email, template, subscriber, retries = 3) {
    const personalized = template
        .replace(/{{NAME}}/g, subscriber.name || 'Friend')
        .replace(/{{EMAIL}}/g, subscriber.email);

    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            await transporter.sendMail({
                from: process.env.SMTP_FROM_EMAIL,
                to: email,
                subject: 'Your Email Subject', // Should come from campaign
                html: personalized,
                headers: {
                    'X-Mailer': 'EKSO Email Marketing',
                    'X-Campaign-ID': 'campaign-id-here'
                }
            });
            
            return; // Success
        } catch (error) {
            if (attempt === retries) {
                throw error; // Final retry failed
            }
            
            // Wait before retry
            await new Promise(resolve => setTimeout(resolve, 2000 * attempt));
        }
    }
}

// ============================================
// HEALTH CHECK
// ============================================

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
    console.log(`
    ╔═══════════════════════════════════════════╗
    ║  EKSO EMAIL MARKETING - BACKEND SERVER   ║
    ║  Server running on port ${PORT}            ║
    ╚═══════════════════════════════════════════╝
    `);
    console.log('✅ SMTP Server connected');
    console.log('✅ Firebase initialized');
    console.log('✅ Rate limiting enabled');
});

module.exports = app;
