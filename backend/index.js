const express = require('express');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');
const database = new DatabaseSync(':memory:');
const app = express();
const port = 3001;

const path = require('path');
const fs = require('fs');
const cors = require('cors');
require('dotenv').config();

app.use(express.json());

app.use(cors({
    origin: 'http://127.0.0.1:5500',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Database setup
database.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        credits INTEGER,
        role TEXT,
        created_at TEXT
    )
`);

database.exec(`
    CREATE TABLE IF NOT EXISTS tokens (
        id INTEGER PRIMARY KEY,
        token TEXT UNIQUE,
        user_id INTEGER,
        role TEXT,
        created_at TEXT,
        expires_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
`);

database.exec(`
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY,
        filename TEXT,
        content TEXT,
        user_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    , updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);

database.exec(`
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY,
        username TEXT,
        credits_used INTEGER
    )
`);
database.exec(`
    CREATE TABLE IF NOT EXISTS credits_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        credits_used INTEGER,
        timestamp TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
`);
database.exec(`
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY,
        message TEXT,
        user_id INTEGER,
        type TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);

database.exec("CREATE INDEX IF NOT EXISTS idx_user_id ON documents (user_id)");
database.exec("CREATE INDEX IF NOT EXISTS idx_filename ON documents (filename)");
database.exec("CREATE INDEX IF NOT EXISTS idx_token ON tokens (token)");


const hashPassword = async (password) => {
    return new Promise((resolve, reject) => {
        const salt = crypto.randomBytes(16).toString('hex');
        crypto.pbkdf2(password, salt, 10000, 64, 'sha256', (err, derivedKey) => {
            if (err) reject(err);
            const hash = `${salt}:${derivedKey.toString('hex')}`;
            resolve(hash);
        });
    });
};

const verifyPassword = async (storedPassword, enteredPassword) => {
    return new Promise((resolve, reject) => {
        const [salt, originalHash] = storedPassword.split(':');
        crypto.pbkdf2(enteredPassword, salt, 10000, 64, 'sha256', (err, derivedKey) => {
            if (err) reject(err);
            const newHash = derivedKey.toString('hex');
            resolve(newHash === originalHash);
        });
    });
};

const generateToken = (user) => {
    const payload = JSON.stringify({ id: user.id, username: user.username, role: user.role });
    const timestamp = Date.now();
    const expiresAt = new Date(timestamp + 3600000).toISOString(); // 1 hour expiration
    const dataToSign = `${payload}.${timestamp}`;
    const signature = crypto
        .createHmac('sha256', process.env.TOKEN_SECRET || 'your_secret_key')
        .update(dataToSign)
        .digest('hex');
    const token = `${Buffer.from(payload).toString('base64')}.${timestamp}.${signature}`;

    
    const stmt = database.prepare(
        "INSERT INTO tokens (token, user_id, role, created_at, expires_at) VALUES (?, ?, ?, ?, ?)"
    );
    stmt.run(token, user.id, user.role, new Date(timestamp).toISOString(), expiresAt);

    return token;
};

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.startsWith('Bearer ')
        ? req.headers['authorization'].slice(7)
        : req.headers['authorization'];

    if (!token) return res.status(403).json({ error: "No token provided" });

    try {
        const stmt = database.prepare("SELECT * FROM tokens WHERE token = ?");
        const tokenData = stmt.all(token)[0];

        if (!tokenData) return res.status(403).json({ error: "Invalid or revoked token" });

        const [encodedPayload, timestamp, signature] = token.split('.');
        const payload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString('utf8'));
        const dataToSign = `${JSON.stringify(payload)}.${timestamp}`;
        const expectedSignature = crypto
            .createHmac('sha256', process.env.TOKEN_SECRET || 'your_secret_key')
            .update(dataToSign)
            .digest('hex');

        const isValid = signature === expectedSignature;
        const isExpired = new Date() > new Date(tokenData.expires_at);

        if (!isValid || isExpired) {

            database.prepare("DELETE FROM tokens WHERE token = ?").run(token);
            return res.status(401).json({ error: "Token invalid or expired" });
        }

        req.userId = payload.id;
        req.userRole = tokenData.role;
        next();
    } catch (err) {
        return res.status(500).json({ error: "Invalid token format" });
    }
};

const requireRole = (role) => {
    return (req, res, next) => {
        if (req.userRole !== role) {
            return res.status(403).json({ error: `Access denied. Requires ${role} role.` });
        }
        next();
    };
};

const calculateSimilarity = (str1, str2) => {
    if (str1 === str2) return 1.0;
    const len1 = str1.length;
    const len2 = str2.length;
    const matrix = Array(len1 + 1).fill().map(() => Array(len2 + 1).fill(0));

    for (let i = 0; i <= len1; i++) matrix[i][0] = i;
    for (let j = 0; j <= len2; j++) matrix[0][j] = j;

    for (let i = 1; i <= len1; i++) {
        for (let j = 1; j <= len2; j++) {
            const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
            matrix[i][j] = Math.min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost
            );
        }
    }
    return 1 - (matrix[len1][len2] / Math.max(len1, len2));
};

// Authentication Routes
app.post('/auth/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const stmt = database.prepare("SELECT * FROM users WHERE username = ?");
        const existingUser = stmt.all(username);

        if (existingUser.length > 0) return res.status(400).json({ error: "Username already exists" });

        const hashedPassword = await hashPassword(password);
        const createdAt = new Date().toISOString();

        const insertStmt = database.prepare(
            "INSERT INTO users (username, password, credits, role, created_at) VALUES (?, ?, ?, ?, ?)"
        );
        const result = insertStmt.run(username, hashedPassword, 20, 'user', createdAt);

        const token = generateToken({ id: result.lastInsertRowid, username, role: 'user' });
        res.status(201).json({ id: result.lastInsertRowid, username, token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const stmt = database.prepare("SELECT * FROM users WHERE username = ?");
        const user = stmt.all(username);

        if (!user.length) return res.status(404).json({ error: "User not found" });

        const isValid = await verifyPassword(user[0].password, password);
        if (isValid) {
            const token = generateToken(user[0]);
            res.status(200).json({ message: "Login successful", token });
        } else {
            res.status(401).json({ error: "Invalid credentials" });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/auth/admin/register', async (req, res) => {
    const { username, password, secretKey } = req.body;
    if (secretKey !== process.env.ADMIN_SECRET_KEY) {
        return res.status(403).json({ error: "Invalid secret key" });
    }

    try {
        const stmt = database.prepare("SELECT * FROM users WHERE username = ?");
        const user = stmt.all(username);
        if (user.length > 0) return res.status(400).json({ error: "Username already exists" });

        const hashedPassword = await hashPassword(password);
        const insertStmt = database.prepare(
            "INSERT INTO users (username, password, credits, role, created_at) VALUES (?, ?, ?, ?, ?)"
        );
        const result = insertStmt.run(username, hashedPassword, 20, 'admin', new Date().toISOString());
        const token = generateToken({ id: result.lastInsertRowid, username, role: 'admin' });
        res.status(201).json({ success: true, username, token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/auth/admin/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const stmt = database.prepare("SELECT * FROM users WHERE username = ? AND role = 'admin'");
        const user = stmt.all(username);

        if (!user.length) return res.status(404).json({ error: "Admin not found" });

        const isValid = await verifyPassword(user[0].password, password);
        if (isValid) {
            const token = generateToken(user[0]);
            res.status(200).json({ message: "Admin login successful", token });
        } else {
            res.status(401).json({ error: "Invalid credentials" });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/auth/logout', verifyToken, (req, res) => {
    const token = req.headers['authorization'].slice(7);
    try {
        database.prepare("DELETE FROM tokens WHERE token = ?").run(token);
        res.status(200).json({ message: "Logged out successfully" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// User Routes
app.get('/user/credits', verifyToken, async (req, res) => {
    try {
        const stmt = database.prepare("SELECT credits FROM users WHERE id = ?");
        const user = stmt.all(req.userId);
        if (!user.length) return res.status(404).json({ error: "User not found" });
        res.json({ credits: user[0].credits });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/user/profile', verifyToken, async (req, res) => {
    try {
        const stmt = database.prepare("SELECT * FROM users WHERE id = ?");
        const user = stmt.all(req.userId);
        if (!user.length) return res.status(404).json({ error: "User not found" });
        res.json({ username: user[0].username, credits: user[0].credits, role: user[0].role });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/scanUpload', verifyToken, async (req, res) => {
    const userId = req.userId; 
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
    }
    
    if (!req.headers['content-type'] || !req.headers['content-type'].includes('multipart/form-data')) {
        return res.status(400).json({ error: 'Content-type must be multipart/form-data' });
    }
    
    try {

        const chunks = [];
        let filename = '';
        let fileContent = Buffer.from([]);
        let boundary = req.headers['content-type'].split('boundary=')[1];
        
        req.on('data', (chunk) => {
            chunks.push(chunk);
        });
        req.on('end', async () => {
            const buffer = Buffer.concat(chunks);
            let content = buffer.toString();
            
            const filePartRegex = new RegExp(`--${boundary}[\\s\\S]+?name="file"[\\s\\S]+?filename="([^"]+)"[\\s\\S]+?\\r\\n\\r\\n([\\s\\S]+?)\\r\\n--${boundary}`, 'i');
            const match = content.match(filePartRegex);
            
            if (!match) {
                return res.status(400).json({ error: 'No file uploaded' });
            }
            
            filename = match[1];
            
            const fileStartIndex = content.indexOf('\r\n\r\n', content.indexOf(`filename="${filename}"`)) + 4;
            const fileEndIndex = content.indexOf(`\r\n--${boundary}`, fileStartIndex);
            fileContent = Buffer.from(buffer.subarray(fileStartIndex, fileEndIndex));
            const fileExtension = path.extname(filename).toLowerCase();
            
            if (fileExtension !== '.txt') {
                return res.status(400).json({ error: "Only .txt files are supported" });
            }
            
            const uniqueFileName = `${crypto.randomBytes(8).toString('hex')}_${filename}`;
            const filePath = path.join(uploadDir, uniqueFileName);
            
            fs.writeFileSync(filePath, fileContent);
            
            try {
                const userStmt = database.prepare("SELECT username, credits FROM users WHERE id = ?");
                const user = userStmt.all(userId);
                if (!user.length || user[0].credits <= 0) {
                    fs.unlinkSync(filePath);
                    return res.status(400).json({ error: "Insufficient credits" });
                }
                
                const docStmt = database.prepare("INSERT INTO documents (filename, content, user_id) VALUES (?, ?, ?)");
                docStmt.run(filename, filePath, userId);
                
                const updateStmt = database.prepare("UPDATE users SET credits = credits - 1 WHERE id = ?");
                updateStmt.run(userId);
                
                const transStmt = database.prepare("INSERT INTO transactions (username, credits_used) VALUES (?, ?)");
                transStmt.run(user[0].username, 1);
                
                const logStmt = database.prepare(
                    "INSERT INTO credits_log (user_id, credits_used, timestamp) VALUES (?, ?, ?)"
                );
                logStmt.run(userId, 1, new Date().toISOString());
                
                const remainingCredits = user[0].credits - 1;
                if (remainingCredits <= 5) {
                    const notifStmt = database.prepare(
                        "INSERT INTO notifications (message, user_id, type) VALUES (?, ?, ?)"
                    );
                    notifStmt.run(`User ${user[0].username} has ${remainingCredits} credits remaining.`, userId, 'credit_warning');
                }
                
                res.status(200).json({ message: "Document uploaded and scanned successfully" });
            } catch (err) {
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                }
                res.status(500).json({ error: err.message });
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Error processing upload: ' + err.message });
    }
});

app.post('/user/request-credits-reset', verifyToken, async (req, res) => {
    try {
        const currentDateTime = new Date().toISOString();
        const stmt = database.prepare(
            "INSERT INTO notifications (message, user_id, type, created_at) VALUES (?, ?, ?, ?)"
        );
        stmt.run(
            `User ${req.userId} requested a credits reset.`, 
            req.userId, 
            'credit_reset_request',
            currentDateTime
        );
        res.status(200).json({ message: "Credits reset request sent to admin" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/user/documents', verifyToken, async (req, res) => {
    const { page = 1, limit = 100 } = req.query;
    const offset = (page - 1) * limit;

    try {
        const stmt = database.prepare(
            "SELECT id, filename FROM documents WHERE user_id = ? LIMIT ? OFFSET ?"
        );
        const docs = stmt.all(req.userId, Number(limit), Number(offset));
        if (!docs.length) return res.status(404).json({ error: "No documents found for this user" });

        res.json({ documents: docs, page, limit });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/extractText/:docId', verifyToken, async (req, res) => {
    const { docId } = req.params;
    try {
        const stmt = database.prepare("SELECT content, user_id FROM documents WHERE id = ?");
        const doc = stmt.all(docId);
        if (!doc.length) return res.status(404).json({ error: "Document not found" });
        if (req.userRole !== 'admin' && req.userId !== doc[0].user_id) {
            return res.status(403).json({ error: "Access denied" });
        }

        const filePath = path.join(__dirname, doc[0].content);
        const data = await fs.promises.readFile(filePath, 'utf-8');
        res.json({ extractedText: data });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Admin Routes


app.get('/admin/credit-reset-requests', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const stmt = database.prepare("SELECT * FROM notifications WHERE type = 'credit_reset_request'");
        const requests = stmt.all();
        res.json({ requests });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/admin/approve-credits-reset', verifyToken, requireRole('admin'), async (req, res) => {
    const { userId } = req.body;
    try {
        database.prepare("UPDATE users SET credits = 20 WHERE id = ?").run(userId);
        
        database.prepare(
            "INSERT INTO credits_log (user_id, credits_used, timestamp) VALUES (?, ?, ?)"
        ).run(userId, 20, new Date().toISOString());
        
        database.prepare(
            "DELETE FROM notifications WHERE user_id = ? AND type = 'credit_reset_request'"
        ).run(userId);
        
        res.status(200).json({ message: "Credits reset approved and notifications cleared" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/admin/decline-credits-reset', verifyToken, requireRole('admin'), async (req, res) => {
    const { userId } = req.body;
    try {
        database.prepare("DELETE FROM notifications WHERE user_id = ? AND type = 'credit_reset_request'").run(userId);
        res.status(200).json({ message: "Credits reset request declined and notifications cleared" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/admin/users-per-day', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const stmt = database.prepare(`
            SELECT DATE(created_at) as date, COUNT(*) as count 
            FROM users 
            GROUP BY DATE(created_at) 
            ORDER BY DATE(created_at) DESC
        `);
        const rows = stmt.all();
        res.json({ usersPerDay: rows });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/matches/:docId', verifyToken, async (req, res) => {
    const { docId } = req.params;
    try {
        const docStmt = database.prepare("SELECT content, user_id FROM documents WHERE id = ?");
        const doc = docStmt.all(docId);
        if (!doc.length) return res.status(404).json({ error: "Document not found" });
        if (req.userRole !== 'admin' && req.userId !== doc[0].user_id) {
            return res.status(403).json({ error: "Access denied" });
        }

        const sourcePath = path.join(__dirname, doc[0].content);
        const sourceData = await fs.promises.readFile(sourcePath, 'utf-8');
        const sourceSentences = sourceData.match(/[^.!?]+[.!?]+/g) || [];

        const docsStmt = database.prepare("SELECT * FROM documents WHERE id != ?");
        const docs = docsStmt.all(docId);
        const results = [];

        for (const otherDoc of docs) {
            const otherPath = path.join(__dirname, otherDoc.content);
            try {
                const otherData = await fs.promises.readFile(otherPath, 'utf-8');
                const otherSentences = otherData.match(/[^.!?]+[.!?]+/g) || [];

                let matchCount = 0;
                let matchedSegments = [];
                for (const sourceSentence of sourceSentences) {
                    const normalizedSource = sourceSentence.trim().toLowerCase();
                    for (const otherSentence of otherSentences) {
                        const normalizedOther = otherSentence.trim().toLowerCase();
                        const similarity = calculateSimilarity(normalizedSource, normalizedOther);
                        if (similarity > 0.8) {
                            matchCount++;
                            matchedSegments.push({
                                source: sourceSentence.trim(),
                                match: otherSentence.trim(),
                                similarity: (similarity * 100).toFixed(2)
                            });
                            break;
                        }
                    }
                }

                const similarityPercentage = (matchCount / sourceSentences.length) * 100;
                if (!isNaN(similarityPercentage)) {
                    results.push({
                        docId: otherDoc.id,
                        filename: otherDoc.filename,
                        similarity: similarityPercentage.toFixed(2),
                        matchedText: matchedSegments
                    });
                }
            } catch (err) {
                continue;
            }
        }

        results.sort((a, b) => b.similarity - a.similarity);
        res.json(results.length === 0 ? { message: "No similarity with other documents" } : { matches: results });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/admin/request-stats', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const totalUsersStmt = database.prepare("SELECT COUNT(*) as totalUsers FROM users");
        const totalUsers = totalUsersStmt.all()[0].totalUsers || 0;

        const activeUsersStmt = database.prepare("SELECT COUNT(DISTINCT user_id) as activeUsers FROM documents");
        const activeUsers = activeUsersStmt.all()[0].activeUsers || 0;

        res.json({ totalUsers, activeUsers });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/admin/most-scanned-document', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const stmt = database.prepare(
            "SELECT content, COUNT(*) as scan_count FROM documents GROUP BY content ORDER BY scan_count DESC LIMIT 1"
        );
        const doc = stmt.all();
        if (!doc.length) return res.status(404).json({ error: "Document not found" });

        const filePath = path.join(__dirname, doc[0].content);
        const data = await fs.promises.readFile(filePath, 'utf-8');
        
        // Split the text into sentences and take the first two
        const sentences = data.match(/[^.!?]+[.!?]+/g) || [];
        const firstTwoSentences = sentences.slice(0, 2).join(' ').trim();

        res.json({ 
            mostScannedDocument: { 
                keyPoints: { summary: firstTwoSentences || "Text is too short or malformed." },
                scan_count: doc[0].scan_count 
            } 
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/admin/highest-credits-used-users', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const stmt = database.prepare(`
            SELECT username, SUM(credits_used) AS total_credits_used 
            FROM transactions 
            GROUP BY username 
            ORDER BY total_credits_used DESC 
            LIMIT 3
        `);
        const users = stmt.all();
        res.json({ users });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/admin/users', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const stmt = database.prepare("SELECT id, username, credits, created_at FROM users WHERE role != 'admin'");
        const users = stmt.all();
        res.json({ users });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.post('/user/change-credits', verifyToken, requireRole('admin'), async (req, res) => {
    const { userId, credits } = req.body;

    if (!userId || typeof credits !== 'number') {
        return res.status(400).json({ error: "Invalid user ID or credits value" });
    }

    try {
        const userStmt = database.prepare("SELECT * FROM users WHERE id = ?");
        const user = userStmt.all(userId);

        if (!user.length) {
            return res.status(404).json({ error: "User not found" });
        }

        const updateStmt = database.prepare("UPDATE users SET credits = ? WHERE id = ?");
        updateStmt.run(credits, userId);

        res.status(200).json({ message: "Credits updated successfully", newCredits: credits });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.delete('/admin/delete-user/:userId', verifyToken, requireRole('admin'), async (req, res) => {
    const { userId } = req.params;

    try {
        const userStmt = database.prepare("SELECT * FROM users WHERE id = ?");
        const user = userStmt.all(userId);

        if (!user.length) {
            return res.status(404).json({ error: "User not found" });
        }

        if (user[0].role === 'admin') {
            return res.status(403).json({ error: "Cannot delete admin users" });
        }

        const deleteUserStmt = database.prepare("DELETE FROM users WHERE id = ?");
        deleteUserStmt.run(userId);

        const cleanupStmts = [
            "DELETE FROM tokens WHERE user_id = ?",
            "DELETE FROM documents WHERE user_id = ?",
            "DELETE FROM notifications WHERE user_id = ?"
        ];

        cleanupStmts.forEach(stmt => {
            database.prepare(stmt).run(userId);
        });

        res.status(200).json({ message: "User and associated data deleted successfully" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.get('/admin/analytics', verifyToken, requireRole('admin'), async (req, res) => {
    try {

        const creditStmt = database.prepare(`
            SELECT 
                SUM(CASE WHEN credits_used != 20 THEN credits_used ELSE 0 END) as total_credits,
                COUNT(*) as total_transactions,
                COUNT(DISTINCT user_id) as total_users
            FROM credits_log
        `);
        const creditStats = creditStmt.all()[0];

        const approvalStmt = database.prepare(`
            SELECT COUNT(*) as approved_requests 
            FROM credits_log 
            WHERE credits_used = 20
        `);
        const approvalStats = approvalStmt.all()[0];

         const peakHourStmt = database.prepare(`
            SELECT 
                strftime('%H', created_at) as hour,
                COUNT(*) as upload_count
            FROM documents 
            GROUP BY hour
            ORDER BY upload_count DESC
            LIMIT 1
        `);
        
        let peakHourData;
        try {
            peakHourData = peakHourStmt.get();
        } catch (err) {
            console.error("Error retrieving peak hour data:", err);
            peakHourData = null;
        }
        let peakUploadHour = "N/A";
        let uploadsInPeakHour = 0;
        
        if (peakHourData) {
            peakUploadHour = peakHourData.hour;
            uploadsInPeakHour = peakHourData.upload_count;
        }
        
        let averageCreditsPerUser = 0;
        if (typeof creditStats !== 'undefined' && creditStats.total_users > 0) {
            averageCreditsPerUser = Math.round((creditStats.total_credits / creditStats.total_users) * 100) / 100;
        }
        
        res.json({
            totalCreditsUsed: creditStats.total_credits || 0,
            totalTransactions: creditStats.total_transactions || 0,
            uniqueUsers: creditStats.total_users || 0,
            approvedRequests: approvalStats.approved_requests || 0,
            averageCreditsPerUser: averageCreditsPerUser,
            peakUploadHour: peakHourData ? peakHourData.hour : null,
            uploadsInPeakHour: peakHourData ? peakHourData.upload_count : 0
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.get('/admin/documents', verifyToken, requireRole('admin'), async (req, res) => {
    try {
        const stmt = database.prepare(`
            SELECT d.*, u.username 
            FROM documents d
            LEFT JOIN users u ON d.user_id = u.id
            ORDER BY d.id DESC
        `);
        const documents = stmt.all();
        
        const formattedDocs = documents.map(doc => ({
            id: doc.id,
            filename: doc.filename,
            username: doc.username,
            content: doc.content,
            user_id: doc.user_id
        }));

        res.json({ documents: formattedDocs });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.get('/view-file/:docId', verifyToken,requireRole('admin'), async (req, res) => {
    const { docId } = req.params;
    try {
        const stmt = database.prepare("SELECT content, user_id FROM documents WHERE id = ?");
        const doc = stmt.all(docId);

        if (!doc.length) {
            return res.status(404).json({ error: "Document not found" });
        }

        if (req.userRole !== 'admin' && req.userId !== doc[0].user_id) {
            return res.status(403).json({ error: "Access denied" });
        }

        const filePath = path.join(__dirname, doc[0].content);
        res.sendFile(filePath);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
// Delete file endpoint
app.delete('/delete-file/:docId', verifyToken,requireRole('admin'), async (req, res) => {
    const { docId } = req.params;
    try {
        const stmt = database.prepare("SELECT content, user_id FROM documents WHERE id = ?");
        const doc = stmt.all(docId);

        if (!doc.length) {
            return res.status(404).json({ error: "Document not found" });
        }

        if (req.userRole !== 'admin' && req.userId !== doc[0].user_id) {
            return res.status(403).json({ error: "Access denied" });
        }
        const deleteStmt = database.prepare("DELETE FROM documents WHERE id = ?");
        const result = deleteStmt.run(docId);

        if (result.changes === 0) {
            return res.status(500).json({ error: "Failed to delete document record" });
        }

        const filePath = path.join(__dirname, doc[0].content);
        
        if (fs.existsSync(filePath)) {
            await fs.promises.unlink(filePath);
        }

        res.json({ message: "File deleted successfully" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/download-file/:docId', verifyToken,requireRole('admin'), async (req, res) => {
    const { docId } = req.params;
    try {
        const stmt = database.prepare("SELECT content, user_id, filename FROM documents WHERE id = ?");
        const doc = stmt.all(docId);

        if (!doc.length) {
            return res.status(404).json({ error: "Document not found" });
        }

        if (req.userRole !== 'admin' && req.userId !== doc[0].user_id) {
            return res.status(403).json({ error: "Access denied" });
        }

        const filePath = path.join(__dirname, doc[0].content);
        res.download(filePath, doc[0].filename);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
// Sample backend endpoint (add to your server.js or routes file)
app.get('/search-documents', verifyToken,  async (req, res) => {
    try {
        const { filename } = req.query;
        if (!filename) {
            return res.json({ documents: [] });
        }

        const stmt = database.prepare(`
            SELECT d.*, u.username 
            FROM documents d
            LEFT JOIN users u ON d.user_id = u.id
            WHERE d.filename LIKE ?
            ORDER BY d.id DESC
        `);
        const documents = stmt.all(`%${filename}%`);
        
        const formattedDocs = documents.map(doc => ({
            id: doc.id,
            filename: doc.filename,
            username: doc.username,
            content: doc.content,
            user_id: doc.user_id
        }));

        res.json({ documents: formattedDocs });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
// Credit Reset Schedule
setInterval(() => {
    const now = new Date();
    if (now.getHours() === 0 && now.getMinutes() === 0) {
        try {
            database.exec("UPDATE users SET credits = 20");
            console.log("Credits reset to 20 for all users at midnight");
        } catch (err) {
            console.error("Error resetting credits:", err.message);
        }
    }
}, 60000); // Check every minute



// Start server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});