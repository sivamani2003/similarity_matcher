const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const port = 3001;
const { GoogleGenerativeAI } = require("@google/generative-ai");
const multer = require('multer');
const pdf = require('pdf-parse');
app.use(bodyParser.json());
const path = require('path');
const fs = require('fs');
const schedule = require('node-schedule');
const jwt = require('jsonwebtoken');
// Setup database
const dbPath = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath);
const genAI = new GoogleGenerativeAI("AIzaSyAiYHG9TYtTNzeca_3zOpQYurKLinlSwmE");
app.use(express.json());
const cors = require('cors');
require('dotenv').config();
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');  // Specify the directory where files will be saved
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);  // Use the original file name
    }
});

const upload = multer({ storage: storage });

app.use(cors({
    origin: 'http://127.0.0.1:5500', // Allow your frontend origin
    methods: ['GET', 'POST', 'OPTIONS'], // Include OPTIONS for preflight
    allowedHeaders: ['Content-Type', 'Authorization']
}));


db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, credits INTEGER, role TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY, filename TEXT, content TEXT, user_id INTEGER)");
});

// Create tables if they don't exist
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, credits INTEGER, role TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY, filename TEXT, content TEXT, user_id INTEGER)");
});

// Middleware to handle large JSON payloads
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

// Optimize database queries for large datasets
db.serialize(() => {
    db.run("CREATE INDEX IF NOT EXISTS idx_user_id ON documents (user_id)");
    db.run("CREATE INDEX IF NOT EXISTS idx_filename ON documents (filename)");
});

// Helper function for password hashing
const hashPassword = async (password) => {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
};

// Helper function for verifying password
const verifyPassword = async (storedPassword, enteredPassword) => {
  return await bcrypt.compare(enteredPassword, storedPassword);
};

// User registration
app.post('/auth/register', async (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (user) {
            return res.status(400).json({ error: "Username already exists" });
        }

        const hashedPassword = await hashPassword(password);
        const createdAt = new Date().toISOString();
        db.run("INSERT INTO users (username, password, credits, role, created_at) VALUES (?, ?, ?, ?, ?)", [username, hashedPassword, 20, 'user', createdAt], function (err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            const token = generateToken({ id: this.lastID, username, role: 'user', credits: 20 });
            res.status(201).json({ id: this.lastID, username, token });
        });
    });
});

app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) {
            return res.status(404).json({ error: "User not found" });
        }

        const isValid = await verifyPassword(user.password, password);
        if (isValid) {
            const token = generateToken(user);
            res.status(200).json({ message: "Login successful", token });
        } else {
            res.status(401).json({ error: "Invalid credentials" });
        }
    });
});
// Reset credits to 20 for all users daily at midnight
const resetCreditsJob = schedule.scheduleJob('0 0 * * *', () => {
    db.run("UPDATE users SET credits = 20", (err) => {
        if (err) {
            console.error("Error resetting credits:", err.message);
        } else {
            console.log("Credits reset to 20 for all users");
        }
    });
});

// Check if the server was off during the reset time
const lastRunFilePath = path.join(__dirname, 'lastRunTime.txt');

const checkAndResetCredits = () => {
    const now = new Date();
    const midnight = new Date();
    midnight.setHours(0, 0, 0, 0);

    fs.readFile(lastRunFilePath, 'utf8', (err, data) => {
        if (err && err.code !== 'ENOENT') {
            console.error("Error reading last run time:", err.message);
            return;
        }

        const lastRunTime = data ? new Date(data) : new Date(0);

        if (lastRunTime < midnight && now >= midnight) {
            db.run("UPDATE users SET credits = 20", (err) => {
                if (err) {
                    console.error("Error resetting credits:", err.message);
                } else {
                    console.log("Credits reset to 20 for all users");
                    fs.writeFile(lastRunFilePath, now.toISOString(), (err) => {
                        if (err) {
                            console.error("Error writing last run time:", err.message);
                        }
                    });
                }
            });
        }
    });
};

checkAndResetCredits();
// Admin registration
app.post('/auth/admin/register', async (req, res) => {
    const { username, password, secretKey } = req.body;

    if (secretKey !== '1307') {
        return res.status(403).json({ error: "Invalid secret key" });
    }

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ error: "Internal server error" });
        }
        if (user) {
            return res.status(400).json({ error: "Username already exists" });
        }

        try {
            const hashedPassword = await hashPassword(password);
            db.run("INSERT INTO users (username, password, credits, role) VALUES (?, ?, ?, ?)", [username, hashedPassword, 20, 'admin'], function (err) {
                if (err) {
                    console.error("Insert error:", err);
                    return res.status(500).json({ error: "Failed to register user" });
                }
                res.status(201).json({ success: true, id: this.lastID, username });
            });
        } catch (error) {
            console.error("Hashing error:", error);
            res.status(500).json({ error: "Password processing failed" });
        }
    });
});

const secretKey = 'your_secret_key'; // Replace with your actual secret key

// Generate JWT token
const generateToken = (user) => {
    return jwt.sign({ id: user.id, username: user.username, role: user.role }, secretKey, { expiresIn: '1h' });
};

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];

    // Check if token is present
    if (!token) {
        return res.status(403).json({ error: "No token provided" });
    }

    // Remove "Bearer " from the token if present
    const bearerToken = token.startsWith('Bearer ') ? token.slice(7, token.length) : token;

    jwt.verify(bearerToken, secretKey, (err, decoded) => {
        if (err) {
            return res.status(500).json({ error: "Failed to authenticate token" });
        }

        // Decode the role and userId
        req.userId = decoded.id;
        req.userRole = decoded.role;

        // Proceed to the next middleware or route handler
        next();
    });
};

// Admin login with JWT token generation
app.post('/auth/admin/login', async (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ? AND role = 'admin'", [username], async (err, user) => {
        if (err || !user) {
            return res.status(404).json({ error: "Admin not found" });
        }

        const isValid = await verifyPassword(user.password, password);
        if (isValid) {
            const token = generateToken(user);
            res.status(200).json({ message: "Admin login successful", token });
        } else {
            res.status(401).json({ error: "Invalid credentials" });
        }
    });
});
// Get available credits for user
app.get('/user/credits', verifyToken, (req, res) => {
    const userId = req.userId;

    db.get("SELECT credits FROM users WHERE id = ?", [userId], (err, user) => {
        if (err || !user) {
            return res.status(404).json({ error: "User not found" });
        }
        res.json({ credits: user.credits });
    });
});
app.post('/admin/reset-credits', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: "Access denied" });
    }

    const { userId } = req.body;

    db.run("UPDATE users SET credits = 20 WHERE id = ?", [userId], (err) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(200).json({ message: "User credits reset to 20" });
    });
});
// Admin login
app.post('/auth/admin/login', async (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ? AND role = 'admin'", [username], async (err, user) => {
        if (err || !user) {
            return res.status(404).json({ error: "Admin not found" });
        }

        const isValid = await verifyPassword(user.password, password);
        if (isValid) {
            res.status(200).json({ message: "Admin login successful", userId: user.id });
        } else {
            res.status(401).json({ error: "Invalid credentials" });
        }
    });
});


// Get user profile
app.get('/user/profile', (req, res) => {
  const { userId } = req.query;

  db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({ username: user.username, credits: user.credits });
  });
});

// Document upload and scan (deduct 1 credit)
app.post('/scanUpload', upload.single('file'), (req, res) => {
    const { userId } = req.body;

    if (!userId) {
        return res.status(400).json({ error: 'User ID is required' });
    }

    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const filename = req.file.filename;
    const content = req.file.path;

    // Start transaction
    db.serialize(() => {
        db.get("SELECT username, credits FROM users WHERE id = ?", [userId], (err, user) => {
            if (err) {
                console.error("Error fetching user:", err.message);
                return res.status(500).json({ error: 'Database error' });
            }

            if (!user || user.credits <= 0) {
                return res.status(400).json({ error: "Insufficient credits" });
            }

            // Insert document
            db.run("INSERT INTO documents (filename, content, user_id) VALUES (?, ?, ?)", 
            [filename, content, userId], function (err) {
                if (err) {
                    console.error("Error inserting document:", err.message);
                    return res.status(500).json({ error: 'Failed to save document' });
                }

                // Deduct 1 credit
                db.run("UPDATE users SET credits = credits - 1 WHERE id = ?", [userId], (err) => {
                    if (err) {
                        console.error("Error updating credits:", err.message);
                        return res.status(500).json({ error: 'Failed to update credits' });
                    }

                    // Log transaction
                    db.run("INSERT INTO transactions (username, credits_used) VALUES (?, ?)", 
                    [user.username, 1], (err) => {
                        if (err) {
                            console.error("Error inserting into transactions:", err.message);
                        }
                    });

                    // Notify if credits are low
                    const remainingCredits = user.credits - 1;
                    if (remainingCredits <= 20) {
                        const notificationMessage = `User ${user.username} has ${remainingCredits} credits remaining.`;
                        db.run("INSERT INTO notifications (message, user_id, type) VALUES (?, ?, ?)", 
                        [notificationMessage, userId, 'credit_warning'], (err) => {
                            if (err) {
                                console.error("Error while notifying admin:", err.message);
                            }
                        });
                    }

                    res.status(200).json({ message: "Document uploaded and scanned successfully" });
                });
            });
        });
    });
});

// Request credits reset
app.post('/user/request-credits-reset', verifyToken, (req, res) => {
    const userId = req.userId;

    db.run("INSERT INTO notifications (message, user_id, type) VALUES (?, ?, ?)", [`User ${userId} requested a credits reset.`, userId, 'credit_reset_request'], (err) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(200).json({ message: "Credits reset request sent to admin" });
    });
});

// Endpoint to show user's credit reset requests
app.get('/admin/credit-reset-requests', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: "Access denied" });
    }

    db.all("SELECT * FROM notifications WHERE type = 'credit_reset_request'", (err, requests) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ requests });
    });
});
// Endpoint for admin to approve credit reset requests
app.post('/admin/approve-credits-reset', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: "Access denied" });
    }

    const { userId } = req.body;

    db.run("UPDATE users SET credits = 20 WHERE id = ?", [userId], (err) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        db.run("DELETE FROM notifications WHERE user_id = ? AND type = 'credit_reset_request'", [userId], (err) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.status(200).json({ message: "Credits reset approved and notifications cleared" });
        });
    });
});
// Endpoint for admin to decline credit reset requests
app.post('/admin/decline-credits-reset', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: "Access denied" });
    }

    const { userId } = req.body;

    db.run("DELETE FROM notifications WHERE user_id = ? AND type = 'credit_reset_request'", [userId], (err) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(200).json({ message: "Credits reset request declined and notifications cleared" });
    });
});
// Endpoint to get the number of users added day by day
app.get('/admin/users-per-day', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: "Access denied" });
    }

    db.all(`
        SELECT DATE(created_at) as date, COUNT(*) as count 
        FROM users 
        GROUP BY DATE(created_at) 
        ORDER BY DATE(created_at) DESC
    `, (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ usersPerDay: rows });
    });
});
app.get('/matches/:docId', async (req, res) => {
    const { docId } = req.params;

    try {
        db.get("SELECT content FROM documents WHERE id = ?", [docId], async (err, doc) => {
            if (err || !doc) {
                return res.status(404).json({ error: "Document not found" });
            }

            const sourcePath = path.join(__dirname, doc.content);
            let sourceSentences = [];

            try {
                const sourceData = await fs.promises.readFile(sourcePath);
                if (sourcePath.endsWith('.txt')) {
                    sourceSentences = sourceData.toString('utf-8').match(/[^.!?]+[.!?]+/g) || [];
                } else if (sourcePath.endsWith('.pdf')) {
                    const pdfData = await pdf(sourceData);
                    sourceSentences = pdfData.text.match(/[^.!?]+[.!?]+/g) || [];
                } else {
                    return res.status(400).json({ error: "Unsupported file type" });
                }
            } catch (err) {
                console.error(`Error reading file: ${sourcePath}`, err);
                return res.status(500).json({ error: "Unable to read source file" });
            }

            db.all("SELECT * FROM documents WHERE id != ?", [docId], async (err, docs) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }

                const results = [];

                for (const otherDoc of docs) {
                    try {
                        const otherPath = path.join(__dirname, otherDoc.content);
                        let otherSentences = [];

                        try {
                            const otherData = await fs.promises.readFile(otherPath);

                            if (otherPath.endsWith('.txt')) {
                                otherSentences = otherData.toString('utf-8').match(/[^.!?]+[.!?]+/g) || [];
                            } else if (otherPath.endsWith('.pdf')) {
                                const pdfData = await pdf(otherData);
                                otherSentences = pdfData.text.match(/[^.!?]+[.!?]+/g) || [];
                            } else {
                                
                                continue;
                            }
                        } catch (err) {
                            
                            continue;
                        }

                        let matchCount = 0;
                        let totalSentences = sourceSentences.length;
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

                        const similarityPercentage = (matchCount / totalSentences) * 100;
                        results.push({
                            docId: otherDoc.id,
                            filename: otherDoc.filename,
                            similarity: similarityPercentage.toFixed(2),
                            matchedText: matchedSegments
                        });

                    } catch (err) {
                        console.error(`Error processing document ${otherDoc.id}:`, err);
                    }
                }

                results.sort((a, b) => b.similarity - a.similarity);
                res.json({ matches: results });
            });
        });
    } catch (err) {
        res.status(500).json({ error: "Error processing documents" });
    }
});

// Helper function for calculating string similarity (Levenshtein Distance)
function calculateSimilarity(str1, str2) {
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
}
  
// Paginate document results for large datasets
app.get('/user/documents', (req, res) => {
    const { userId, page = 1, limit = 100 } = req.query; // Add pagination parameters

    const offset = (page - 1) * limit;

    db.all("SELECT id, filename FROM documents WHERE user_id = ? LIMIT ? OFFSET ?", [userId, limit, offset], (err, docs) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        if (!docs || docs.length === 0) {
            return res.status(404).json({ error: "No documents found for this user" });
        }

        const documents = docs.map(doc => ({ id: doc.id, filename: doc.filename }));
        res.json({ documents, page, limit });
    });
});

app.get('/extractText/:docId', (req, res) => {
    const { docId } = req.params;

    // Query the document from the database using docId to get the file path
    db.get("SELECT content FROM documents WHERE id = ?", [docId], (err, doc) => {
        if (err || !doc) {
            return res.status(404).json({ error: "Document not found" });
        }

        const filePath = path.join(__dirname, doc.content); // Assuming 'content' stores the file path

        // Check the file extension
        const fileExtension = path.extname(filePath).toLowerCase();

        if (fileExtension === '.pdf') {
            // Read the PDF file and extract text
            fs.readFile(filePath, (err, data) => {
                if (err) {
                    return res.status(500).json({ error: "Failed to read the PDF file" });
                }

                pdf(data).then(function (pdfData) {
                    // pdfData.text contains the extracted text
                    res.json({ extractedText: pdfData.text });
                }).catch(() => {
                    res.status(500).json({ error: "Error extracting text from PDF" });
                });
            });
        } else if (fileExtension === '.txt') {
            // Read the text file and return its content
            fs.readFile(filePath, 'utf-8', (err, data) => {
                if (err) {
                    return res.status(500).json({ error: "Failed to read the text file" });
                }
                res.json({ extractedText: data });
            });
        } else {
            res.status(400).json({ error: "Unsupported file type" });
        }
    });
});
// Track total number of requests and requests per user

// Endpoint to get request statistics
app.get('/admin/request-stats', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: "Access denied" });
    }

    db.all("SELECT COUNT(*) as totalRequests FROM notifications WHERE type = 'credit_reset_request'", (err, totalRow) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        const totalRequests = totalRow[0]?.totalRequests || 0;

        db.all("SELECT user_id, COUNT(*) as request_count FROM notifications WHERE type = 'credit_reset_request' GROUP BY user_id", (err, rows) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            const requestStats = rows.reduce((acc, row) => {
                acc[row.user_id] = row.request_count;
                return acc;
            }, {});

            db.get("SELECT COUNT(*) as totalUsers FROM users", (err, userRow) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }

                const totalUsers = userRow?.totalUsers || 0;
                res.json({ totalRequests, userRequests: requestStats, totalUsers });
            });
        });
    });
});
const extractKeyPoints = async (text) => {
    try {
        const model = genAI.getGenerativeModel({ model: "gemini-pro" });

        const result = await model.generateContent({
            contents: [{ role: "user", parts: [{ text: `Get the  topics in ${text} show result in 2 sentences` }] }]
        });

        const response = result.response;
        return response.candidates[0].content.parts[0].text.trim();
    } catch (error) {
        console.error("Error with Gemini API:", error.message);
        return "Failed to extract key points.";
    }
};

// Endpoint to get the most scanned document with summary
app.get('/admin/most-scanned-document', verifyToken, async (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: "Access denied" });
    }

    db.get("SELECT content, COUNT(*) as scan_count FROM documents GROUP BY content ORDER BY scan_count DESC LIMIT 1", async (err, doc) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!doc) {
            return res.status(404).json({ error: "Document not found" });
        }

        const filePath = path.join(__dirname, doc.content);
        const fileExtension = path.extname(filePath).toLowerCase();

        if (fileExtension === '.pdf') {
            fs.readFile(filePath, async (err, data) => {
                if (err) return res.status(500).json({ error: "Failed to read the PDF file" });

                pdf(data).then(async (pdfData) => {
                    const keyPoints = await extractKeyPoints(pdfData.text);
                    res.json({ mostScannedDocument: { keyPoints, scan_count: doc.scan_count } });
                }).catch(() => res.status(500).json({ error: "Error extracting text from PDF" }));
            });
        } else if (fileExtension === '.txt') {
            fs.readFile(filePath, 'utf-8', async (err, data) => {
                if (err) return res.status(500).json({ error: "Failed to read the text file" });

                const keyPoints = await extractKeyPoints(data);
                res.json({ mostScannedDocument: { keyPoints, scan_count: doc.scan_count } });
            });
        } else {
            res.status(400).json({ error: "Unsupported file type" });
        }
    });
});

// app.get('/admin/most-scanned-document', verifyToken, (req, res) => {
//     if (req.userRole !== 'admin') {
//         return res.status(403).json({ error: "Access denied" });
//     }

//     db.get("SELECT content, COUNT(*) as scan_count FROM documents GROUP BY content ORDER BY scan_count DESC LIMIT 1", (err, doc) => {
//         if (err || !doc) {
//             return res.status(500).json({ error: err.message });
//         }

//         const filePath = path.join(__dirname, doc.content);
//         const fileExtension = path.extname(filePath).toLowerCase();

//         if (fileExtension === '.pdf') {
//             fs.readFile(filePath, (err, data) => {
//                 if (err) {
//                     return res.status(500).json({ error: "Failed to read the PDF file" });
//                 }

//                 pdf(data).then(function (pdfData) {
//                     const summary = pdfData.text.slice(0, 1000); // Extract first 1000 characters as summary
//                     res.json({ mostScannedDocument: { summary, scan_count: doc.scan_count } });
//                 }).catch((err) => {
//                     res.status(500).json({ error: "Error extracting text from PDF" });
//                 });
//             });
//         } else if (fileExtension === '.txt') {
//             fs.readFile(filePath, 'utf-8', (err, data) => {
//                 if (err) {
//                     return res.status(500).json({ error: "Failed to read the text file" });
//                 }
//                 const summary = data.slice(0, 1000); // Extract first 1000 characters as summary
//                 res.json({ mostScannedDocument: { summary, scan_count: doc.scan_count } });
//             });
//         } else {
//             res.status(400).json({ error: "Unsupported file type" });
//         }
//     });
// });

// Endpoint to get the user with the highest credits
app.get('/admin/highest-credits-used-users', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: "Access denied" });
    }

    db.all(`
        SELECT username, SUM(credits_used) AS total_credits_used 
        FROM transactions 
        GROUP BY username 
        ORDER BY total_credits_used DESC 
        LIMIT 3
    `, (err, users) => {
        if (err || !users) {
            return res.status(500).json({ error: err ? err.message : "No data found" });
        }
        res.json({ users });
    });
});

// Admin endpoint to get all users and manually change credits
app.post('/admin/users', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: "Access denied" });
    }

    db.all("SELECT id, username, credits FROM users WHERE role != 'admin'", (err, users) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ users });
    });
});

app.post('/admin/change-credits', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: "Access denied" });
    }

    const { userId, newCredits } = req.body;

    db.run("UPDATE users SET credits = ? WHERE id = ?", [newCredits, userId], (err) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(200).json({ message: "User credits updated successfully" });
    });
});
// Admin endpoint to get all documents
app.post('/admin/documents', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: "Access denied" });
    }

    db.all("SELECT id, filename, user_id FROM documents", (err, docs) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ documents: docs });
    });
});
// Endpoint to view a file in the database
app.get('/view-file/:docId', verifyToken, (req, res) => {
    const { docId } = req.params;

    db.get("SELECT * FROM documents WHERE id = ?", [docId], (err, doc) => {
        if (err || !doc) {
            return res.status(404).json({ error: "Document not found" });
        }

        // Check if the requester is an admin or the owner of the document
        if (req.userRole !== 'admin' && req.userId !== doc.user_id) {
            return res.status(403).json({ error: "Access denied" });
        }

        const filePath = path.join(__dirname, doc.content);
        const fileExtension = path.extname(filePath).toLowerCase();

        if (fileExtension === '.pdf') {
            fs.readFile(filePath, (err, data) => {
                if (err) {
                    return res.status(500).json({ error: "Failed to read the PDF file" });
                }

                pdf(data).then(function (pdfData) {
                    res.json({ preview: pdfData.text.slice(0, 1000) }); // Return first 1000 characters as preview
                }).catch((err) => {
                    res.status(500).json({ error: "Error extracting text from PDF" });
                });
            });
        } else if (fileExtension === '.txt') {
            fs.readFile(filePath, 'utf-8', (err, data) => {
                if (err) {
                    return res.status(500).json({ error: "Failed to read the text file" });
                }
                res.json({ preview: data.slice(0, 1000) }); // Return first 1000 characters as preview
            });
        } else {
            res.status(400).json({ error: "Unsupported file type" });
        }
    });
});
// Endpoint to download a document
app.get('/download/:docId', verifyToken, (req, res) => {
    const { docId } = req.params;

    db.get("SELECT * FROM documents WHERE id = ?", [docId], (err, doc) => {
        if (err || !doc) {
            return res.status(404).json({ error: "Document not found" });
        }

        // Check if the requester is an admin or the owner of the document
        if (req.userRole !== 'admin' && req.userId !== doc.user_id) {
            return res.status(403).json({ error: "Access denied" });
        }

        const filePath = path.join(__dirname, doc.content);
        res.download(filePath, doc.filename, (err) => {
            if (err) {
                return res.status(500).json({ error: "Failed to download the file" });
            }
        });
    });
});
// Delete user
app.post('/admin/delete-user', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: "Access denied" });
    }

    const { userId } = req.body;

    db.run("DELETE FROM users WHERE id = ?", [userId], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(200).json({ message: "User deleted successfully" });
    });
});
// Endpoint to delete a document
app.post('/admin/delete-document', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: "Access denied" });
    }

    const { docId } = req.body;

    db.run("DELETE FROM documents WHERE id = ?", [docId], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(200).json({ message: "Document deleted successfully" });
    });
});

// Endpoint to change credits of a user
app.post('/user/change-credits', verifyToken, (req, res) => {
    const { userId, newCredits } = req.body;

    // Check if the requester is an admin or the user themselves
    if (req.userRole !== 'admin' && req.userId !== userId) {
        return res.status(403).json({ error: "Access denied" });
    }

    db.run("UPDATE users SET credits = ? WHERE id = ?", [newCredits, userId], (err) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(200).json({ message: "User credits updated successfully" });
    });
});
// Start server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
