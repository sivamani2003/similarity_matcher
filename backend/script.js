const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
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
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');  // Specify the directory where files will be saved
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);  // Use the original file name
    }
});

const upload = multer({ storage: storage });
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
app.get('/admin/most-scanned-document', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: "Access denied" });
    }

    db.get("SELECT content, COUNT(*) as scan_count FROM documents GROUP BY content ORDER BY scan_count DESC LIMIT 1", (err, doc) => {
        if (err || !doc) {
            return res.status(500).json({ error: err.message });
        }

        const filePath = path.join(__dirname, doc.content);
        const fileExtension = path.extname(filePath).toLowerCase();

        if (fileExtension === '.pdf') {
            fs.readFile(filePath, (err, data) => {
                if (err) {
                    return res.status(500).json({ error: "Failed to read the PDF file" });
                }

                pdf(data).then(function (pdfData) {
                    const summary = pdfData.text.slice(0, 1000); // Extract first 1000 characters as summary
                    res.json({ mostScannedDocument: { summary, scan_count: doc.scan_count } });
                }).catch((err) => {
                    res.status(500).json({ error: "Error extracting text from PDF" });
                });
            });
        } else if (fileExtension === '.txt') {
            fs.readFile(filePath, 'utf-8', (err, data) => {
                if (err) {
                    return res.status(500).json({ error: "Failed to read the text file" });
                }
                const summary = data.slice(0, 1000); // Extract first 1000 characters as summary
                res.json({ mostScannedDocument: { summary, scan_count: doc.scan_count } });
            });
        } else {
            res.status(400).json({ error: "Unsupported file type" });
        }
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
app.get('/admin/most-scanned-document', verifyToken, (req, res) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: "Access denied" });
    }

    db.get("SELECT content, COUNT(*) as scan_count FROM documents GROUP BY content ORDER BY scan_count DESC LIMIT 1", (err, doc) => {
        if (err || !doc) {
            return res.status(500).json({ error: err.message });
        }

        const filePath = path.join(__dirname, doc.content);
        const fileExtension = path.extname(filePath).toLowerCase();

        if (fileExtension === '.pdf') {
            fs.readFile(filePath, (err, data) => {
                if (err) {
                    return res.status(500).json({ error: "Failed to read the PDF file" });
                }

                pdf(data).then(function (pdfData) {
                    const summary = pdfData.text.slice(0, 1000); // Extract first 1000 characters as summary
                    res.json({ mostScannedDocument: { summary, scan_count: doc.scan_count } });
                }).catch((err) => {
                    res.status(500).json({ error: "Error extracting text from PDF" });
                });
            });
        } else if (fileExtension === '.txt') {
            fs.readFile(filePath, 'utf-8', (err, data) => {
                if (err) {
                    return res.status(500).json({ error: "Failed to read the text file" });
                }
                const summary = data.slice(0, 1000); // Extract first 1000 characters as summary
                res.json({ mostScannedDocument: { summary, scan_count: doc.scan_count } });
            });
        } else {
            res.status(400).json({ error: "Unsupported file type" });
        }
    });
});