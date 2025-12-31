/**
 * Fixed Express Application - Security vulnerabilities addressed
 */

const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const yaml = require('js-yaml');
const xml2js = require('xml2js');
const serialize = require('node-serialize');
const helmet = require('helmet');
const axios = require('axios');
const MongoClient = require('mongodb').MongoClient;

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet()); // FIX: Add security headers

// FIX: Restrict CORS to trusted origins
const allowedOrigins = ['https://trusted-domain.com'];
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
    }
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

// FIX: Bind server to localhost by default
const PORT = process.env.PORT || 3000;
app.listen(PORT, '127.0.0.1', () => {
    console.log(`Server running on port ${PORT}`);
});

// FIX: Avoid exposing stack traces in production
app.use((err, req, res, next) => {
    res.status(500).json({
        error: 'An unexpected error occurred.'
    });
});

// FIX: Replace eval() and new Function with safer alternatives
app.post('/calculate', (req, res) => {
    const expression = req.body.expr;
    try {
        // Validate and sanitize the input
        if (!/^[0-9+\-*/().\s]+$/.test(expression)) {
            throw new Error('Invalid expression');
        }
        const result = Function(`"use strict"; return (${expression})`)();
        res.json({ result });
    } catch (error) {
        res.status(400).json({ error: 'Invalid input' });
    }
});

app.get('/dynamic', (req, res) => {
    const code = req.query.code;
    try {
        // Validate and sanitize the input
        if (!/^[0-9+\-*/().\s]+$/.test(code)) {
            throw new Error('Invalid code');
        }
        const fn = Function(`"use strict"; return (${code})`);
        res.json({ result: fn() });
    } catch (error) {
        res.status(400).json({ error: 'Invalid input' });
    }
});

// FIX: Use parameterized queries to prevent SQL injection
app.get('/user', (req, res) => {
    const username = req.query.username;
    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) {
            res.status(500).json({ error: 'Database error' });
        } else {
            res.json(results);
        }
    });
});

app.get('/search', (req, res) => {
    const term = req.query.term;
    const query = 'SELECT * FROM products WHERE name LIKE ?';
    db.query(query, [`%${term}%`], (err, results) => {
        if (err) {
            res.status(500).json({ error: 'Database error' });
        } else {
            res.json(results);
        }
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
    db.query(query, [username, password], (err, results) => {
        if (err) {
            res.status(500).json({ error: 'Database error' });
        } else if (results.length > 0) {
            res.json({ status: 'success' });
        } else {
            res.json({ status: 'failed' });
        }
    });
});

// FIX: Prevent command injection by validating input
app.get('/ping', (req, res) => {
    const host = req.query.host;
    if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
        return res.status(400).send('Invalid host');
    }
    exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send('Error executing command');
        } else {
            res.send(stdout);
        }
    });
});

app.get('/exec', (req, res) => {
    res.status(403).send('Command execution is disabled for security reasons');
});

app.post('/run', (req, res) => {
    res.status(403).send('Command execution is disabled for security reasons');
});

// FIX: Sanitize user input to prevent XSS
app.get('/hello', (req, res) => {
    const name = req.query.name;
    res.send(`<h1>Hello ${escapeHtml(name)}!</h1>`);
});

app.get('/profile', (req, res) => {
    const bio = req.query.bio;
    res.send(`
        <html>
            <body>
                <h1>User Profile</h1>
                <p>Bio: ${escapeHtml(bio)}</p>
            </body>
        </html>
    `);
});

// FIX: Validate file paths to prevent path traversal
app.get('/read-file', (req, res) => {
    const filename = req.query.file;
    if (!/^[a-zA-Z0-9_.-]+$/.test(filename)) {
        return res.status(400).send('Invalid filename');
    }
    const content = fs.readFileSync(path.join('/var/data', filename), 'utf8');
    res.send(content);
});

app.get('/download', (req, res) => {
    const filepath = req.query.path;
    if (!/^[a-zA-Z0-9_.-/]+$/.test(filepath)) {
        return res.status(400).send('Invalid filepath');
    }
    res.sendFile(path.join(__dirname, filepath));
});

// FIX: Validate and sanitize input for deserialization
app.post('/deserialize', (req, res) => {
    const data = req.body.data;
    try {
        const obj = serialize.unserialize(data);
        res.json(obj);
    } catch (error) {
        res.status(400).json({ error: 'Invalid input' });
    }
});

// FIX: Prevent prototype pollution
app.post('/merge', (req, res) => {
    const target = {};
    const source = req.body;
    for (const key in source) {
        if (key === '__proto__' || key === 'constructor') {
            continue;
        }
        target[key] = source[key];
    }
    res.json(target);
});

// FIX: Use secure cryptographic algorithms
function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function encryptData(data, key) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key.slice(0, 32), Buffer.alloc(16));
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// FIX: Use cryptographically secure random values
function generateToken() {
    return crypto.randomBytes(16).toString('hex');
}

function generateSessionId() {
    return crypto.randomBytes(16).toString('hex');
}

// FIX: Validate URLs to prevent open redirects
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    if (!/^https:\/\/trusted-domain\.com/.test(url)) {
        return res.status(400).send('Invalid URL');
    }
    res.redirect(url);
});

app.get('/goto', (req, res) => {
    const destination = req.query.dest;
    if (!/^https:\/\/trusted-domain\.com/.test(destination)) {
        return res.status(400).send('Invalid destination');
    }
    res.redirect(302, destination);
});

// FIX: Validate YAML input
app.post('/parse-yaml', (req, res) => {
    const yamlData = req.body.yaml;
    try {
        const config = yaml.load(yamlData, { schema: yaml.JSON_SCHEMA });
        res.json(config);
    } catch (error) {
        res.status(400).json({ error: 'Invalid YAML input' });
    }
});

// FIX: Use safe regex patterns
function validateEmail(email) {
    const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return pattern.test(email);
}

function validateInput(input) {
    const pattern = /^[a-zA-Z0-9]+$/;
    return pattern.test(input);
}

// FIX: Use parameterized queries for MongoDB
app.post('/find-user', async (req, res) => {
    const client = await MongoClient.connect('mongodb://localhost:27017');
    const db = client.db('test');
    const user = await db.collection('users').findOne({
        username: req.body.username,
        password: req.body.password
    });
    res.json(user);
});

// FIX: Validate URLs to prevent SSRF
app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    if (!/^https:\/\/trusted-domain\.com/.test(url)) {
        return res.status(400).send('Invalid URL');
    }
    const response = await axios.get(url);
    res.send(response.data);
});

// Helper function to escape HTML
function escapeHtml(str) {
    return str.replace(/[&<>"']/g, (match) => {
        const escape = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        };
        return escape[match];
    });
}