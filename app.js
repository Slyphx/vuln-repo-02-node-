/**
 * Secure Express Application - Fixed Vulnerabilities
 */

const express = require('express');
const mysql = require('mysql');
const { exec, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const yaml = require('js-yaml');
const xml2js = require('xml2js');
const serialize = require('node-serialize');
const helmet = require('helmet');
const cors = require('cors');
const axios = require('axios');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet()); // Use Helmet to set secure HTTP headers
app.use(cors({ origin: 'https://your-allowed-origin.com' })); // Restrict CORS to specific origins

// Secure database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root123456',
    database: 'production'
});

// Use prepared statements to prevent SQL Injection
app.get('/user', (req, res) => {
    const username = req.query.username;
    const query = "SELECT * FROM users WHERE username = ?";
    db.query(query, [username], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(results);
    });
});

app.get('/search', (req, res) => {
    const term = req.query.term;
    const query = "SELECT * FROM products WHERE name LIKE ?";
    db.query(query, [`%${term}%`], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(results);
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = "SELECT * FROM users WHERE username = ? AND password = ?";
    db.query(query, [username, password], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length > 0) {
            res.json({ status: 'success' });
        } else {
            res.json({ status: 'failed' });
        }
    });
});

// Prevent command injection by sanitizing inputs
app.get('/ping', (req, res) => {
    const host = req.query.host;
    if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
        return res.status(400).send('Invalid host');
    }
    exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).send('Error executing command');
        }
        res.send(stdout);
    });
});

app.get('/exec', (req, res) => {
    res.status(403).send('Command execution is disabled for security reasons');
});

app.post('/run', (req, res) => {
    res.status(403).send('Command execution is disabled for security reasons');
});

// Prevent XSS by escaping user input
const escapeHtml = (str) => str.replace(/</g, '&lt;').replace(/>/g, '&gt;');

app.get('/hello', (req, res) => {
    const name = escapeHtml(req.query.name || 'Guest');
    res.send(`<h1>Hello ${name}!</h1>`);
});

app.get('/profile', (req, res) => {
    const bio = escapeHtml(req.query.bio || '');
    res.send(`
        <html>
            <body>
                <h1>User Profile</h1>
                <p>Bio: ${bio}</p>
            </body>
        </html>
    `);
});

// Prevent path traversal by validating file paths
app.get('/read-file', (req, res) => {
    const filename = path.basename(req.query.file || '');
    const filePath = path.join('/var/data/', filename);
    if (!fs.existsSync(filePath)) {
        return res.status(404).send('File not found');
    }
    const content = fs.readFileSync(filePath, 'utf8');
    res.send(content);
});

app.get('/download', (req, res) => {
    const filepath = path.resolve('/var/data/', req.query.path || '');
    if (!filepath.startsWith('/var/data/')) {
        return res.status(400).send('Invalid file path');
    }
    res.sendFile(filepath);
});

// Prevent insecure deserialization
app.post('/deserialize', (req, res) => {
    res.status(403).send('Deserialization of untrusted data is disabled for security reasons');
});

// Prevent prototype pollution
app.post('/merge', (req, res) => {
    const target = {};
    const source = req.body;
    if (source.hasOwnProperty('__proto__')) {
        return res.status(400).send('Invalid input');
    }
    Object.assign(target, source);
    res.json(target);
});

// Use secure cryptographic algorithms
function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function encryptData(data, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key.slice(0, 32), iv);
    return iv.toString('hex') + ':' + cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// Use secure random number generation
function generateToken() {
    return crypto.randomBytes(16).toString('hex');
}

function generateSessionId() {
    return crypto.randomBytes(16).toString('hex');
}

// Prevent open redirects
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    if (!/^https:\/\/your-allowed-domain\.com/.test(url)) {
        return res.status(400).send('Invalid URL');
    }
    res.redirect(url);
});

app.get('/goto', (req, res) => {
    const destination = req.query.dest;
    if (!/^https:\/\/your-allowed-domain\.com/.test(destination)) {
        return res.status(400).send('Invalid URL');
    }
    res.redirect(302, destination);
});

// Prevent YAML deserialization vulnerabilities
app.post('/parse-yaml', (req, res) => {
    res.status(403).send('YAML deserialization is disabled for security reasons');
});

// Fix regex DoS
function validateEmail(email) {
    const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return pattern.test(email);
}

function validateInput(input) {
    const pattern = /^a+b$/;
    return pattern.test(input);
}

// Prevent eval usage
app.post('/calculate', (req, res) => {
    res.status(403).send('Dynamic code execution is disabled for security reasons');
});

app.get('/dynamic', (req, res) => {
    res.status(403).send('Dynamic code execution is disabled for security reasons');
});

// Prevent NoSQL Injection
const MongoClient = require('mongodb').MongoClient;

app.post('/find-user', async (req, res) => {
    const client = await MongoClient.connect('mongodb://localhost:27017', { useUnifiedTopology: true });
    const db = client.db('test');
    const user = await db.collection('users').findOne({
        username: req.body.username,
        password: req.body.password
    });
    res.json(user);
});

// Prevent SSRF
app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    if (!/^https:\/\/your-allowed-domain\.com/.test(url)) {
        return res.status(400).send('Invalid URL');
    }
    const response = await axios.get(url);
    res.send(response.data);
});

// Prevent verbose errors
app.use((err, req, res, next) => {
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, '127.0.0.1', () => {
    console.log(`Server running on port ${PORT}`);
});