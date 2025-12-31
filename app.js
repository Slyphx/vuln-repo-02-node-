/**
 * Vulnerable Express Application - For Testing Semgrep Detection
 * DO NOT USE IN PRODUCTION - Contains intentional security vulnerabilities
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

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// VULNERABILITY 1: Hardcoded secrets (semgrep: javascript.lang.security.audit.detect-*)
const API_KEY = "sk-1234567890abcdef1234567890abcdef";
const DATABASE_PASSWORD = "super_secret_password_123";
const JWT_SECRET = "my-super-secret-jwt-key-12345";
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// Database connection with hardcoded credentials
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root123456',
    database: 'production'
});


// VULNERABILITY 2: SQL Injection (semgrep: javascript.lang.security.audit.sqli.*)
app.get('/user', (req, res) => {
    const username = req.query.username;
    // BAD: String concatenation in SQL query
    const query = "SELECT * FROM users WHERE username = '" + username + "'";
    db.query(query, (err, results) => {
        res.json(results);
    });
});

app.get('/search', (req, res) => {
    const term = req.query.term;
    // BAD: Template literal in SQL query
    const query = `SELECT * FROM products WHERE name LIKE '%${term}%'`;
    db.query(query, (err, results) => {
        res.json(results);
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // BAD: Direct string interpolation
    db.query(`SELECT * FROM users WHERE username='${username}' AND password='${password}'`, 
        (err, results) => {
            if (results.length > 0) {
                res.json({ status: 'success' });
            } else {
                res.json({ status: 'failed' });
            }
        }
    );
});


// VULNERABILITY 3: Command Injection (semgrep: javascript.lang.security.audit.command-injection.*)
app.get('/ping', (req, res) => {
    const host = req.query.host;
    // BAD: User input directly in exec
    exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

app.get('/exec', (req, res) => {
    const cmd = req.query.cmd;
    // BAD: execSync with user input
    const result = execSync(cmd);
    res.send(result.toString());
});

app.post('/run', (req, res) => {
    const { command, args } = req.body;
    // BAD: User-controlled command execution
    exec(command + ' ' + args.join(' '), (error, stdout) => {
        res.send(stdout);
    });
});


// VULNERABILITY 4: XSS / Reflected Input (semgrep: javascript.express.security.audit.xss.*)
app.get('/hello', (req, res) => {
    const name = req.query.name;
    // BAD: Directly embedding user input in HTML response
    res.send(`<h1>Hello ${name}!</h1>`);
});

app.get('/profile', (req, res) => {
    const bio = req.query.bio;
    // BAD: No sanitization of user input
    res.send(`
        <html>
            <body>
                <h1>User Profile</h1>
                <p>Bio: ${bio}</p>
            </body>
        </html>
    `);
});


// VULNERABILITY 5: Path Traversal (semgrep: javascript.lang.security.audit.path-traversal.*)
app.get('/read-file', (req, res) => {
    const filename = req.query.file;
    // BAD: No path validation
    const content = fs.readFileSync('/var/data/' + filename, 'utf8');
    res.send(content);
});

app.get('/download', (req, res) => {
    const filepath = req.query.path;
    // BAD: path.join doesn't prevent traversal when user controls start
    res.sendFile(path.join(__dirname, filepath));
});


// VULNERABILITY 6: Insecure Deserialization (semgrep: javascript.lang.security.detect-non-literal-require.*)
app.post('/deserialize', (req, res) => {
    const data = req.body.data;
    // BAD: Deserializing untrusted data
    const obj = serialize.unserialize(data);
    res.json(obj);
});


// VULNERABILITY 7: Prototype Pollution
app.post('/merge', (req, res) => {
    const target = {};
    const source = req.body;
    // BAD: Merging user input without sanitization
    Object.assign(target, source);
    res.json(target);
});

function deepMerge(target, source) {
    for (const key in source) {
        // BAD: No __proto__ check - prototype pollution
        if (typeof source[key] === 'object') {
            target[key] = deepMerge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}


// VULNERABILITY 8: Weak Cryptography (semgrep: javascript.lang.security.audit.crypto-*)
function hashPassword(password) {
    // BAD: MD5 is cryptographically broken
    return crypto.createHash('md5').update(password).digest('hex');
}

function hashWithSha1(data) {
    // BAD: SHA1 is deprecated for security
    return crypto.createHash('sha1').update(data).digest('hex');
}

function encryptData(data, key) {
    // BAD: DES is deprecated
    const cipher = crypto.createCipheriv('des', key.slice(0, 8), Buffer.alloc(8));
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}


// VULNERABILITY 9: Insecure Random (semgrep: javascript.lang.security.audit.insecure-random.*)
function generateToken() {
    // BAD: Math.random() is not cryptographically secure
    return Math.random().toString(36).substring(2);
}

function generateSessionId() {
    // BAD: Predictable random
    return Math.floor(Math.random() * 1000000).toString();
}


// VULNERABILITY 10: Open Redirect (semgrep: javascript.express.security.audit.express-open-redirect.*)
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    // BAD: Redirecting to user-supplied URL
    res.redirect(url);
});

app.get('/goto', (req, res) => {
    const destination = req.query.dest;
    // BAD: No URL validation
    res.redirect(302, destination);
});


// VULNERABILITY 11: YAML Deserialization
app.post('/parse-yaml', (req, res) => {
    const yamlData = req.body.yaml;
    // BAD: Loading untrusted YAML
    const config = yaml.load(yamlData);
    res.json(config);
});


// VULNERABILITY 12: Regex DoS (semgrep: javascript.lang.security.audit.regex-dos.*)
function validateEmail(email) {
    // BAD: Catastrophic backtracking
    const pattern = /^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$/;
    return pattern.test(email);
}

function validateInput(input) {
    // BAD: Evil regex
    const pattern = /(a+)+b/;
    return pattern.test(input);
}


// VULNERABILITY 13: eval() usage (semgrep: javascript.lang.security.audit.detect-eval.*)
app.post('/calculate', (req, res) => {
    const expression = req.body.expr;
    // BAD: eval with user input
    const result = eval(expression);
    res.json({ result });
});

app.get('/dynamic', (req, res) => {
    const code = req.query.code;
    // BAD: new Function is like eval
    const fn = new Function('return ' + code);
    res.json({ result: fn() });
});


// VULNERABILITY 14: NoSQL Injection (for MongoDB)
const MongoClient = require('mongodb').MongoClient;

app.post('/find-user', async (req, res) => {
    const client = await MongoClient.connect('mongodb://localhost:27017');
    const db = client.db('test');
    
    // BAD: User input directly in query - allows {$gt: ""} bypass
    const user = await db.collection('users').findOne({
        username: req.body.username,
        password: req.body.password
    });
    
    res.json(user);
});


// VULNERABILITY 15: SSRF (Server-Side Request Forgery)
const axios = require('axios');

app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    // BAD: Fetching user-supplied URL
    const response = await axios.get(url);
    res.send(response.data);
});


// VULNERABILITY 16: Debug mode / Verbose errors
app.use((err, req, res, next) => {
    // BAD: Exposing stack traces
    res.status(500).json({
        error: err.message,
        stack: err.stack
    });
});


// VULNERABILITY 17: Insecure CORS (semgrep: javascript.express.security.audit.express-cors.*)
app.use((req, res, next) => {
    // BAD: Allow all origins
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', '*');
    next();
});


// VULNERABILITY 18: Helmet not used / Security headers missing
// BAD: No security headers configured


// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    // BAD: Binding to 0.0.0.0 exposes to all interfaces
    console.log(`Server running on port ${PORT}`);
});

