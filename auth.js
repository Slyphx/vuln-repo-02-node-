/**
 * Vulnerable Authentication Module - For Testing Semgrep Detection
 * DO NOT USE IN PRODUCTION - Contains intentional security vulnerabilities
 */

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const https = require('https');
const http = require('http');

// VULNERABILITY 1: Hardcoded secrets and credentials
const JWT_SECRET = "super-secret-key-do-not-share";
const ADMIN_PASSWORD = "admin123";
const API_KEY = "AKIAIOSFODNN7EXAMPLE";
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy
-----END RSA PRIVATE KEY-----`;

const ENCRYPTION_KEY = Buffer.from('0123456789abcdef0123456789abcdef');
const IV = Buffer.from('0123456789abcdef');


// VULNERABILITY 2: JWT with no algorithm verification
function verifyToken(token) {
    // BAD: algorithms not specified
    return jwt.verify(token, JWT_SECRET);
}

function createWeakToken(payload) {
    // BAD: Using 'none' algorithm
    return jwt.sign(payload, '', { algorithm: 'none' });
}

function decodeWithoutVerify(token) {
    // BAD: Decoding without verification
    return jwt.decode(token);
}


// VULNERABILITY 3: Insecure password storage
function hashPasswordInsecure(password) {
    // BAD: Synchronous bcrypt with low rounds
    return bcrypt.hashSync(password, 1);
}

function storePasswordPlaintext(password) {
    // BAD: Storing plaintext password
    return password;
}


// VULNERABILITY 4: Timing attack vulnerabilities
function verifyApiKey(providedKey, storedKey) {
    // BAD: Direct string comparison - timing attack
    return providedKey === storedKey;
}

function verifyTokenUnsafe(inputToken, validToken) {
    // BAD: Character by character - timing leak
    if (inputToken.length !== validToken.length) {
        return false;
    }
    for (let i = 0; i < inputToken.length; i++) {
        if (inputToken[i] !== validToken[i]) {
            return false;
        }
    }
    return true;
}


// VULNERABILITY 5: Insecure SSL/TLS configuration
function fetchDataInsecure(url) {
    // BAD: Disabling certificate verification
    const options = {
        rejectUnauthorized: false,
        requestCert: false
    };
    
    return new Promise((resolve, reject) => {
        https.get(url, options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(data));
        });
    });
}

function makeHttpRequest(url) {
    // BAD: Using HTTP instead of HTTPS
    return new Promise((resolve, reject) => {
        http.get(url, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(data));
        });
    });
}


// VULNERABILITY 6: Weak encryption
function encryptWithECB(data) {
    // BAD: ECB mode is insecure
    const cipher = crypto.createCipheriv('aes-256-ecb', ENCRYPTION_KEY, null);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

function encryptWithDES(data) {
    // BAD: DES is deprecated
    const key = Buffer.from('12345678');
    const cipher = crypto.createCipheriv('des', key, Buffer.alloc(0));
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}


// VULNERABILITY 7: Insecure random generation
function generateSessionId() {
    // BAD: Math.random is not cryptographically secure
    return Math.random().toString(36).substring(2, 15);
}

function generateOTP() {
    // BAD: Predictable OTP
    return Math.floor(Math.random() * 900000 + 100000).toString();
}

function generateResetToken() {
    // BAD: Using Date.now() for tokens
    return Date.now().toString(36);
}


// VULNERABILITY 8: eval and dynamic code execution
function executeUserCode(code) {
    // BAD: eval with user input
    return eval(code);
}

function createDynamicFunction(body) {
    // BAD: new Function is like eval
    return new Function('x', 'return ' + body);
}

function runScript(script) {
    // BAD: Indirect eval
    return (0, eval)(script);
}


// VULNERABILITY 9: require() with user input
function loadModule(moduleName) {
    // BAD: Dynamic require with user input
    return require(moduleName);
}

function loadPlugin(pluginPath) {
    // BAD: User-controlled module path
    return require('./' + pluginPath);
}


// VULNERABILITY 10: Logging sensitive data
function login(username, password) {
    // BAD: Logging credentials
    console.log(`Login attempt: username=${username}, password=${password}`);
    
    if (username === 'admin' && password === ADMIN_PASSWORD) {
        console.log(`Successful login with API_KEY: ${API_KEY}`);
        return { success: true, token: generateSessionId() };
    }
    return { success: false };
}


// VULNERABILITY 11: Buffer issues
function processInput(input) {
    // BAD: Buffer with encoding issues in old Node
    const buf = new Buffer(input);
    return buf.toString('base64');
}


// VULNERABILITY 12: Dangerous object operations
function cloneObject(obj) {
    // BAD: Prototype pollution via JSON parse
    return JSON.parse(JSON.stringify(obj));
}

function extendObject(target, source) {
    // BAD: No prototype check
    for (const key in source) {
        target[key] = source[key];
    }
    return target;
}


// VULNERABILITY 13: Unvalidated redirects
function getRedirectUrl(userUrl) {
    // BAD: No validation of redirect target
    return userUrl;
}


// VULNERABILITY 14: Insecure cookie settings
function setAuthCookie(res, token) {
    // BAD: Missing secure, httpOnly, sameSite flags
    res.cookie('auth_token', token, {
        secure: false,
        httpOnly: false
    });
}


// VULNERABILITY 15: Environment variable exposure
function getConfig() {
    // BAD: Exposing all environment variables
    return process.env;
}

function logEnvironment() {
    // BAD: Logging secrets
    console.log('Environment:', JSON.stringify(process.env));
}


// VULNERABILITY 16: Process.exit without cleanup
function handleError(err) {
    console.error(err);
    // BAD: Abrupt termination
    process.exit(1);
}


// VULNERABILITY 17: Dangerous RegExp
function matchPattern(input) {
    // BAD: ReDoS vulnerable
    const regex = /^(a+)+$/;
    return regex.test(input);
}

function validateUrl(url) {
    // BAD: Catastrophic backtracking
    const regex = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
    return regex.test(url);
}


module.exports = {
    verifyToken,
    createWeakToken,
    hashPasswordInsecure,
    verifyApiKey,
    generateSessionId,
    generateOTP,
    login,
    executeUserCode,
    loadModule
};

