/**
 * Vulnerable Database Module - For Testing Semgrep Detection
 * DO NOT USE IN PRODUCTION - Contains intentional security vulnerabilities
 */

const mysql = require('mysql');
const pg = require('pg');
const { MongoClient } = require('mongodb');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

// VULNERABILITY 1: Hardcoded database credentials
const DB_CONFIG = {
    host: 'production-db.example.com',
    user: 'admin',
    password: 'SuperSecretPass123!',
    database: 'production'
};

const MONGO_URI = 'mongodb://admin:password123@localhost:27017/production';
const POSTGRES_URI = 'postgres://root:rootpass@localhost:5432/mydb';


// VULNERABILITY 2: SQL Injection - Various patterns
class MySQLDatabase {
    constructor() {
        this.connection = mysql.createConnection(DB_CONFIG);
    }

    // BAD: String concatenation
    findUserByName(username) {
        const query = "SELECT * FROM users WHERE username = '" + username + "'";
        return this.connection.query(query);
    }

    // BAD: Template literal
    findUserByEmail(email) {
        return this.connection.query(`SELECT * FROM users WHERE email = '${email}'`);
    }

    // BAD: Format string style
    searchProducts(term) {
        const query = "SELECT * FROM products WHERE name LIKE '%" + term + "%'";
        return this.connection.query(query);
    }

    // BAD: Multiple injections
    authenticate(username, password) {
        return this.connection.query(
            `SELECT * FROM users WHERE username='${username}' AND password='${password}'`
        );
    }

    // BAD: DELETE with injection
    deleteUser(userId) {
        return this.connection.query("DELETE FROM users WHERE id = " + userId);
    }

    // BAD: UPDATE with injection
    updateRole(userId, role) {
        return this.connection.query(`UPDATE users SET role = '${role}' WHERE id = ${userId}`);
    }

    // BAD: INSERT with injection
    createUser(username, email, password) {
        return this.connection.query(
            `INSERT INTO users (username, email, password) VALUES ('${username}', '${email}', '${password}')`
        );
    }
}


// VULNERABILITY 3: NoSQL Injection
class MongoDatabase {
    async connect() {
        this.client = await MongoClient.connect(MONGO_URI);
        this.db = this.client.db('production');
    }

    // BAD: User input directly in query
    async findUser(username) {
        return this.db.collection('users').findOne({ username: username });
    }

    // BAD: Allows operator injection { $gt: "" }
    async authenticate(username, password) {
        return this.db.collection('users').findOne({
            username: username,
            password: password
        });
    }

    // BAD: User controls query operators
    async searchWithOperators(query) {
        return this.db.collection('users').find(query).toArray();
    }

    // BAD: Aggregation injection
    async aggregate(pipeline) {
        return this.db.collection('data').aggregate(pipeline).toArray();
    }
}


// VULNERABILITY 4: File system vulnerabilities
class FileOperations {
    // BAD: Path traversal
    readFile(filename) {
        const filepath = '/var/data/' + filename;
        return fs.readFileSync(filepath, 'utf8');
    }

    // BAD: path.join doesn't prevent traversal
    readUserFile(userId, filename) {
        const filepath = path.join('/uploads', userId, filename);
        return fs.readFileSync(filepath);
    }

    // BAD: No validation
    writeFile(filename, content) {
        fs.writeFileSync('/tmp/' + filename, content);
    }

    // BAD: Arbitrary file deletion
    deleteFile(filepath) {
        fs.unlinkSync(filepath);
    }

    // BAD: Symlink following
    copyFile(source, dest) {
        const content = fs.readFileSync(source);
        fs.writeFileSync(dest, content);
    }

    // BAD: Directory listing
    listDirectory(dir) {
        return fs.readdirSync(dir);
    }
}


// VULNERABILITY 5: Command injection via shell
class BackupOperations {
    // BAD: Command injection
    backupDatabase(dbName) {
        return new Promise((resolve, reject) => {
            exec(`mysqldump ${dbName} > /tmp/backup.sql`, (error, stdout) => {
                resolve(stdout);
            });
        });
    }

    // BAD: User controls command
    runBackupScript(scriptName) {
        return new Promise((resolve, reject) => {
            exec(`/scripts/${scriptName}`, (error, stdout) => {
                resolve(stdout);
            });
        });
    }

    // BAD: Environment variable injection
    backupWithEnv(dbName, options) {
        return new Promise((resolve, reject) => {
            exec(`pg_dump ${dbName}`, {
                env: { ...process.env, ...options }
            }, (error, stdout) => {
                resolve(stdout);
            });
        });
    }
}


// VULNERABILITY 6: Insecure temporary files
function createTempFile(data) {
    // BAD: Predictable temp filename
    const tempPath = `/tmp/upload_${process.pid}_${Date.now()}.txt`;
    fs.writeFileSync(tempPath, data);
    return tempPath;
}

function createConfigFile(config) {
    // BAD: World-readable permissions
    const configPath = '/tmp/config.json';
    fs.writeFileSync(configPath, JSON.stringify(config));
    fs.chmodSync(configPath, 0o777);
    return configPath;
}


// VULNERABILITY 7: Prototype pollution in merge operations
function mergeDeep(target, source) {
    // BAD: No __proto__ check
    for (const key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            mergeDeep(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

function assignProperties(target, source) {
    // BAD: Allows prototype pollution
    Object.keys(source).forEach(key => {
        target[key] = source[key];
    });
    return target;
}


// VULNERABILITY 8: SSRF via user-controlled URL
const axios = require('axios');

async function fetchRemoteData(url) {
    // BAD: User controls URL - SSRF
    const response = await axios.get(url);
    return response.data;
}

async function postToWebhook(webhookUrl, data) {
    // BAD: User controls destination
    await axios.post(webhookUrl, data);
}


// VULNERABILITY 9: Unsafe deserialization
const serialize = require('node-serialize');

function deserializeData(serializedData) {
    // BAD: Deserializing untrusted data
    return serialize.unserialize(serializedData);
}


// VULNERABILITY 10: Race conditions
let userCount = 0;

async function incrementUserCount() {
    // BAD: Race condition - not atomic
    const current = userCount;
    await new Promise(resolve => setTimeout(resolve, 10));
    userCount = current + 1;
    return userCount;
}


// VULNERABILITY 11: Information disclosure
function getSystemInfo() {
    return {
        // BAD: Exposing system information
        env: process.env,
        cwd: process.cwd(),
        memory: process.memoryUsage(),
        cpus: require('os').cpus(),
        network: require('os').networkInterfaces()
    };
}


module.exports = {
    MySQLDatabase,
    MongoDatabase,
    FileOperations,
    BackupOperations,
    mergeDeep,
    fetchRemoteData,
    deserializeData,
    getSystemInfo
};

