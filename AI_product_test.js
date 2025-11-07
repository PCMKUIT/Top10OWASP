// test-complete.js - Test ALL vulnerabilities
const db = require('./db');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { exec } = require('child_process');
const cors = require('cors');

// A01 - Broken Access Control
function insecureAccessControl(req, res) {
    const userId = req.body.userId;
    return db.getUser(userId); // Missing auth check
}

// A02 - Cryptographic Failures
function weakCrypto(password) {
    const crypto = require('crypto');
    return crypto.createHash('md5').update(password).digest('hex'); // Weak hashing
}

function logPassword(password) {
    console.log("User password:", password); // Password in plaintext
}

// A03 - Injection
function sqlInjection(userId) {
    return db.query("SELECT * FROM users WHERE id=" + userId); // SQL injection
}

function nosqlInjection(req) {
    return User.find({ username: req.body.username }); // NoSQL injection
}

function commandInjection(userInput) {
    exec("ls " + userInput); // Command injection
}

// A05 - Security Misconfiguration
function insecureCORS() {
    app.use(cors({
        origin: "*",
        credentials: true
    })); // Insecure CORS
}

// A07 - Identification and Authentication Failures
function insecureSession(req, res) {
    res.cookie('session', 'token123', {}); // Missing secure flags
}

function weakPassword(password) {
    if (password.length < 6) return true; // Weak validation
    return false;
}

function jwtVulnerability(token) {
    return jwt.verify(token, 'secret', { algorithms: ['none'] }); // JWT none alg
}

// A08 - Software and Data Integrity Failures
function unsafeDeserialization(data) {
    return JSON.parse(data); // Unsafe deserialization
}

// A10 - SSRF
function ssrfVulnerability(url) {
    return axios.get(url); // SSRF
}

// General
function hardcodedSecret() {
    const apiKey = "sk_live_1234567890"; // Hardcoded secret
    return apiKey;
}

function unsafeRedirect(req, res) {
    const url = req.query.redirect;
    res.redirect(url); // Open redirect
}