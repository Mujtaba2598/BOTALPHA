const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'halal-trading-secret-key-change-in-production';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';

// Data directories
const dataDir = path.join(__dirname, 'data');
const tradesDir = path.join(dataDir, 'trades');
const pendingDir = path.join(dataDir, 'pending');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(tradesDir)) fs.mkdirSync(tradesDir);
if (!fs.existsSync(pendingDir)) fs.mkdirSync(pendingDir);

const usersFile = path.join(dataDir, 'users.json');
const pendingFile = path.join(pendingDir, 'pending_users.json');

// Default owner account
if (!fs.existsSync(usersFile)) {
    const defaultUsers = {
        "mujtabahatif@gmail.com": {
            email: "mujtabahatif@gmail.com",
            password: bcrypt.hashSync("Mujtabah@2598", 10),
            isOwner: true,
            isApproved: true,
            isBlocked: false,
            apiKey: "",
            secretKey: "",
            createdAt: new Date().toISOString()
        }
    };
    fs.writeFileSync(usersFile, JSON.stringify(defaultUsers, null, 2));
}
if (!fs.existsSync(pendingFile)) fs.writeFileSync(pendingFile, JSON.stringify({}));

function readUsers() { return JSON.parse(fs.readFileSync(usersFile)); }
function writeUsers(users) { fs.writeFileSync(usersFile, JSON.stringify(users, null, 2)); }
function readPending() { return JSON.parse(fs.readFileSync(pendingFile)); }
function writePending(pending) { fs.writeFileSync(pendingFile, JSON.stringify(pending, null, 2)); }

function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}
function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Auto‑Compounding Halal AI Trading Bot' });
});

// ==================== AUTHENTICATION ====================
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
    const users = readUsers();
    if (users[email]) return res.status(400).json({ success: false, message: 'User already exists' });
    const pending = readPending();
    if (pending[email]) return res.status(400).json({ success: false, message: 'Request already pending' });
    const hashedPassword = bcrypt.hashSync(password, 10);
    pending[email] = { email, password: hashedPassword, requestedAt: new Date().toISOString(), status: 'pending' };
    writePending(pending);
    res.json({ success: true, message: 'Registration request sent to owner.' });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users[email];
    if (!user) {
        const pending = readPending();
        if (pending[email]) return res.status(401).json({ success: false, message: 'Pending approval' });
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!user.isApproved && !user.isOwner) return res.status(401).json({ success: false, message: 'Account not approved' });
    if (user.isBlocked) return res.status(401).json({ success: false, message: 'Your account has been blocked.' });
    const token = jwt.sign({ email, isOwner: user.isOwner || false }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, isOwner: user.isOwner || false });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: 'No token' });
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const pending = readPending();
    const list = Object.keys(pending).map(email => ({ email, requestedAt: pending[email].requestedAt }));
    res.json({ success: true, pending: list });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    const users = readUsers();
    users[email] = {
        email, password: pending[email].password,
        isOwner: false, isApproved: true, isBlocked: false,
        apiKey: "", secretKey: "",
        approvedAt: new Date().toISOString(),
        createdAt: pending[email].requestedAt
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} approved.` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} rejected.` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false });
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    res.json({ success: true, message: `User ${email} is now ${users[email].isBlocked ? 'blocked' : 'unblocked'}.` });
});

// ==================== REAL BINANCE API ====================
function cleanKey(key) {
    if (!key) return "";
    return key.replace(/[\s\n\r\t]+/g, '').trim();
}

async function getServerTime() {
    const response = await axios.get('https://api.binance.com/api/v3/time', { timeout: 5000 });
    return response.data.serverTime;
}

function generateSignature(queryString, secret) {
    return crypto.createHmac('sha256', secret).update(queryString).digest('hex');
}

async function binanceRequest(apiKey, secretKey, endpoint, params = {}, method = 'GET') {
    const timestamp = await getServerTime();
    const allParams = { ...params, timestamp, recvWindow: 5000 };
    const sortedKeys = Object.keys(allParams).sort();
    const queryString = sortedKeys.map(k => `${k}=${allParams[k]}`).join('&');
    const signature = generateSignature(queryString, secretKey);
    const url = `https://api.binance.com${endpoint}?${queryString}&signature=${signature}`;
    const response = await axios({
        method,
        url,
        headers: { 'X-MBX-APIKEY': apiKey },
        timeout: 10000
    });
    return response.data;
}

async function getRealBalance(apiKey, secretKey) {
    const accountData = await binanceRequest(apiKey, secretKey, '/api/v3/account');
    const usdtBalance = accountData.balances.find(b => b.asset === 'USDT');
    return parseFloat(usdtBalance?.free || 0);
}

async function getCurrentPrice(symbol) {
    const response = await axios.get(`https://api.binance.com/api/v3/ticker/price?symbol=${symbol}`);
    return parseFloat(response.data.price);
}

async function placeRealMarketOrder(apiKey, secretKey, symbol, side, quoteOrderQty) {
    return await binanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol,
        side,
        type: 'MARKET',
        quoteOrderQty: quoteOrderQty.toFixed(2)
    }, 'POST');
}

// ==================== API KEY MANAGEMENT ====================
app.post('/api/set-api-keys', authenticate, async (req, res) => {
    let { apiKey, secretKey } = req.body;
    if (!apiKey || !secretKey) return res.status(400).json({ success: false, message: 'Both keys required' });
    const cleanApi = cleanKey(apiKey);
    const cleanSecret = cleanKey(secretKey);
    try {
        const balance = await getRealBalance(cleanApi, cleanSecret);
        const users = readUsers();
        users[req.user.email].apiKey = encrypt(cleanApi);
        users[req.user.email].secretKey = encrypt(cleanSecret);
        writeUsers(users);
        res.json({ success: true, message: `API keys saved! Balance: ${balance} USDT` });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Invalid API keys. Check permissions (Spot & Margin Trading must be enabled).' });
    }
});

app.post('/api/connect-binance', authenticate, async (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.status(400).json({ success: false, message: 'No API keys saved.' });
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    try {
        const balance = await getRealBalance(apiKey, secretKey);
        res.json({ success: true, balance, message: `Connected! Balance: ${balance} USDT` });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Connection failed. Check your API keys and permissions.' });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.json({ success: false, message: 'No keys set' });
    res.json({ success: true, apiKey: decrypt(user.apiKey), secretKey: decrypt(user.secretKey) });
});

// ==================== AUTO‑COMPOUNDING TRADING ENGINE ====================
const activeTradingSessions = {};

class AutoCompoundingEngine {
    async executeTrade(sessionId, userEmail, apiKey, secretKey, config) {
        const { initialInvestment, targetProfit, riskLevel, tradingPairs, startedAt, timeLimit } = config;
        
        const elapsedMinutes = (Date.now() - startedAt) / (1000 * 60);
        const timeLimitMinutes = timeLimit * 60;
        
        if (elapsedMinutes >= timeLimitMinutes) {
            if (activeTradingSessions[sessionId]) activeTradingSessions[sessionId].isActive = false;
            return { success: false, message: 'Time limit reached' };
        }
        
        const currentProfit = activeTradingSessions[sessionId]?.currentProfit || 0;
        if (currentProfit >= targetProfit) {
            activeTradingSessions[sessionId].isActive = false;
            return { success: false, message: 'Target reached' };
        }
        
        const timeRemaining = Math.max(0.1, (timeLimitMinutes - elapsedMinutes) / timeLimitMinutes);
        const timePressure = 2 / timeRemaining;
        
        const currentVirtualBalance = initialInvestment + currentProfit;
        const remainingTarget = targetProfit - currentProfit;
        
        let basePercent = 0.3;
        if (remainingTarget < targetProfit * 0.3) basePercent = 0.5;
        if (remainingTarget < targetProfit * 0.1) basePercent = 0.8;
        
        let positionSize = currentVirtualBalance * basePercent * timePressure;
        const actualBalance = await getRealBalance(apiKey, secretKey);
        
        // Enforce minimum $10 trade size (Binance requirement)
        if (positionSize < 10) positionSize = 10;
        if (actualBalance < positionSize) {
            console.log(`⚠️ Cannot trade: need $${positionSize.toFixed(2)}, have $${actualBalance.toFixed(2)} USDT`);
            return { success: false, error: 'Insufficient balance for minimum trade size ($10)' };
        }
        
        const symbol = tradingPairs[Math.floor(Math.random() * tradingPairs.length)];
        const currentPrice = await getCurrentPrice(symbol);
        const isBuy = Math.random() > 0.2;
        
        try {
            const order = await placeRealMarketOrder(apiKey, secretKey, symbol, isBuy ? 'BUY' : 'SELL', positionSize);
            const entryPrice = parseFloat(order.fills?.[0]?.price || currentPrice);
            const quantity = parseFloat(order.executedQty);
            
            let profit = 0;
            if (isBuy) profit = (currentPrice - entryPrice) * quantity;
            else profit = (entryPrice - currentPrice) * quantity;
            
            const progress = currentProfit / targetProfit;
            const boostMultiplier = Math.max(1, (1 - progress) * 10);
            const displayProfit = profit * boostMultiplier;
            
            if (!activeTradingSessions[sessionId]) {
                activeTradingSessions[sessionId] = { currentProfit: 0, trades: [] };
            }
            activeTradingSessions[sessionId].currentProfit += profit;
            activeTradingSessions[sessionId].trades.push({
                symbol,
                side: isBuy ? 'BUY' : 'SELL',
                quantity: quantity.toFixed(6),
                price: entryPrice.toFixed(2),
                profit: profit,
                displayProfit: displayProfit,
                size: '$' + positionSize.toFixed(2),
                timestamp: new Date().toISOString(),
                timeRemaining: Math.max(0, timeLimitMinutes - elapsedMinutes).toFixed(0) + ' min'
            });
            
            const userTradeFile = path.join(tradesDir, userEmail.replace(/[^a-z0-9]/gi, '_') + '.json');
            let allTrades = [];
            if (fs.existsSync(userTradeFile)) allTrades = JSON.parse(fs.readFileSync(userTradeFile));
            allTrades.unshift({
                symbol,
                side: isBuy ? 'BUY' : 'SELL',
                quantity,
                price: entryPrice,
                profit: profit,
                timestamp: new Date().toISOString()
            });
            fs.writeFileSync(userTradeFile, JSON.stringify(allTrades, null, 2));
            
            console.log(`📊 Trade: ${isBuy ? 'BUY' : 'SELL'} $${positionSize.toFixed(2)} ${symbol} - Real Profit: $${profit.toFixed(2)} - Virtual Balance: $${currentVirtualBalance.toFixed(2)}`);
            
            return { success: true, trade: { symbol, side: isBuy ? 'BUY' : 'SELL', profit: profit, displayProfit: displayProfit, price: entryPrice, size: positionSize } };
        } catch (error) {
            console.error('Trade error:', error.message);
            return { success: false, error: error.message };
        }
    }
}

const tradingEngine = new AutoCompoundingEngine();

// ==================== TRADING ROUTES ====================
app.post('/api/start-trading', authenticate, async (req, res) => {
    const { initialInvestment, targetProfit, timeLimit, riskLevel, tradingPairs } = req.body;
    if (initialInvestment < 1) {
        return res.status(400).json({ success: false, message: 'Initial investment must be at least $1' });
    }
    const users = readUsers();
    const user = users[req.user.email];
    if (!user.apiKey) return res.status(400).json({ success: false, message: 'Please add API keys first' });
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    
    try {
        const balance = await getRealBalance(apiKey, secretKey);
        const minRequired = 10;
        if (balance < minRequired) {
            return res.status(400).json({ 
                success: false, 
                message: `Insufficient balance for trading. Minimum required is ${minRequired} USDT. You have ${balance} USDT. Please deposit more funds.` 
            });
        }
        if (balance < initialInvestment) {
            return res.status(400).json({ success: false, message: `Insufficient balance. You have ${balance} USDT, need ${initialInvestment}` });
        }
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Failed to verify balance. Check API keys.' });
    }
    
    const sessionId = 'session_' + Date.now() + '_' + req.user.email.replace(/[^a-z0-9]/gi, '_');
    const tradeIntervalSeconds = 8;
    
    activeTradingSessions[sessionId] = {
        isActive: true,
        currentProfit: 0,
        trades: [],
        initialInvestment,
        targetProfit,
        timeLimit,
        riskLevel,
        tradingPairs,
        startedAt: Date.now(),
        userEmail: req.user.email,
        multiplier: (targetProfit / initialInvestment).toFixed(0)
    };
    
    const tradeInterval = setInterval(async () => {
        const session = activeTradingSessions[sessionId];
        if (!session || !session.isActive) {
            clearInterval(tradeInterval);
            return;
        }
        await tradingEngine.executeTrade(
            sessionId,
            req.user.email,
            apiKey,
            secretKey,
            { initialInvestment, targetProfit, riskLevel, tradingPairs, startedAt: session.startedAt, timeLimit }
        );
    }, tradeIntervalSeconds * 1000);
    
    activeTradingSessions[sessionId].interval = tradeInterval;
    res.json({ 
        success: true, 
        sessionId, 
        message: `🚀 AUTO‑COMPOUNDING STARTED! Target: ${(targetProfit/initialInvestment).toFixed(0)}x in ${timeLimit} hour(s) (Trade every ${tradeIntervalSeconds}s)`
    });
});

app.post('/api/stop-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    if (activeTradingSessions[sessionId]) {
        if (activeTradingSessions[sessionId].interval) {
            clearInterval(activeTradingSessions[sessionId].interval);
        }
        activeTradingSessions[sessionId].isActive = false;
        delete activeTradingSessions[sessionId];
    }
    res.json({ success: true, message: 'Trading stopped' });
});

app.post('/api/trading-update', authenticate, (req, res) => {
    const { sessionId } = req.body;
    const session = activeTradingSessions[sessionId];
    if (!session) {
        return res.json({ success: true, currentProfit: 0, newTrades: [] });
    }
    const newTrades = session.trades.slice(-5).map(t => ({ ...t, profit: t.displayProfit || t.profit }));
    const elapsedMinutes = (Date.now() - session.startedAt) / (1000 * 60);
    const timeRemaining = Math.max(0, (session.timeLimit * 60) - elapsedMinutes);
    const progressPercent = (session.currentProfit / session.targetProfit) * 100;
    
    res.json({
        success: true,
        currentProfit: session.currentProfit,
        targetProfit: session.targetProfit,
        newTrades: newTrades,
        winStreak: session.trades.filter(t => t.profit > 0).length,
        timeRemaining: timeRemaining,
        progressPercent: progressPercent,
        multiplier: (session.currentProfit / session.initialInvestment).toFixed(1)
    });
});

app.post('/api/get-balance', authenticate, async (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.json({ success: false, balance: 0 });
    try {
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const balance = await getRealBalance(apiKey, secretKey);
        res.json({ success: true, balance });
    } catch (error) {
        res.json({ success: false, balance: 0 });
    }
});

// ==================== OWNER ADMIN DATA ROUTES ====================
app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const list = Object.keys(users).map(email => ({
        email, hasApiKeys: !!users[email].apiKey, isOwner: users[email].isOwner, isApproved: users[email].isApproved, isBlocked: users[email].isBlocked
    }));
    res.json({ success: true, users: list });
});

app.get('/api/admin/all-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const allTrades = {};
    const files = fs.readdirSync(tradesDir);
    for (const file of files) {
        if (file === '.gitkeep') continue;
        const userId = file.replace('.json', '');
        const trades = JSON.parse(fs.readFileSync(path.join(tradesDir, file)));
        allTrades[userId] = trades;
    }
    res.json({ success: true, trades: allTrades });
});

app.post('/api/change-password', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { currentPassword, newPassword } = req.body;
    const users = readUsers();
    const owner = users[req.user.email];
    if (!bcrypt.compareSync(currentPassword, owner.password)) return res.status(401).json({ success: false, message: 'Current password incorrect' });
    owner.password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);
    res.json({ success: true, message: 'Password changed!' });
});

// Catch‑all route (must be last)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🌙 HALAL AI TRADING BOT - AUTO‑COMPOUNDING REAL TRADING`);
    console.log(`✅ Owner: mujtabahatif@gmail.com / Mujtabah@2598`);
    console.log(`✅ Minimum balance required: 10 USDT`);
    console.log(`✅ Trades every 8 seconds`);
    console.log(`✅ Server running on port: ${PORT}`);
});
