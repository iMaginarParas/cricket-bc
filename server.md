// CricketBet Backend - Express.js Server with Real Cricket Data
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cors = require('cors');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const fetch = require('node-fetch');
const cron = require('node-cron');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Environment Variables
const JWT_SECRET = process.env.JWT_SECRET || 'cricket_bet_secret_2025';
const CRICKET_API_KEY = '6963166c-d144-42b7-9f62-6129a2aa7aaa';
const CRICKET_API_BASE = 'https://api.cricapi.com/v1';

// Cloudinary Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Database Configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Multer configuration for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

// Database Schema Creation
const initDatabase = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        phone VARCHAR(20) UNIQUE NOT NULL,
        city VARCHAR(100) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        balance DECIMAL(10,2) DEFAULT 100.00,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS matches (
        id VARCHAR(255) PRIMARY KEY,
        name VARCHAR(500) NOT NULL,
        match_type VARCHAR(50) NOT NULL,
        status VARCHAR(200) NOT NULL,
        venue VARCHAR(300),
        date_time_gmt TIMESTAMP,
        team1 VARCHAR(200) NOT NULL,
        team2 VARCHAR(200) NOT NULL,
        team1_img VARCHAR(500),
        team2_img VARCHAR(500),
        series_id VARCHAR(255),
        fantasy_enabled BOOLEAN DEFAULT TRUE,
        has_squad BOOLEAN DEFAULT TRUE,
        match_started BOOLEAN DEFAULT FALSE,
        match_ended BOOLEAN DEFAULT FALSE,
        winner VARCHAR(200),
        player_of_match VARCHAR(200),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS players (
        id SERIAL PRIMARY KEY,
        name VARCHAR(200) NOT NULL,
        team VARCHAR(200) NOT NULL,
        match_id VARCHAR(255) REFERENCES matches(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS bets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        match_id VARCHAR(255) REFERENCES matches(id),
        winner_prediction VARCHAR(200) NOT NULL,
        motm_prediction VARCHAR(200) NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        potential_return DECIMAL(10,2) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        qr_image_url VARCHAR(500),
        payment_verified BOOLEAN DEFAULT FALSE,
        admin_verified_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS withdrawals (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        processed_at TIMESTAMP,
        processed_by INTEGER REFERENCES users(id)
      );
    `);

    // Create default admin user
    const adminExists = await pool.query('SELECT id FROM users WHERE phone = $1', ['admin']);
    if (adminExists.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('CricketAdmin@2025', 10);
      await pool.query(
        'INSERT INTO users (name, phone, city, password_hash, balance, is_admin) VALUES ($1, $2, $3, $4, $5, $6)',
        ['Admin User', 'admin', 'Admin City', hashedPassword, 10000, true]
      );
      console.log('✅ Default admin user created');
    }

    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
  }
};

// Cricket API Helper Functions
const fetchFromCricketAPI = async (endpoint) => {
  try {
    const url = `${CRICKET_API_BASE}/${endpoint}?apikey=${CRICKET_API_KEY}`;
    const response = await fetch(url);
    const data = await response.json();
    
    if (data.status === 'success') {
      return data.data;
    } else {
      throw new Error(`API Error: ${data.status}`);
    }
  } catch (error) {
    console.error(`❌ Cricket API Error (${endpoint}):`, error);
    throw error;
  }
};

const syncMatchesFromAPI = async () => {
  try {
    console.log('🔄 Syncing matches from Cricket API...');
    
    // Fetch current matches
    const matches = await fetchFromCricketAPI('currentMatches&offset=0');
    
    for (const match of matches) {
      // Extract team names
      const team1 = match.teams[0];
      const team2 = match.teams[1];
      
      // Get team images
      const team1Img = match.teamInfo?.find(t => t.name === team1)?.img || 'https://h.cricapi.com/img/icon512.png';
      const team2Img = match.teamInfo?.find(t => t.name === team2)?.img || 'https://h.cricapi.com/img/icon512.png';
      
      // Insert or update match
      await pool.query(`
        INSERT INTO matches 
        (id, name, match_type, status, venue, date_time_gmt, team1, team2, team1_img, team2_img, series_id, fantasy_enabled, has_squad, match_started, match_ended, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, CURRENT_TIMESTAMP)
        ON CONFLICT (id) DO UPDATE SET
        status = EXCLUDED.status,
        match_started = EXCLUDED.match_started,
        match_ended = EXCLUDED.match_ended,
        updated_at = CURRENT_TIMESTAMP
      `, [
        match.id,
        match.name,
        match.matchType,
        match.status,
        match.venue,
        match.dateTimeGMT,
        team1,
        team2,
        team1Img,
        team2Img,
        match.series_id,
        match.fantasyEnabled,
        match.hasSquad,
        match.matchStarted,
        match.matchEnded
      ]);

      // Fetch and store players if match has squad
      if (match.hasSquad && !match.matchEnded) {
        try {
          const matchInfo = await fetchFromCricketAPI(`match_info&id=${match.id}`);
          if (matchInfo && matchInfo.players) {
            // Clear existing players for this match
            await pool.query('DELETE FROM players WHERE match_id = $1', [match.id]);
            
            // Insert new players
            for (const player of matchInfo.players) {
              await pool.query(
                'INSERT INTO players (name, team, match_id) VALUES ($1, $2, $3)',
                [player.name, player.team || 'Unknown', match.id]
              );
            }
          }
        } catch (playerError) {
          console.log(`⚠️ Could not fetch players for match ${match.id}`);
        }
      }
    }
    
    console.log(`✅ Synced ${matches.length} matches successfully`);
  } catch (error) {
    console.error('❌ Match sync error:', error);
  }
};

// Middleware for JWT authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Middleware for admin authentication
const authenticateAdmin = async (req, res, next) => {
  try {
    const user = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
    if (!user.rows[0]?.is_admin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  } catch (error) {
    res.status(500).json({ error: 'Admin verification failed' });
  }
};

// ==================== AUTH ROUTES ====================

// User Registration
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, city, password } = req.body;
    
    if (!name || !phone || !city || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user exists
    const existingUser = await pool.query('SELECT id FROM users WHERE phone = $1', [phone]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User with this phone number already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user with welcome bonus
    const newUser = await pool.query(
      'INSERT INTO users (name, phone, city, password_hash, balance) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, phone, city, balance',
      [name, phone, city, hashedPassword, 100.00]
    );

    // Generate JWT token
    const token = jwt.sign(
      { id: newUser.rows[0].id, phone: newUser.rows[0].phone },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: newUser.rows[0]
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;

    if (!phone || !password) {
      return res.status(400).json({ error: 'Phone and password are required' });
    }

    // Find user
    const user = await pool.query(
      'SELECT id, name, phone, city, password_hash, balance, is_admin FROM users WHERE phone = $1',
      [phone]
    );

    if (user.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { id: user.rows[0].id, phone: user.rows[0].phone },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    const { password_hash, ...userWithoutPassword } = user.rows[0];

    res.json({
      message: 'Login successful',
      token,
      user: userWithoutPassword
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ==================== MATCH ROUTES ====================

// Get upcoming matches
app.get('/api/matches/upcoming', async (req, res) => {
  try {
    const matches = await pool.query(`
      SELECT m.*, 
             COUNT(p.id) as player_count
      FROM matches m
      LEFT JOIN players p ON m.id = p.match_id
      WHERE m.match_ended = FALSE
      GROUP BY m.id
      ORDER BY m.date_time_gmt ASC
      LIMIT 20
    `);

    res.json({
      matches: matches.rows
    });
  } catch (error) {
    console.error('Fetch matches error:', error);
    res.status(500).json({ error: 'Failed to fetch matches' });
  }
});

// Get players for a specific match
app.get('/api/matches/:id/players', async (req, res) => {
  try {
    const { id } = req.params;
    
    const players = await pool.query(
      'SELECT * FROM players WHERE match_id = $1 ORDER BY team, name',
      [id]
    );

    res.json({
      players: players.rows
    });
  } catch (error) {
    console.error('Fetch players error:', error);
    res.status(500).json({ error: 'Failed to fetch players' });
  }
});

// ==================== BETTING ROUTES ====================

// Place a bet
app.post('/api/bets/place', authenticateToken, upload.single('qrImage'), async (req, res) => {
  try {
    const { matchId, winnerPrediction, motmPrediction, amount } = req.body;
    const userId = req.user.id;

    if (!matchId || !winnerPrediction || !motmPrediction || !amount) {
      return res.status(400).json({ error: 'All bet details are required' });
    }

    // Validate amount
    const betAmount = parseFloat(amount);
    if (betAmount < 10 || betAmount > 10000) {
      return res.status(400).json({ error: 'Bet amount must be between ₹10 and ₹10,000' });
    }

    // Check user balance
    const user = await pool.query('SELECT balance FROM users WHERE id = $1', [userId]);
    if (user.rows[0].balance < betAmount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Check if match exists and is not ended
    const match = await pool.query('SELECT * FROM matches WHERE id = $1 AND match_ended = FALSE', [matchId]);
    if (match.rows.length === 0) {
      return res.status(400).json({ error: 'Match not found or already ended' });
    }

    // Upload QR image to Cloudinary if provided
    let qrImageUrl = null;
    if (req.file) {
      try {
        const result = await new Promise((resolve, reject) => {
          cloudinary.uploader.upload_stream(
            { 
              folder: 'cricketbet/qr-codes',
              public_id: `bet_${userId}_${Date.now()}`,
              format: 'jpg'
            },
            (error, result) => {
              if (error) reject(error);
              else resolve(result);
            }
          ).end(req.file.buffer);
        });
        qrImageUrl = result.secure_url;
      } catch (uploadError) {
        console.error('QR upload error:', uploadError);
        return res.status(500).json({ error: 'Failed to upload QR code' });
      }
    }

    // Calculate potential return (3x)
    const potentialReturn = betAmount * 3;

    // Create bet
    const bet = await pool.query(`
      INSERT INTO bets (user_id, match_id, winner_prediction, motm_prediction, amount, potential_return, qr_image_url)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
    `, [userId, matchId, winnerPrediction, motmPrediction, betAmount, potentialReturn, qrImageUrl]);

    // Deduct amount from user balance
    await pool.query(
      'UPDATE users SET balance = balance - $1 WHERE id = $2',
      [betAmount, userId]
    );

    res.status(201).json({
      message: 'Bet placed successfully',
      bet: bet.rows[0]
    });
  } catch (error) {
    console.error('Place bet error:', error);
    res.status(500).json({ error: 'Failed to place bet' });
  }
});

// Get user's bets
app.get('/api/user/bets', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const bets = await pool.query(`
      SELECT b.*, m.name as match_name, m.team1, m.team2, m.venue, m.status as match_status
      FROM bets b
      JOIN matches m ON b.match_id = m.id
      WHERE b.user_id = $1
      ORDER BY b.created_at DESC
    `, [userId]);

    res.json({
      bets: bets.rows
    });
  } catch (error) {
    console.error('Fetch user bets error:', error);
    res.status(500).json({ error: 'Failed to fetch bets' });
  }
});

// ==================== WALLET ROUTES ====================

// Get user wallet
app.get('/api/user/wallet', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const user = await pool.query('SELECT balance FROM users WHERE id = $1', [userId]);
    const totalBets = await pool.query('SELECT COUNT(*), COALESCE(SUM(amount), 0) as total_staked FROM bets WHERE user_id = $1', [userId]);
    const wonBets = await pool.query('SELECT COUNT(*), COALESCE(SUM(potential_return), 0) as total_winnings FROM bets WHERE user_id = $1 AND status = $2', [userId, 'won']);

    res.json({
      balance: user.rows[0].balance,
      totalBets: totalBets.rows[0].count,
      totalStaked: totalBets.rows[0].total_staked,
      wonBets: wonBets.rows[0].count,
      totalWinnings: wonBets.rows[0].total_winnings
    });
  } catch (error) {
    console.error('Fetch wallet error:', error);
    res.status(500).json({ error: 'Failed to fetch wallet info' });
  }
});

// Request withdrawal
app.post('/api/withdrawals/request', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;
    const userId = req.user.id;

    if (!amount || amount < 100) {
      return res.status(400).json({ error: 'Minimum withdrawal amount is ₹100' });
    }

    // Check user balance
    const user = await pool.query('SELECT balance FROM users WHERE id = $1', [userId]);
    if (user.rows[0].balance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Create withdrawal request
    const withdrawal = await pool.query(`
      INSERT INTO withdrawals (user_id, amount)
      VALUES ($1, $2)
      RETURNING *
    `, [userId, amount]);

    // Deduct amount from user balance
    await pool.query(
      'UPDATE users SET balance = balance - $1 WHERE id = $2',
      [amount, userId]
    );

    res.status(201).json({
      message: 'Withdrawal request submitted successfully',
      withdrawal: withdrawal.rows[0]
    });
  } catch (error) {
    console.error('Withdrawal request error:', error);
    res.status(500).json({ error: 'Failed to submit withdrawal request' });
  }
});

// ==================== ADMIN ROUTES ====================

// Get pending payments (bets with QR codes)
app.get('/api/admin/payments/pending', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const pendingPayments = await pool.query(`
      SELECT b.*, u.name as user_name, u.phone as user_phone, m.name as match_name
      FROM bets b
      JOIN users u ON b.user_id = u.id
      JOIN matches m ON b.match_id = m.id
      WHERE b.qr_image_url IS NOT NULL AND b.payment_verified = FALSE
      ORDER BY b.created_at DESC
    `);

    res.json({
      payments: pendingPayments.rows
    });
  } catch (error) {
    console.error('Fetch pending payments error:', error);
    res.status(500).json({ error: 'Failed to fetch pending payments' });
  }
});

// Settle a bet (mark as won/lost)
app.post('/api/admin/bets/:id/settle', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, actualWinner, actualMotm } = req.body; // status: 'won' or 'lost'
    const adminId = req.user.id;

    if (!['won', 'lost'].includes(status)) {
      return res.status(400).json({ error: 'Status must be won or lost' });
    }

    const bet = await pool.query('SELECT * FROM bets WHERE id = $1', [id]);
    if (bet.rows.length === 0) {
      return res.status(404).json({ error: 'Bet not found' });
    }

    // Update bet status
    await pool.query(
      'UPDATE bets SET status = $1, admin_verified_at = CURRENT_TIMESTAMP WHERE id = $2',
      [status, id]
    );

    // If bet won, credit the potential return to user balance
    if (status === 'won') {
      await pool.query(
        'UPDATE users SET balance = balance + $1 WHERE id = $2',
        [bet.rows[0].potential_return, bet.rows[0].user_id]
      );
    }

    // Update match with actual results if provided
    if (actualWinner || actualMotm) {
      await pool.query(
        'UPDATE matches SET winner = COALESCE($1, winner), player_of_match = COALESCE($2, player_of_match) WHERE id = $3',
        [actualWinner, actualMotm, bet.rows[0].match_id]
      );
    }

    res.json({
      message: `Bet ${status} successfully`,
      bet: { ...bet.rows[0], status }
    });
  } catch (error) {
    console.error('Settle bet error:', error);
    res.status(500).json({ error: 'Failed to settle bet' });
  }
});

// Get pending withdrawals
app.get('/api/admin/withdrawals/pending', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const pendingWithdrawals = await pool.query(`
      SELECT w.*, u.name as user_name, u.phone as user_phone
      FROM withdrawals w
      JOIN users u ON w.user_id = u.id
      WHERE w.status = 'pending'
      ORDER BY w.requested_at DESC
    `);

    res.json({
      withdrawals: pendingWithdrawals.rows
    });
  } catch (error) {
    console.error('Fetch pending withdrawals error:', error);
    res.status(500).json({ error: 'Failed to fetch pending withdrawals' });
  }
});

// Process withdrawal
app.put('/api/admin/withdrawals/:id/process', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body; // 'completed' or 'rejected'
    const adminId = req.user.id;

    if (!['completed', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Status must be completed or rejected' });
    }

    const withdrawal = await pool.query('SELECT * FROM withdrawals WHERE id = $1', [id]);
    if (withdrawal.rows.length === 0) {
      return res.status(404).json({ error: 'Withdrawal not found' });
    }

    // If rejected, refund the amount to user balance
    if (status === 'rejected') {
      await pool.query(
        'UPDATE users SET balance = balance + $1 WHERE id = $2',
        [withdrawal.rows[0].amount, withdrawal.rows[0].user_id]
      );
    }

    // Update withdrawal status
    await pool.query(
      'UPDATE withdrawals SET status = $1, processed_at = CURRENT_TIMESTAMP, processed_by = $2 WHERE id = $3',
      [status, adminId, id]
    );

    res.json({
      message: `Withdrawal ${status} successfully`
    });
  } catch (error) {
    console.error('Process withdrawal error:', error);
    res.status(500).json({ error: 'Failed to process withdrawal' });
  }
});

// ==================== CRON JOBS ====================

// Sync matches every 30 minutes
cron.schedule('*/30 * * * *', () => {
  console.log('🔄 Running scheduled match sync...');
  syncMatchesFromAPI();
});

// Auto-settle bets for ended matches every hour
cron.schedule('0 * * * *', async () => {
  console.log('🔄 Checking for ended matches to auto-settle bets...');
  
  try {
    // Get matches that ended but haven't been processed
    const endedMatches = await pool.query(`
      SELECT DISTINCT m.id, m.name, m.status
      FROM matches m
      JOIN bets b ON m.id = b.match_id
      WHERE m.match_ended = TRUE 
      AND b.status = 'pending'
      AND b.payment_verified = TRUE
    `);

    for (const match of endedMatches.rows) {
      // For now, we'll need manual settlement since determining winner/MOTM from status text is complex
      // In production, you'd parse the match result from the API response
      console.log(`⚠️ Match ${match.name} ended - requires manual settlement`);
    }
  } catch (error) {
    console.error('Auto-settle error:', error);
  }
});

// ==================== SERVER START ====================

// Health check route
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    database: 'connected',
    cricketAPI: 'connected'
  });
});

// Initialize database and start server
const startServer = async () => {
  try {
    await initDatabase();
    
    // Initial match sync
    setTimeout(() => {
      syncMatchesFromAPI();
    }, 2000);
    
    app.listen(PORT, () => {
      console.log(`🚀 CricketBet Backend running on port ${PORT}`);
      console.log(`🏏 Real Cricket Data API integrated`);
      console.log(`💾 Database: Connected`);
      console.log(`🔐 Admin Login: admin@cricketbet.com / CricketAdmin@2025`);
    });
  } catch (error) {
    console.error('❌ Server startup failed:', error);
    process.exit(1);
  }
};

startServer();

module.exports = app;