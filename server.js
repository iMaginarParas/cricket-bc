// CricketBet Backend - Railway Production with PostgreSQL
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
const JWT_SECRET = process.env.JWT_SECRET || 'cricket_bet_railway_secret_2025';
const CRICKET_API_KEY = '6963166c-d144-42b7-9f62-6129a2aa7aaa';
const CRICKET_API_BASE = 'https://api.cricapi.com/v1';

// Cloudinary Configuration (optional for QR uploads)
if (process.env.CLOUDINARY_CLOUD_NAME) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  });
}

// PostgreSQL Database Configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.on('connect', () => {
  console.log('✅ Connected to PostgreSQL database');
});

pool.on('error', (err) => {
  console.error('❌ PostgreSQL connection error:', err);
});

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Multer configuration for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

// Database Schema Creation with Enhanced Error Handling
const initDatabase = async () => {
  const client = await pool.connect();
  try {
    console.log('🔄 Initializing database schema...');

    // Users table
    await client.query(`
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

    // Matches table
    await client.query(`
      CREATE TABLE IF NOT EXISTS matches (
        id VARCHAR(255) PRIMARY KEY,
        name VARCHAR(500) NOT NULL,
        match_type VARCHAR(50) NOT NULL,
        status VARCHAR(300) NOT NULL,
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

    // Players table
    await client.query(`
      CREATE TABLE IF NOT EXISTS players (
        id SERIAL PRIMARY KEY,
        name VARCHAR(200) NOT NULL,
        team VARCHAR(200) NOT NULL,
        match_id VARCHAR(255) REFERENCES matches(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Bets table
    await client.query(`
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

    // Withdrawals table
    await client.query(`
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

    // Create indexes for better performance
    await client.query('CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);');
    await client.query('CREATE INDEX IF NOT EXISTS idx_matches_status ON matches(match_ended, date_time_gmt);');
    await client.query('CREATE INDEX IF NOT EXISTS idx_bets_user ON bets(user_id);');
    await client.query('CREATE INDEX IF NOT EXISTS idx_bets_match ON bets(match_id);');
    await client.query('CREATE INDEX IF NOT EXISTS idx_bets_status ON bets(status);');
    await client.query('CREATE INDEX IF NOT EXISTS idx_withdrawals_status ON withdrawals(status);');

    // Create default admin user
    const adminExists = await client.query('SELECT id FROM users WHERE phone = $1', ['admin']);
    if (adminExists.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('CricketAdmin@2025', 10);
      await client.query(
        'INSERT INTO users (name, phone, city, password_hash, balance, is_admin) VALUES ($1, $2, $3, $4, $5, $6)',
        ['Admin User', 'admin', 'Admin City', hashedPassword, 10000, true]
      );
      console.log('✅ Default admin user created (admin / CricketAdmin@2025)');
    }

    console.log('✅ Database schema initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
    throw error;
  } finally {
    client.release();
  }
};

// Cricket API Helper Functions
const fetchFromCricketAPI = async (endpoint) => {
  try {
    const url = `${CRICKET_API_BASE}/${endpoint}?apikey=${CRICKET_API_KEY}`;
    console.log(`🔄 Fetching: ${endpoint}`);
    
    const response = await fetch(url, {
      timeout: 10000 // 10 second timeout
    });
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    const data = await response.json();
    
    if (data.status === 'success') {
      console.log(`✅ API Success: ${endpoint} (${data.data?.length || 0} items)`);
      return data.data;
    } else {
      throw new Error(`API Error: ${data.status} - ${data.info?.error || 'Unknown error'}`);
    }
  } catch (error) {
    console.error(`❌ Cricket API Error (${endpoint}):`, error.message);
    throw error;
  }
};

const syncMatchesFromAPI = async () => {
  const client = await pool.connect();
  try {
    console.log('🔄 Syncing matches from Cricket API...');
    
    // Fetch current matches
    const matches = await fetchFromCricketAPI('currentMatches&offset=0');
    
    let syncedCount = 0;
    
    for (const match of matches) {
      try {
        // Extract team names safely
        const team1 = match.teams?.[0] || 'Team 1';
        const team2 = match.teams?.[1] || 'Team 2';
        
        // Get team images
        const team1Img = match.teamInfo?.find(t => t.name === team1)?.img || 'https://h.cricapi.com/img/icon512.png';
        const team2Img = match.teamInfo?.find(t => t.name === team2)?.img || 'https://h.cricapi.com/img/icon512.png';
        
        // Insert or update match
        await client.query(`
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
          match.name || `${team1} vs ${team2}`,
          match.matchType || 'unknown',
          match.status || 'Unknown',
          match.venue || 'TBD',
          match.dateTimeGMT || null,
          team1,
          team2,
          team1Img,
          team2Img,
          match.series_id || null,
          match.fantasyEnabled || false,
          match.hasSquad || false,
          match.matchStarted || false,
          match.matchEnded || false
        ]);

        // Add sample players for matches with squads
        if (match.hasSquad && !match.matchEnded) {
          // Clear existing players for this match
          await client.query('DELETE FROM players WHERE match_id = $1', [match.id]);
          
          // Add sample players (in production, you'd fetch real squad data)
          const samplePlayers = [
            { name: 'Captain 1', team: team1 },
            { name: 'Batsman 1', team: team1 },
            { name: 'Bowler 1', team: team1 },
            { name: 'All-rounder 1', team: team1 },
            { name: 'Wicket Keeper 1', team: team1 },
            { name: 'Captain 2', team: team2 },
            { name: 'Batsman 2', team: team2 },
            { name: 'Bowler 2', team: team2 },
            { name: 'All-rounder 2', team: team2 },
            { name: 'Wicket Keeper 2', team: team2 }
          ];

          for (const player of samplePlayers) {
            await client.query(
              'INSERT INTO players (name, team, match_id) VALUES ($1, $2, $3)',
              [player.name, player.team, match.id]
            );
          }
        }

        syncedCount++;
      } catch (matchError) {
        console.error(`❌ Error syncing match ${match.id}:`, matchError.message);
      }
    }
    
    console.log(`✅ Successfully synced ${syncedCount}/${matches.length} matches`);
  } catch (error) {
    console.error('❌ Match sync error:', error.message);
  } finally {
    client.release();
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
      message: 'User registered successfully! ₹100 welcome bonus added.',
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
      success: true,
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
      success: true,
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
    if (req.file && process.env.CLOUDINARY_CLOUD_NAME) {
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
        // Continue without QR upload
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
      success: true,
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
      success: true,
      balance: parseFloat(user.rows[0].balance),
      totalBets: parseInt(totalBets.rows[0].count),
      totalStaked: parseFloat(totalBets.rows[0].total_staked),
      wonBets: parseInt(wonBets.rows[0].count),
      totalWinnings: parseFloat(wonBets.rows[0].total_winnings)
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
      success: true,
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
    const { status, actualWinner, actualMotm } = req.body;

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
      success: true,
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
    const { status } = req.body;
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

// ==================== CRON JOBS (Only in production) ====================

if (process.env.NODE_ENV === 'production') {
  // Sync matches every 30 minutes
  cron.schedule('*/30 * * * *', () => {
    console.log('🔄 Running scheduled match sync...');
    syncMatchesFromAPI().catch(console.error);
  });

  console.log('✅ Cron jobs scheduled for production');
}

// ==================== HEALTH CHECK & ERROR HANDLING ====================

// Health check route
app.get('/health', async (req, res) => {
  try {
    // Test database connection
    const dbTest = await pool.query('SELECT NOW()');
    
    // Test Cricket API
    let apiStatus = 'connected';
    try {
      await fetchFromCricketAPI('currentMatches&offset=0');
    } catch (apiError) {
      apiStatus = 'error';
    }

    res.json({ 
      status: 'healthy', 
      timestamp: new Date().toISOString(),
      database: 'connected',
      cricketAPI: apiStatus,
      dbTime: dbTest.rows[0].now,
      environment: process.env.NODE_ENV || 'development'
    });
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    availableRoutes: [
      'GET /health',
      'POST /api/auth/register',
      'POST /api/auth/login',
      'GET /api/matches/upcoming',
      'GET /api/matches/:id/players',
      'POST /api/bets/place',
      'GET /api/user/bets',
      'GET /api/user/wallet',
      'POST /api/withdrawals/request'
    ]
  });
});

// ==================== SERVER START ====================

// Initialize database and start server
const startServer = async () => {
  try {
    console.log('🚀 Starting CricketBet Backend...');
    console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔑 Using Cricket API Key: ${CRICKET_API_KEY.substring(0, 8)}...`);
    
    // Initialize database
    await initDatabase();
    
    // Initial match sync (delay for Railway startup)
    setTimeout(() => {
      console.log('🔄 Starting initial match sync...');
      syncMatchesFromAPI().catch(err => {
        console.error('❌ Initial match sync failed:', err.message);
      });
    }, 5000); // 5 second delay
    
    // Start server
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 CricketBet Backend running on port ${PORT}`);
      console.log(`🏏 Real Cricket Data API integrated`);
      console.log(`💾 Database: PostgreSQL (Railway)`);
      console.log(`🔐 Admin Login: admin / CricketAdmin@2025`);
      console.log(`🌐 Server ready to accept connections`);
      
      if (process.env.RAILWAY_STATIC_URL) {
        console.log(`🔗 Public URL: ${process.env.RAILWAY_STATIC_URL}`);
      }
    });
  } catch (error) {
    console.error('❌ Server startup failed:', error);
    process.exit(1);
  }
};

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('🛑 Received SIGTERM, shutting down gracefully');
  await pool.end();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('🛑 Received SIGINT, shutting down gracefully');
  await pool.end();
  process.exit(0);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

startServer();

module.exports = app;