// Database Migration Script for CricketBet
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function runMigrations() {
  try {
    console.log('🔄 Starting database migrations...');

    // Create users table
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
    console.log('✅ Users table created');

    // Create matches table
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
    console.log('✅ Matches table created');

    // Create players table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS players (
        id SERIAL PRIMARY KEY,
        name VARCHAR(200) NOT NULL,
        team VARCHAR(200) NOT NULL,
        match_id VARCHAR(255) REFERENCES matches(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('✅ Players table created');

    // Create bets table
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
    console.log('✅ Bets table created');

    // Create withdrawals table
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
    console.log('✅ Withdrawals table created');

    // Create indexes for better performance
    await pool.query('CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_matches_status ON matches(match_ended, date_time_gmt);');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_bets_user ON bets(user_id);');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_bets_match ON bets(match_id);');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_bets_status ON bets(status);');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_withdrawals_status ON withdrawals(status);');
    console.log('✅ Database indexes created');

    // Create default admin user
    const adminExists = await pool.query('SELECT id FROM users WHERE phone = $1', ['admin']);
    if (adminExists.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('CricketAdmin@2025', 10);
      await pool.query(
        'INSERT INTO users (name, phone, city, password_hash, balance, is_admin) VALUES ($1, $2, $3, $4, $5, $6)',
        ['Admin User', 'admin', 'Admin City', hashedPassword, 10000, true]
      );
      console.log('✅ Default admin user created');
      console.log('🔐 Admin Login: admin / CricketAdmin@2025');
    } else {
      console.log('✅ Admin user already exists');
    }

    // Create sample test user (optional)
    const testUserExists = await pool.query('SELECT id FROM users WHERE phone = $1', ['9999999999']);
    if (testUserExists.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('test123', 10);
      await pool.query(
        'INSERT INTO users (name, phone, city, password_hash, balance) VALUES ($1, $2, $3, $4, $5)',
        ['Test User', '9999999999', 'Test City', hashedPassword, 500.00]
      );
      console.log('✅ Test user created (Phone: 9999999999, Password: test123)');
    }

    console.log('\n🎉 Database migration completed successfully!');
    console.log('\n📊 Database Schema:');
    console.log('   - users (authentication & wallet)');
    console.log('   - matches (real cricket data)');
    console.log('   - players (team squads)');
    console.log('   - bets (user predictions)');
    console.log('   - withdrawals (payout requests)');
    console.log('\n🔗 Ready to connect to CricketData API!');
    
  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

// Run migrations
runMigrations();