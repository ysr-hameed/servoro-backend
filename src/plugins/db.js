// plugins/pg.js
import fp from 'fastify-plugin'
import pkg from 'pg'
const { Pool } = pkg

export default fp(async function (fastify, opts) {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  })

  fastify.decorate('pg', pool)

  // ✅ Enable UUID & Random ID Extensions
  await pool.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`)
  await pool.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`)

  // ✅ Users Table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      first_name TEXT NOT NULL,
      last_name TEXT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT,
      provider TEXT NOT NULL DEFAULT 'form',
      is_admin BOOLEAN DEFAULT false,
      is_verified BOOLEAN DEFAULT false,
      is_blocked BOOLEAN DEFAULT false,
      verification_token TEXT,
      reset_token TEXT,
      reset_token_expires TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      created_at TIMESTAMP DEFAULT now()
    );
  `)

  // ✅ App Settings Table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_settings (
      id SERIAL PRIMARY KEY,
      app_name VARCHAR(100) DEFAULT 'Servoro',
      tagline TEXT,
      description TEXT,
      favicon_url TEXT,
      logo_url TEXT,
      light_primary_color VARCHAR(10),
      dark_primary_color VARCHAR(10),
      support_email TEXT,
      contact_phone TEXT,
      default_language VARCHAR(10) DEFAULT 'en',
      maintenance_mode BOOLEAN DEFAULT FALSE,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `)

  // ✅ Insert default app_settings if empty
  const res = await pool.query('SELECT COUNT(*) FROM app_settings')
  if (res.rows[0].count === '0') {
    await pool.query(`
      INSERT INTO app_settings (
        app_name, tagline, description,
        light_primary_color, dark_primary_color
      ) VALUES (
        'StartNet',
        'Your Hyperlocal Service Hub',
        'Find and offer services locally with ease.',
        '#4f46e5',
        '#0e8aa3'
      );
    `)
    fastify.log.info('✅ Default app_settings inserted')
  }

// ✅ Notifications Table
await pool.query(`
  CREATE TABLE IF NOT EXISTS notifications (
  id SERIAL PRIMARY KEY,
  user_id UUID,
  title TEXT,
  message TEXT NOT NULL,
  is_read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`);


await pool.query(`
  CREATE TABLE IF NOT EXISTS notification_reads (
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  notification_id UUID REFERENCES notifications(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, notification_id)
);
`);

  fastify.log.info('✅ Database ready with users, settings, notifications')
})