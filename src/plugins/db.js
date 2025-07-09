import fp from 'fastify-plugin'
import pkg from 'pg'
const { Pool } = pkg

export default fp(async function (fastify, opts) {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  })

  fastify.decorate('pg', pool)

  await pool.query(`
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      first_name TEXT NOT NULL,
      last_name TEXT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT,
      provider TEXT NOT NULL DEFAULT 'form',
      is_verified BOOLEAN DEFAULT false,
      is_blocked BOOLEAN DEFAULT false,
      verification_token TEXT,
      reset_token TEXT,
      reset_token_expires TIMESTAMP,
      created_at TIMESTAMP DEFAULT now()
    );
  `)

  fastify.log.info('✅ Database ready')
})