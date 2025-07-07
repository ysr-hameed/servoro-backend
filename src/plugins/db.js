import fp from 'fastify-plugin';
import pkg from 'pg';
const { Pool } = pkg;

export default fp(async function (fastify, opts) {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  });

  fastify.decorate('pg', pool);

  await pool.query(`
    create extension if not exists "uuid-ossp";

    create table if not exists users (
      id uuid primary key default uuid_generate_v4(),
      first_name text not null,
      last_name text not null,
      username text unique not null,
      email text unique not null,
      password text not null,
      is_verified boolean default false,
      verification_token text,
      reset_token text,
      reset_token_expires timestamp,
      created_at timestamp default now()
    );
  `);

  fastify.log.info('✅ Database ready');
});