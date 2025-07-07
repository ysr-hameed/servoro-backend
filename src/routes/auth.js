import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';
import { sendVerificationEmail, sendResetPasswordEmail } from '../utils/mailer.js';

export default async function (fastify, opts) {
  // 🧾 REGISTER
  fastify.post('/register', async (req, reply) => {
    const schema = z.object({
      first_name: z.string().min(2),
      last_name: z.string().min(2),
      username: z.string().min(3).regex(/^[a-zA-Z0-9_]+$/),
      email: z.string().email(),
      password: z.string().min(6),
    });

    const body = schema.parse(req.body);
    const { first_name, last_name, username, email, password } = body;

    const [userByEmail, userByUsername] = await Promise.all([
      fastify.pg.query('SELECT id FROM users WHERE email=$1', [email]),
      fastify.pg.query('SELECT id FROM users WHERE username=$1', [username])
    ]);

    if (userByEmail.rows.length) return reply.code(400).send({ error: 'Email already registered' });
    if (userByUsername.rows.length) return reply.code(400).send({ error: 'Username already taken' });

    const hashed = await bcrypt.hash(password, 10);
    const token = randomBytes(32).toString('hex');

    await fastify.pg.query(`
      INSERT INTO users (first_name, last_name, username, email, password, verification_token)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [first_name, last_name, username, email, hashed, token]);

    await sendVerificationEmail(email, token);
    reply.send({ message: 'Verification email sent' });
  });

  // ✅ VERIFY EMAIL
  fastify.get('/verify-email', async (req, reply) => {
    const { token } = req.query;
    if (!token) return reply.code(400).send({ error: 'Missing token' });

    const result = await fastify.pg.query(`
      UPDATE users SET is_verified=true, verification_token=NULL
      WHERE verification_token=$1 RETURNING id
    `, [token]);

    if (result.rowCount === 0) return reply.code(400).send({ error: 'Invalid or expired token' });
    reply.send({ message: 'Email verified successfully' });
  });

  // 🔁 RESEND VERIFICATION
  fastify.post('/resend-verification', async (req, reply) => {
    const schema = z.object({ email: z.string().email() });
    const { email } = schema.parse(req.body);

    const result = await fastify.pg.query(`SELECT id, is_verified FROM users WHERE email=$1`, [email]);
    const user = result.rows[0];

    if (!user) return reply.code(400).send({ error: 'User not found' });
    if (user.is_verified) return reply.code(400).send({ error: 'User already verified' });

    const token = randomBytes(32).toString('hex');
    await fastify.pg.query(`UPDATE users SET verification_token=$1 WHERE email=$2`, [token, email]);

    await sendVerificationEmail(email, token);
    reply.send({ message: 'Verification email resent' });
  });

  // 🔐 LOGIN
  fastify.post('/login', async (req, reply) => {
    const schema = z.object({
      identifier: z.string(),
      password: z.string().min(6)
    });

    const { identifier, password } = schema.parse(req.body);

    const result = await fastify.pg.query(
      `SELECT * FROM users WHERE email=$1 OR username=$1`, [identifier]
    );
    const user = result.rows[0];

    if (!user) return reply.code(400).send({ error: 'Invalid credentials' });
    if (!user.is_verified) return reply.code(401).send({ error: 'Email not verified' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return reply.code(400).send({ error: 'Invalid credentials' });

    const token = fastify.jwt.sign({ id: user.id }, { expiresIn: '7d' });

    reply.send({
      token,
      user: {
        id: user.id,
        name: `${user.first_name} ${user.last_name}`,
        username: user.username,
        email: user.email
      }
    });
  });

  // 🔁 FORGOT PASSWORD
  fastify.post('/forgot-password', async (req, reply) => {
    const schema = z.object({ email: z.string().email() });
    const { email } = schema.parse(req.body);

    const user = await fastify.pg.query(`SELECT id FROM users WHERE email=$1`, [email]);
    if (!user.rows.length) return reply.code(400).send({ error: 'User not found' });

    const token = randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 15 * 60 * 1000); // 15 mins

    await fastify.pg.query(`
      UPDATE users SET reset_token=$1, reset_token_expires=$2 WHERE email=$3
    `, [token, expiry, email]);

    await sendResetPasswordEmail(email, token);
    reply.send({ message: 'Reset link sent to email' });
  });

  // 🔑 RESET PASSWORD
  fastify.post('/reset-password', async (req, reply) => {
    const schema = z.object({
      token: z.string(),
      password: z.string().min(6)
    });

    const { token, password } = schema.parse(req.body);

    const result = await fastify.pg.query(`
      SELECT id FROM users WHERE reset_token=$1 AND reset_token_expires > NOW()
    `, [token]);

    if (!result.rows.length) return reply.code(400).send({ error: 'Token invalid or expired' });

    const hash = await bcrypt.hash(password, 10);
    await fastify.pg.query(`
      UPDATE users SET password=$1, reset_token=NULL, reset_token_expires=NULL
      WHERE reset_token=$2
    `, [hash, token]);

    reply.send({ message: 'Password reset successful' });
  });
}