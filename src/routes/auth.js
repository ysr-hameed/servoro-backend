import { z } from 'zod'
import bcrypt from 'bcryptjs'
import { randomBytes } from 'crypto'
import { sendVerificationEmail, sendResetPasswordEmail } from '../utils/mailer.js'
import fastifyOauth2 from '@fastify/oauth2'

export default async function (fastify, opts) {
  // 🔐 REGISTER
  fastify.post('/register', {
    config: {
      rateLimit: {
        max: 5,
        timeWindow: '10m',
        keyGenerator: req => req.body?.email || req.ip
      }
    }
  }, async (req, reply) => {
    const schema = z.object({
      first_name: z.string().min(2),
      last_name: z.string().min(2),
      username: z.string().min(3).regex(/^[a-zA-Z0-9_]+$/),
      email: z.string().email(),
      password: z.string().min(6),
    })
    const body = schema.parse(req.body)
    const { first_name, last_name, username, email, password } = body

    const [userByEmail, userByUsername] = await Promise.all([
      fastify.pg.query('SELECT id FROM users WHERE email=$1', [email]),
      fastify.pg.query('SELECT id FROM users WHERE username=$1', [username])
    ])

    if (userByEmail.rows.length) return reply.code(400).send({ error: 'Email already registered' })
    if (userByUsername.rows.length) return reply.code(400).send({ error: 'Username already taken' })

    const hashed = await bcrypt.hash(password, 10)
    const token = randomBytes(32).toString('hex')

    await fastify.pg.query(`
      INSERT INTO users (first_name, last_name, username, email, password, verification_token)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [first_name, last_name, username, email, hashed, token])

    await sendVerificationEmail(email, token)
    reply.send({ message: 'Verification email sent' })
  })

  // ✅ VERIFY EMAIL
  fastify.get('/verify-email', async (req, reply) => {
    const { token } = req.query
    if (!token) return reply.code(400).send({ error: 'Missing token' })

    const result = await fastify.pg.query(`
      UPDATE users SET is_verified=true, verification_token=NULL
      WHERE verification_token=$1 RETURNING id
    `, [token])

    if (result.rowCount === 0) return reply.code(400).send({ error: 'Invalid or expired token' })
    reply.send({ message: 'Email verified successfully' })
  })

  // 🔁 RESEND VERIFICATION
  fastify.post('/resend-verification', {
    config: {
      rateLimit: {
        max: 3,
        timeWindow: '15m',
        keyGenerator: req => req.body?.identifier || req.ip
      }
    }
  }, async (req, reply) => {
    const schema = z.object({ identifier: z.string().min(1) })
    const { identifier } = schema.parse(req.body)

    const result = await fastify.pg.query(`
      SELECT email, is_verified FROM users
      WHERE email = $1 OR username = $1
    `, [identifier.toLowerCase()])

    const user = result.rows[0]
    if (!user) return reply.code(400).send({ error: 'User not found' })
    if (user.is_verified) return reply.code(400).send({ error: 'User already verified' })

    const token = randomBytes(32).toString('hex')
    await fastify.pg.query(`
      UPDATE users SET verification_token = $1 WHERE email = $2
    `, [token, user.email])

    await sendVerificationEmail(user.email, token)
    return reply.send({ message: 'Verification email resent' })
  })

  // 🔐 LOGIN
  fastify.post('/login', {
    config: {
      rateLimit: {
        max: 5,
        timeWindow: '10m',
        keyGenerator: req => req.body?.identifier || req.ip
      }
    }
  }, async (req, reply) => {
    const schema = z.object({
      identifier: z.string(),
      password: z.string().min(6)
    })
    const { identifier, password } = schema.parse(req.body)

    const result = await fastify.pg.query(`
      SELECT * FROM users WHERE email=$1 OR username=$1
    `, [identifier])
    const user = result.rows[0]

    if (!user) return reply.code(400).send({ error: 'Invalid credentials' })
    if (!user.is_verified) return reply.code(401).send({ error: 'Email not verified' })

    const valid = await bcrypt.compare(password, user.password)
    if (!valid) return reply.code(400).send({ error: 'Invalid credentials' })

    const token = fastify.jwt.sign({ id: user.id }, { expiresIn: '7d' })

    reply.setCookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Lax',
      path: '/',
      maxAge: 7 * 24 * 60 * 60
    }).send({
      user: {
        id: user.id,
        name: `${user.first_name} ${user.last_name}`,
        username: user.username,
        email: user.email
      }
    })
  })

  // 🔁 FORGOT PASSWORD
  fastify.post('/forgot-password', {
    config: {
      rateLimit: {
        max: 3,
        timeWindow: '15m',
        keyGenerator: req => req.body?.email || req.ip
      }
    }
  }, async (req, reply) => {
    const schema = z.object({ email: z.string().email() })
    const { email } = schema.parse(req.body)

    const user = await fastify.pg.query(`SELECT id FROM users WHERE email=$1`, [email])
    if (!user.rows.length) return reply.code(400).send({ error: 'User not found' })

    const token = randomBytes(32).toString('hex')
    const expiry = new Date(Date.now() + 15 * 60 * 1000)

    await fastify.pg.query(`
      UPDATE users SET reset_token=$1, reset_token_expires=$2 WHERE email=$3
    `, [token, expiry, email])

    await sendResetPasswordEmail(email, token)
    reply.send({ message: 'Reset link sent to email' })
  })

  // 🔑 RESET PASSWORD
  fastify.post('/reset-password', {
    config: {
      rateLimit: {
        max: 5,
        timeWindow: '10m',
        keyGenerator: req => req.body?.token || req.ip
      }
    }
  }, async (req, reply) => {
    const schema = z.object({
      token: z.string(),
      password: z.string().min(6)
    })
    const { token, password } = schema.parse(req.body)

    const result = await fastify.pg.query(`
      SELECT id FROM users WHERE reset_token=$1 AND reset_token_expires > NOW()
    `, [token])
    if (!result.rows.length) return reply.code(400).send({ error: 'Token invalid or expired' })

    const hash = await bcrypt.hash(password, 10)
    await fastify.pg.query(`
      UPDATE users SET password=$1, reset_token=NULL, reset_token_expires=NULL
      WHERE reset_token=$2
    `, [hash, token])

    reply.send({ message: 'Password reset successful' })
  })

  // 🔒 GET CURRENT USER
  fastify.get('/me', { preHandler: fastify.auth }, async (req, reply) => {
    const { id } = req.user
    const result = await fastify.pg.query(`
      SELECT id, username, email, first_name, last_name FROM users WHERE id=$1
    `, [id])
    if (!result.rows.length) return reply.code(401).send({ error: 'User not found' })
    reply.send(result.rows[0])
  })

  // 🔧 UPDATE PROFILE
  fastify.put('/me', { preHandler: fastify.auth }, async (req, reply) => {
    const schema = z.object({
      first_name: z.string().min(2),
      last_name: z.string().min(2),
      username: z.string().min(3).regex(/^[a-zA-Z0-9_]+$/)
    })
    const body = schema.parse(req.body)
    const { id } = req.user

    const existing = await fastify.pg.query(`
      SELECT id FROM users WHERE username=$1 AND id != $2
    `, [body.username, id])
    if (existing.rows.length) return reply.code(400).send({ error: 'Username already taken' })

    await fastify.pg.query(`
      UPDATE users SET first_name=$1, last_name=$2, username=$3 WHERE id=$4
    `, [body.first_name, body.last_name, body.username, id])

    reply.send({ message: 'Profile updated' })
  })

  // 🚪 LOGOUT
  fastify.post('/logout', async (req, reply) => {
    reply.clearCookie('token', {
      path: '/',
      httpOnly: true,
      sameSite: 'Lax',
      secure: process.env.NODE_ENV === 'production'
    })
    reply.send({ message: 'Logged out' })
  })

  // ✅ CHECK USERNAME
  fastify.get('/username-check', async (req, reply) => {
    const username = req.query.username?.toLowerCase()
    if (!username) return reply.code(400).send({ error: 'Missing username' })

    const result = await fastify.pg.query(`SELECT id FROM users WHERE username=$1`, [username])
    reply.send({ available: result.rowCount === 0 })
  })

  // 🌐 GOOGLE OAUTH
  await fastify.register(fastifyOauth2, {
    name: 'googleOAuth2',
    scope: ['profile', 'email'],
    credentials: {
      client: {
        id: process.env.GOOGLE_CLIENT_ID,
        secret: process.env.GOOGLE_CLIENT_SECRET
      },
      auth: fastifyOauth2.GOOGLE_CONFIGURATION
    },
    startRedirectPath: '/auth/google',
    callbackUri: process.env.GOOGLE_REDIRECT_URI
  })

  fastify.get('/api/v1/auth/google/callback', async (req, reply) => {
    const token = await fastify.googleOAuth2.getAccessTokenFromAuthorizationCodeFlow(req)
    const googleUser = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${token.token.access_token}` }
    }).then(res => res.json())

    const email = googleUser.email?.toLowerCase()
    const name = googleUser.name?.split(' ') || []
    const first_name = name[0] || 'Google'
    const last_name = name[1] || 'User'
    const username = email.split('@')[0]

    const result = await fastify.pg.query(`SELECT * FROM users WHERE email=$1`, [email])
    let user = result.rows[0]

    if (!user) {
      const insert = await fastify.pg.query(`
        INSERT INTO users (first_name, last_name, username, email, is_verified)
        VALUES ($1, $2, $3, $4, true)
        RETURNING *
      `, [first_name, last_name, username, email])
      user = insert.rows[0]
    }

    const jwtToken = fastify.jwt.sign({ id: user.id }, { expiresIn: '7d' })

    reply.setCookie('token', jwtToken, {
      httpOnly: true,
      sameSite: 'Lax',
      secure: process.env.NODE_ENV === 'production',
      path: '/',
      maxAge: 7 * 24 * 60 * 60
    }).redirect(`${process.env.FRONTEND_URL}/dashboard`)
  })

  // 🐙 GITHUB OAUTH
  await fastify.register(fastifyOauth2, {
    name: 'githubOAuth2',
    scope: ['user:email'],
    credentials: {
      client: {
        id: process.env.GITHUB_CLIENT_ID,
        secret: process.env.GITHUB_CLIENT_SECRET
      },
      auth: {
        authorizeHost: 'https://github.com',
        authorizePath: '/login/oauth/authorize',
        tokenHost: 'https://github.com',
        tokenPath: '/login/oauth/access_token'
      }
    },
    startRedirectPath: '/auth/github',
    callbackUri: process.env.GITHUB_REDIRECT_URI
  })

  fastify.get('/api/v1/auth/github/callback', async (req, reply) => {
    const token = await fastify.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(req)

    const githubUser = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${token.token.access_token}` }
    }).then(res => res.json())

    const emailsRes = await fetch('https://api.github.com/user/emails', {
      headers: { Authorization: `Bearer ${token.token.access_token}` }
    }).then(res => res.json())

    const primaryEmail = emailsRes.find(e => e.primary && e.verified)?.email
    if (!primaryEmail) return reply.code(400).send({ error: 'GitHub email not found' })

    const email = primaryEmail.toLowerCase()
    const username = githubUser.login.toLowerCase()
    const first_name = githubUser.name?.split(' ')[0] || 'GitHub'
    const last_name = githubUser.name?.split(' ')[1] || 'User'

    const result = await fastify.pg.query(`SELECT * FROM users WHERE email=$1`, [email])
    let user = result.rows[0]

    if (!user) {
      const insert = await fastify.pg.query(`
        INSERT INTO users (first_name, last_name, username, email, is_verified)
        VALUES ($1, $2, $3, $4, true)
        RETURNING *
      `, [first_name, last_name, username, email])
      user = insert.rows[0]
    }

    const jwtToken = fastify.jwt.sign({ id: user.id }, { expiresIn: '7d' })

    reply.setCookie('token', jwtToken, {
      httpOnly: true,
      sameSite: 'Lax',
      secure: process.env.NODE_ENV === 'production',
      path: '/',
      maxAge: 7 * 24 * 60 * 60
    }).redirect(`${process.env.FRONTEND_URL}/dashboard`)
  })
}