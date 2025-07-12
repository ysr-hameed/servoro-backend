import { z } from 'zod'
import bcrypt from 'bcryptjs'
import { randomBytes } from 'crypto'
import { sendVerificationEmail, sendResetPasswordEmail } from '../utils/mailer.js'
import fastifyOauth2 from '@fastify/oauth2'
import fetch from 'node-fetch'
import dotenv from 'dotenv'
dotenv.config()

function getCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'None', // Needed for cross-site cookies
    path: '/',
    maxAge: 30 * 24 * 60 * 60 // 30 days
  }
}

export default async function (fastify, opts) {
  // 🔐 REGISTER (FORM SIGNUP)
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
    username: z.string().min(3).max(30).regex(/^[a-z0-9_]+$/, {
      message: 'Username must contain only lowercase letters, numbers, and underscores'
    }),
    email: z.string().email(),
    password: z.string().min(6),
  })

  let body
  try {
    body = schema.parse(req.body)
  } catch (err) {
    return reply.code(400).send({ error: 'Invalid input', details: err.errors })
  }

  let { first_name, last_name, username, email, password } = body

  // force lowercase and validate again
  username = username.toLowerCase()

  const [emailCheck, usernameCheck] = await Promise.all([
    fastify.pg.query('SELECT id, provider FROM users WHERE email=$1', [email]),
    fastify.pg.query('SELECT id FROM users WHERE LOWER(username) = $1', [username])
  ])

  const existingByEmail = emailCheck.rows[0]
  const existingByUsername = usernameCheck.rows[0]

  if (existingByEmail) {
    return reply.code(400).send({ error: 'Email already registered with another provider' })
  }

  if (existingByUsername) {
    return reply.code(400).send({ error: 'Username already taken' })
  }

  const hashed = await bcrypt.hash(password, 10)
  const token = randomBytes(32).toString('hex')

  await fastify.pg.query(`
    INSERT INTO users (first_name, last_name, username, email, password, verification_token, provider)
    VALUES ($1, $2, $3, $4, $5, $6, 'form')
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

  let parsed
  try {
    parsed = schema.parse(req.body)
  } catch (err) {
    return reply.code(400).send({ error: 'Invalid input', details: err.errors })
  }

  const { identifier, password } = parsed

  const result = await fastify.pg.query(`
    SELECT * FROM users WHERE email = $1 OR username = $1
  `, [identifier.toLowerCase()])

  const user = result.rows[0]

  if (!user) {
    return reply.code(400).send({ error: 'Invalid credentials' })
  }

  // 🚫 OAuth protection
  if (user.provider !== 'form') {
    return reply.code(403).send({
      error: `This account is registered using ${user.provider}. Please log in using ${user.provider}.`
    })
  }

  if (!user.is_verified) {
    return reply.code(401).send({ error: 'Email not verified' })
  }

  if (user.is_blocked) {
    return reply.code(403).send({ error: 'Your account is blocked' })
  }

  const valid = await bcrypt.compare(password, user.password)
  if (!valid) {
    return reply.code(400).send({ error: 'Invalid credentials' })
  }

  // ✅ Sign JWT
  const token = fastify.jwt.sign({
    id: user.id,
    email: user.email,
    is_admin: user.is_admin
  }, { expiresIn: '30d' })

  // ✅ Set cookie securely
  const isProd = process.env.NODE_ENV === 'production'

  reply.setCookie('token', token, getCookieOptions())

  // ✅ Send user payload to frontend
  reply.send({
    user: {
      id: user.id,
      name: `${user.first_name} ${user.last_name}`,
      username: user.username,
      email: user.email,
      is_admin: user.is_admin
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
    SELECT id, username, email, first_name, last_name, is_admin
    FROM users
    WHERE id = $1
  `, [id])

  if (!result.rows.length) {
    return reply.code(401).send({ error: 'User not found' })
  }

  reply.send(result.rows[0])
})
  // 🔧 UPDATE PROFILE
fastify.put('/me', { preHandler: fastify.auth }, async (req, reply) => {
  try {
    // Schema where last_name is optional and may be empty string
    const schema = z.object({
      first_name: z.string().min(2, 'First name is required'),
      last_name: z.string().optional().nullable(),
      username: z.string().min(3).regex(/^[a-zA-Z0-9_]+$/)
    });

    const body = schema.parse(req.body);
    const { id } = req.user;

    const last_name = body.last_name?.trim() || ''; // allow blank last name

    // Check if username already exists for another user
    const existing = await fastify.pg.query(
      'SELECT id FROM users WHERE username=$1 AND id != $2',
      [body.username, id]
    );
    if (existing.rows.length) {
      return reply.code(400).send({ error: 'Username already taken' });
    }

    // Update user info
    await fastify.pg.query(
      `UPDATE users 
       SET first_name = $1, last_name = $2, username = $3 
       WHERE id = $4`,
      [body.first_name.trim(), last_name, body.username.trim(), id]
    );

    reply.send({ message: 'Profile updated' });
  } catch (err) {
    fastify.log.error(err);
    return reply.code(500).send({ error: 'Server error' });
  }
});
  // 🚪 LOGOUT
  fastify.post('/logout', async (req, reply) => {
  const isProd = process.env.NODE_ENV === 'production'

  reply.clearCookie('token', getCookieOptions())

  return reply.send({ message: 'Logged out successfully' })
})
  // ✅ CHECK USERNAME
  fastify.get('/username-check', async (req, reply) => {
    const username = req.query.username?.toLowerCase()
    if (!username) return reply.code(400).send({ error: 'Missing username' })

    const result = await fastify.pg.query(`SELECT id FROM users WHERE username=$1`, [username])
    reply.send({ available: result.rowCount === 0 })
  })

// ✅ Google OAuth
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
  startRedirectPath: '/api/v1/auth/google',
  callbackUri: process.env.GOOGLE_REDIRECT_URI
})

fastify.get('/api/v1/auth/google/callback', async (req, reply) => {
  try {
    const token = await fastify.googleOAuth2.getAccessTokenFromAuthorizationCodeFlow(req)

    const googleUser = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${token.token.access_token}` }
    }).then(res => res.json())

    const email = googleUser.email?.toLowerCase()
    if (!email) {
      const msg = encodeURIComponent('Google email not found')
      return reply.redirect(`${process.env.FRONTEND_URL}/login?oauth=error&msg=${msg}`)
    }

    const nameParts = googleUser.name?.split(' ') || []
    const first_name = nameParts[0] || 'Google'
    const last_name = nameParts[1] || 'User'
    const rawUsername = email.split('@')[0].toLowerCase().replace(/[^a-z0-9_]/g, '')

    const result = await fastify.pg.query(`SELECT * FROM users WHERE email=$1`, [email])
    let user = result.rows[0]

    if (user) {
      if (user.is_blocked) {
        const msg = encodeURIComponent('Your account is blocked')
        return reply.redirect(`${process.env.FRONTEND_URL}/login?oauth=error&msg=${msg}`)
      }
      if (user.provider !== 'google') {
        const msg = encodeURIComponent(`This email is already registered via ${user.provider}`)
        return reply.redirect(`${process.env.FRONTEND_URL}/login?oauth=error&msg=${msg}`)
      }
    } else {
      let username = rawUsername
      while (true) {
        const check = await fastify.pg.query(`SELECT 1 FROM users WHERE LOWER(username) = $1`, [username])
        if (check.rowCount === 0) break
        const random = Math.floor(10000 + Math.random() * 90000)
        username = `${rawUsername}_${random}`
      }

      const insert = await fastify.pg.query(`
        INSERT INTO users (first_name, last_name, username, email, is_verified, provider)
        VALUES ($1, $2, $3, $4, true, 'google') RETURNING *
      `, [first_name, last_name, username, email])
      user = insert.rows[0]
    }

    const jwtToken = fastify.jwt.sign({ id: user.id }, { expiresIn: '30d' })

    reply.setCookie('token', token, getCookieOptions())

return reply.redirect(`${process.env.FRONTEND_URL}/dashboard?oauth=success`)
  } catch (err) {
    req.log.error(err)
    const msg = encodeURIComponent('Google login failed')
    reply.redirect(`${process.env.FRONTEND_URL}/login?oauth=error&msg=${msg}`)
  }
})


// ✅ GitHub OAuth
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
  startRedirectPath: '/api/v1/auth/github',
  callbackUri: process.env.GITHUB_REDIRECT_URI
})

fastify.get('/api/v1/auth/github/callback', async (req, reply) => {
  try {
    const token = await fastify.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(req)

    const githubUser = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${token.token.access_token}` }
    }).then(res => res.json())

    const emailsRes = await fetch('https://api.github.com/user/emails', {
      headers: { Authorization: `Bearer ${token.token.access_token}` }
    }).then(res => res.json())

    const primaryEmail = emailsRes.find(e => e.primary && e.verified)?.email
    if (!primaryEmail) {
      const msg = encodeURIComponent('GitHub email not found or unverified')
      return reply.redirect(`${process.env.FRONTEND_URL}/login?oauth=error&msg=${msg}`)
    }

    const email = primaryEmail.toLowerCase()
    const rawUsername = githubUser.login.toLowerCase().replace(/[^a-z0-9_]/g, '')
    const first_name = githubUser.name?.split(' ')[0] || 'GitHub'
    const last_name = githubUser.name?.split(' ')[1] || 'User'

    const result = await fastify.pg.query(`SELECT * FROM users WHERE email=$1`, [email])
    let user = result.rows[0]

    if (user) {
      if (user.is_blocked) {
        const msg = encodeURIComponent('Your account is blocked')
        return reply.redirect(`${process.env.FRONTEND_URL}/login?oauth=error&msg=${msg}`)
      }
      if (user.provider !== 'github') {
        const msg = encodeURIComponent(`This email is already registered via ${user.provider}`)
        return reply.redirect(`${process.env.FRONTEND_URL}/login?oauth=error&msg=${msg}`)
      }
    } else {
      let username = rawUsername
      while (true) {
        const check = await fastify.pg.query(`SELECT 1 FROM users WHERE LOWER(username) = $1`, [username])
        if (check.rowCount === 0) break
        const random = Math.floor(10000 + Math.random() * 90000)
        username = `${rawUsername}_${random}`
      }

      const insert = await fastify.pg.query(`
        INSERT INTO users (first_name, last_name, username, email, is_verified, provider)
        VALUES ($1, $2, $3, $4, true, 'github') RETURNING *
      `, [first_name, last_name, username, email])
      user = insert.rows[0]
    }

    const jwtToken = fastify.jwt.sign({ id: user.id }, { expiresIn: '30d' })

    reply.setCookie('token', token, getCookieOptions())

return reply.redirect(`${process.env.FRONTEND_URL}/dashboard?oauth=success`)
  } catch (err) {
    req.log.error(err)
    const msg = encodeURIComponent('GitHub login failed')
    reply.redirect(`${process.env.FRONTEND_URL}/login?oauth=error&msg=${msg}`)
  }
})
}
