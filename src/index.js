import Fastify from 'fastify'
import cors from '@fastify/cors'
import cookie from '@fastify/cookie'
import rateLimit from '@fastify/rate-limit'
import dotenv from 'dotenv'

import db from './plugins/db.js'
import jwt from './plugins/jwt.js'

import authRoutes from './routes/auth.js'
import statsRoutes from './routes/stats.js'
import settingsRoutes from './routes/settings.js'
import adminRoutes from './plugins/admin.js'
import profileRoutes from './routes/profile.js'
import followRoutes from './routes/follow.js'
import userRoutes from './routes/userRoutes.js'
import startupRoutes from './routes/startups.js'

dotenv.config()

async function start() {
  const fastify = Fastify({
    logger: true,
    trustProxy: true
  })

  await fastify.register(cors, {
    origin: (origin, cb) => {
      const allowedOrigins = [process.env.FRONTEND_URL || 'http://localhost:5173']
      if (!origin || allowedOrigins.includes(origin)) {
        cb(null, true)
      } else {
        cb(new Error('Not allowed by CORS'), false)
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
  })

  await fastify.register(cookie, {
    secret: process.env.COOKIE_SECRET || 'your_cookie_secret',
    hook: 'onRequest'
  })

  await fastify.register(rateLimit, {
    global: false
  })

  await fastify.register(db)
  await fastify.register(jwt)

  await fastify.register(authRoutes)
  await fastify.register(statsRoutes)
  await fastify.register(adminRoutes)
  await fastify.register(profileRoutes)
  await fastify.register(settingsRoutes, { prefix: '/api' })
  await fastify.register(followRoutes)
  await fastify.register(userRoutes)
  await fastify.register(startupRoutes)

  fastify.get('/ping', async () => ({
    status: 'ok',
    time: new Date().toISOString()
  }))

  const PORT = process.env.PORT || 5000
  const HOST = process.env.HOST || '0.0.0.0'

  try {
    await fastify.listen({ port: PORT, host: HOST })
    console.log(`🚀 Server ready at http://${HOST}:${PORT}`)
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}

start()