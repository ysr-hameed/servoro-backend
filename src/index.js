import Fastify from 'fastify'
import cors from '@fastify/cors'
import cookie from '@fastify/cookie'
import rateLimit from '@fastify/rate-limit'
import dotenv from 'dotenv'
import db from './plugins/db.js'
import jwt from './plugins/jwt.js'
import authRoutes from './routes/auth.js'

// ✅ Load environment variables
dotenv.config()

// ✅ Create Fastify instance with logger enabled
const fastify = Fastify({ logger: true })


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
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
})

// ✅ Enable cookie 
await fastify.register(cookie, {
  secret: process.env.COOKIE_SECRET || 'your_cookie_secret',
  hook: 'onRequest'
})

// ✅ Rate limit (disabled globally, can be used per route)
await fastify.register(rateLimit, {
  global: false
})

// ✅ Register custom plugins
await fastify.register(db)
await fastify.register(jwt)

// ✅ Register routes
await fastify.register(authRoutes)

fastify.get('/ping', async (request, reply) => {
  return { status: 'ok', time: new Date().toISOString() }
})

const PORT = process.env.PORT || 5000
const HOST = process.env.HOST || '0.0.0.0' 

fastify.listen({ port: PORT, host: HOST }, (err, address) => {
  if (err) {
    fastify.log.error(err)
    process.exit(1)
  }
  console.log(`🚀 Server ready at ${address}`)
})