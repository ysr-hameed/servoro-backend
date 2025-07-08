import Fastify from 'fastify'
import cors from '@fastify/cors'
import cookie from '@fastify/cookie'
import rateLimit from '@fastify/rate-limit'
import db from './plugins/db.js'
import jwt from './plugins/jwt.js'
import authRoutes from './routes/auth.js'
import dotenv from 'dotenv'

dotenv.config()

const fastify = Fastify({ logger: true })

// ✅ CORS – only allow your frontend
await fastify.register(cors, {
  origin: (origin, cb) => {
    const allowedOrigins = [process.env.FRONTEND_URL || 'http://localhost:5173']
    if (!origin || allowedOrigins.includes(origin)) {
      cb(null, true)
    } else {
      cb(new Error('Not allowed'), false)
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
})

// ✅ Cookie parser (signed cookies if needed)
await fastify.register(cookie, {
  secret: process.env.COOKIE_SECRET || 'your_cookie_secret',
  hook: 'onRequest'
})

// ✅ Rate limiting (only on specific routes)
await fastify.register(rateLimit, {
  global: false
})

// ✅ Custom plugins
await fastify.register(db)
await fastify.register(jwt)

// ✅ Auth routes
await fastify.register(authRoutes)

// ✅ Start server
fastify.listen({ port: process.env.PORT || 5000 }, (err, address) => {
  if (err) throw err
  console.log(`🚀 Server ready at ${address}`)
})