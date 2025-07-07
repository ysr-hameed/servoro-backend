import Fastify from 'fastify'
import cors from '@fastify/cors'
import cookie from '@fastify/cookie' // ✅ import cookie plugin
import db from './plugins/db.js'
import jwt from './plugins/jwt.js'
import authRoutes from './routes/auth.js'
import dotenv from 'dotenv'
dotenv.config()

const fastify = Fastify({ logger: true })

// ✅ Register CORS with credentials
await fastify.register(cors, {
  origin: process.env.FRONTEND_URL || 'http://localhost:3000', // allow only your frontend
  credentials: true
})

// ✅ Register cookie plugin
await fastify.register(cookie, {
  secret: process.env.COOKIE_SECRET || 'your_cookie_secret', // optional: for signed cookies
  hook: 'onRequest'
})

await fastify.register(db)
await fastify.register(jwt)
await fastify.register(authRoutes)

fastify.listen({ port: process.env.PORT || 5000 }, (err, address) => {
  if (err) throw err
  console.log(`🚀 Server ready at ${address}`)
})