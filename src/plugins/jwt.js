import fp from 'fastify-plugin'
import fastifyJwt from '@fastify/jwt'
import dotenv from 'dotenv'

dotenv.config()

export default fp(async function (fastify, opts) {
  // ✅ Register JWT with cookie support
  fastify.register(fastifyJwt, {
    secret: process.env.JWT_SECRET,
    cookie: {
      cookieName: 'token',
      signed: false
    }
  })

  // ✅ General user auth middleware
  fastify.decorate('auth', async function (request, reply) {
    try {
      request.user = await request.jwtVerify()
    } catch {
      return reply.code(401).send({ error: 'Unauthorized' })
    }
  })

  // ✅ Admin-only auth middleware
  fastify.decorate('adminAuth', async function (request, reply) {
    try {
      const user = await request.jwtVerify()
      if (!user.is_admin) {
        return reply.code(403).send({ error: 'Admin access only' })
      }
      request.user = user
    } catch {
      return reply.code(401).send({ error: 'Unauthorized' })
    }
  })
})