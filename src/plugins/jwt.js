// src/plugins/jwt.js
import fp from 'fastify-plugin'
import fastifyJwt from '@fastify/jwt'
import dotenv from 'dotenv'
dotenv.config()
export default fp(async function (fastify, opts) {
  fastify.register(fastifyJwt, {
    secret: process.env.JWT_SECRET,
    cookie: {
      cookieName: 'token',
      signed: false
    }
  })

  fastify.decorate('auth', async function (request, reply) {
    try {
      await request.jwtVerify()
    } catch (err) {
      reply.code(401).send({ error: 'Unauthorized' })
    }
  })
})