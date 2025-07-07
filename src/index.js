import Fastify from 'fastify';
import cors from '@fastify/cors';
import dotenv from 'dotenv';
import db from './plugins/db.js';
import jwt from './plugins/jwt.js';
import authRoutes from './routes/auth.js';

dotenv.config();

const fastify = Fastify({ logger: true });

await fastify.register(cors, { origin: '*' });
await fastify.register(db);
await fastify.register(jwt);
await fastify.register(authRoutes);

fastify.listen({ port: process.env.PORT }, (err, address) => {
  if (err) throw err;
  console.log(`🚀 Server ready at ${address}`);
});