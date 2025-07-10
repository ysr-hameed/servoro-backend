export default async function statsRoutes(fastify) {
  fastify.get('/stats', async (req, reply) => {
    try {
      const { rows } = await fastify.pg.query(`
        SELECT 
          COUNT(*)::int AS total_users,
          COUNT(*) FILTER (WHERE is_verified = true)::int AS verified_users
        FROM users
      `)

      return {
        total_users: rows[0].total_users,
        verified_users: rows[0].verified_users
      }
    } catch (err) {
      req.log.error(err)
      return reply.code(500).send({ error: 'Failed to fetch stats' })
    }
  })
}