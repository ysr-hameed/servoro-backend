// routes/profile.js

export default async function profileRoutes(fastify, opts) {
  
  
  fastify.get('/users/:username', async (req, reply) => {
  const { username } = req.params
  const { rows } = await fastify.pg.query(
    'SELECT id, first_name, last_name, username, email FROM users WHERE LOWER(username) = LOWER($1)',
    [username]
  )
  if (!rows[0]) return reply.code(404).send({ error: 'User not found' })
  return rows[0]
})



}