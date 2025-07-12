export default async function followRoutes(fastify) {
  // ✅ GET: Publicly accessible stats (NO auth)
  // ✅ Public follower/following counts
fastify.get('/follow/stats/:username', async (req, reply) => {
  const { username } = req.params

  // First get the user's ID
  const { rows: userRows } = await fastify.pg.query(
    `SELECT id FROM users WHERE username = $1`,
    [username]
  )
  if (!userRows.length) {
    return reply.code(404).send({ error: 'User not found' })
  }

  const userId = userRows[0].id

  // Count followers and following
  const { rows } = await fastify.pg.query(
    `
    SELECT
      (SELECT COUNT(*) FROM follows WHERE following_id = $1) AS followers,
      (SELECT COUNT(*) FROM follows WHERE follower_id = $1) AS following
    `,
    [userId]
  )

  return rows[0]
})

  // ✅ GET: Check if logged-in user follows someone
  fastify.get('/follow/:username', async (req, reply) => {
    try {
      await req.jwtVerify()
    } catch {
      return reply.code(401).send({ error: 'Unauthorized' })
    }

    const { username } = req.params

    const { rows } = await fastify.pg.query(
      `SELECT 1 FROM follows
       JOIN users u ON u.id = follows.following_id
       WHERE u.username = $1 AND follows.follower_id = $2`,
      [username, req.user.id]
    )

    return { following: rows.length > 0 }
  })

  // ✅ POST: Follow someone
  fastify.post('/follow/:username', async (req, reply) => {
    try {
      await req.jwtVerify()
    } catch {
      return reply.code(401).send({ error: 'Unauthorized' })
    }

    const { username } = req.params

    const { rows: targetRows } = await fastify.pg.query(
      `SELECT id FROM users WHERE username = $1`,
      [username]
    )
    if (!targetRows[0]) return reply.code(404).send({ error: 'User not found' })

    const followingId = targetRows[0].id
    if (followingId === req.user.id)
      return reply.code(400).send({ error: 'Cannot follow yourself' })

    try {
      await fastify.pg.query(
        `INSERT INTO follows (follower_id, following_id)
         VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [req.user.id, followingId]
      )
      return { success: true }
    } catch (err) {
      fastify.log.error(err)
      return reply.code(500).send({ error: 'Failed to follow user' })
    }
  })

  // ✅ DELETE: Unfollow
  fastify.delete('/follow/:username', async (req, reply) => {
    try {
      await req.jwtVerify()
    } catch {
      return reply.code(401).send({ error: 'Unauthorized' })
    }

    const { username } = req.params
    const { rows: targetRows } = await fastify.pg.query(
      `SELECT id FROM users WHERE username = $1`,
      [username]
    )
    if (!targetRows[0]) return reply.code(404).send({ error: 'User not found' })

    const followingId = targetRows[0].id

    try {
      await fastify.pg.query(
        `DELETE FROM follows
         WHERE follower_id = $1 AND following_id = $2`,
        [req.user.id, followingId]
      )
      return { success: true }
    } catch (err) {
      fastify.log.error(err)
      return reply.code(500).send({ error: 'Failed to unfollow user' })
    }
  })
}