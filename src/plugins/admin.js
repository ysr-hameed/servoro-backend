import fp from 'fastify-plugin'

export default fp(async function (fastify, opts) {
  // ✅ Admin Auth Middleware
  fastify.decorate('isAdmin', async (req, reply) => {
    try {
      const token = req.cookies.token
      if (!token) return reply.code(401).send({ error: 'Unauthorized' })

      const decoded = fastify.jwt.verify(token)
      if (!decoded.is_admin) return reply.code(403).send({ error: 'Forbidden' })

      req.user = decoded
    } catch (err) {
      return reply.code(401).send({ error: 'Invalid token' })
    }
  })

  // ✅ GET /admin/settings
  fastify.get('/admin/settings', { preHandler: fastify.isAdmin }, async (req, reply) => {
    const res = await fastify.pg.query('SELECT * FROM app_settings LIMIT 1')
    reply.send(res.rows[0])
  })

  // ✅ PUT /admin/settings
  fastify.put('/admin/settings', { preHandler: fastify.isAdmin }, async (req, reply) => {
    const {
      app_name,
      tagline,
      description,
      light_primary_color,
      dark_primary_color,
      theme_mode,
      support_email,
      contact_phone,
      default_language,
      maintenance_mode,
      favicon_url,
      logo_url
    } = req.body

    await fastify.pg.query(`
      UPDATE app_settings SET
        app_name = $1,
        tagline = $2,
        description = $3,
        light_primary_color = $4,
        dark_primary_color = $5,
        theme_mode = $6,
        support_email = $7,
        contact_phone = $8,
        default_language = $9,
        maintenance_mode = $10,
        favicon_url = $11,
        logo_url = $12,
        updated_at = CURRENT_TIMESTAMP
    `, [
      app_name,
      tagline,
      description,
      light_primary_color,
      dark_primary_color,
      theme_mode,
      support_email,
      contact_phone,
      default_language,
      maintenance_mode,
      favicon_url,
      logo_url
    ])

    reply.send({ success: true })
  })

  // ✅ GET /admin/users with filters and pagination
  fastify.get('/admin/users', { preHandler: fastify.isAdmin }, async (req, reply) => {
    const {
      page = 1,
      limit = 20,
      search = '',
      is_verified,
      is_blocked,
      is_admin
    } = req.query

    const offset = (page - 1) * limit
    const values = []
    const conditions = []
    let i = 1

    if (search) {
      conditions.push(`(username ILIKE $${i} OR email ILIKE $${i})`)
      values.push(`%${search}%`)
      i++
    }

    if (typeof is_verified === 'string' && (is_verified === 'true' || is_verified === 'false')) {
      conditions.push(`is_verified = $${i++}`)
      values.push(is_verified === 'true')
    }

    if (typeof is_blocked === 'string' && (is_blocked === 'true' || is_blocked === 'false')) {
      conditions.push(`is_blocked = $${i++}`)
      values.push(is_blocked === 'true')
    }

    if (typeof is_admin === 'string' && (is_admin === 'true' || is_admin === 'false')) {
      conditions.push(`is_admin = $${i++}`)
      values.push(is_admin === 'true')
    }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : ''

    const countRes = await fastify.pg.query(`SELECT COUNT(*) FROM users ${where}`, values)
    const total = parseInt(countRes.rows[0].count)

    const dataRes = await fastify.pg.query(`
      SELECT id, first_name, last_name, username, email, provider,
             is_admin, is_verified, is_blocked, created_at
      FROM users
      ${where}
      ORDER BY created_at DESC
      LIMIT $${i++} OFFSET $${i++}
    `, [...values, limit, offset])

    reply.send({
      total,
      page: Number(page),
      limit: Number(limit),
      users: dataRes.rows
    })
  })

  // ✅ PATCH /admin/users/:id (update is_admin / is_blocked)
  fastify.patch('/admin/users/:id', { preHandler: fastify.isAdmin }, async (req, reply) => {
    const { id } = req.params
    const fields = []
    const values = []
    let i = 1

    if ('is_admin' in req.body) {
      fields.push(`is_admin = $${i++}`)
      values.push(req.body.is_admin)
    }

    if ('is_blocked' in req.body) {
      fields.push(`is_blocked = $${i++}`)
      values.push(req.body.is_blocked)
    }

    if (fields.length === 0) {
      return reply.code(400).send({ error: 'No valid fields to update' })
    }

    values.push(id)
    const query = `UPDATE users SET ${fields.join(', ')} WHERE id = $${i}`
    await fastify.pg.query(query, values)

    reply.send({ success: true })
  })

  // ✅ DELETE /admin/users/:id
  fastify.delete('/admin/users/:id', { preHandler: fastify.isAdmin }, async (req, reply) => {
    const { id } = req.params
    await fastify.pg.query('DELETE FROM users WHERE id = $1', [id])
    reply.send({ success: true })
  })

  // ✅ GET /admin/overview
  fastify.get('/admin/overview', { preHandler: fastify.isAdmin }, async (req, reply) => {
    const result = await fastify.pg.query(`
      SELECT
        (SELECT COUNT(*) FROM users) AS total_users,
        (SELECT COUNT(*) FROM users WHERE is_verified = true) AS verified_users,
        (SELECT COUNT(*) FROM users WHERE is_blocked = true) AS blocked_users,
        (SELECT COUNT(*) FROM users WHERE is_admin = true) AS admin_users,
        (SELECT maintenance_mode FROM app_settings LIMIT 1),
        (SELECT updated_at FROM app_settings LIMIT 1)
    `)

    reply.send(result.rows[0])
  })
  fastify.get('/admin/users/:id', { preHandler: fastify.isAdmin }, async (req, reply) => {
  const { id } = req.params

  try {
    const result = await fastify.pg.query(`
      SELECT id, first_name, last_name, username, email, provider,
             is_verified, is_blocked, is_admin, created_at
      FROM users
      WHERE id = $1
    `, [id])

    if (result.rowCount === 0) {
      return reply.code(404).send({ error: 'User not found' })
    }

    reply.send(result.rows[0])
  } catch (err) {
    req.log.error(err)
    reply.code(500).send({ error: 'Failed to fetch user' })
  }
})
  
  
  
  
  
})