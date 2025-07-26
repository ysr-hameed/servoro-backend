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

  // ✅ Ensure default app_settings row exists
  fastify.addHook('onReady', async () => {
    const check = await fastify.pg.query('SELECT COUNT(*) FROM app_settings')
    if (parseInt(check.rows[0].count) === 0) {
      await fastify.pg.query(`
  INSERT INTO app_settings (
    id, app_name, tagline, description,
    light_primary_color, dark_primary_color, 
    support_email, contact_phone, default_language,
    maintenance_mode, favicon_url, logo_url, updated_at
  ) VALUES (
    1, 'StartNet', '', '', '#4f46e5', '#0f172a',
    '', '', 'en', false, '', '', CURRENT_TIMESTAMP
  )
`)
      fastify.log.info('✅ Inserted default app_settings row')
    }
  })

  // ✅ GET /admin/settings
  fastify.get('/admin/settings', { preHandler: fastify.isAdmin }, async (req, reply) => {
    const res = await fastify.pg.query('SELECT * FROM app_settings LIMIT 1')
    reply.send(res.rows[0])
  })

  // ✅ PUT /admin/settings
  fastify.put('/admin/settings', {
    preHandler: fastify.isAdmin,
    schema: {
      body: {
        type: 'object',
        required: ['app_name'],
        properties: {
          app_name: { type: 'string' },
          tagline: { type: 'string' },
          description: { type: 'string' },
          light_primary_color: { type: 'string' },
          dark_primary_color: { type: 'string' },
          
          support_email: { type: 'string' },
          contact_phone: { type: 'string' },
          default_language: { type: 'string' },
          maintenance_mode: { type: 'boolean' },
          favicon_url: { type: 'string' },
          logo_url: { type: 'string' }
        }
      }
    }
  }, async (req, reply) => {
    const {
      app_name, tagline, description,
      light_primary_color, dark_primary_color, 
      support_email, contact_phone, default_language,
      maintenance_mode, favicon_url, logo_url
    } = req.body

    await fastify.pg.query(`
      UPDATE app_settings SET
        app_name = $1,
        tagline = $2,
        description = $3,
        light_primary_color = $4,
        dark_primary_color = $5,
        support_email = $6,
        contact_phone = $7,
        default_language = $8,
        maintenance_mode = $9,
        favicon_url = $10,
        logo_url = $11,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = 1
    `, [
      app_name, tagline, description,
      light_primary_color, dark_primary_color, 
      support_email, contact_phone, default_language,
      maintenance_mode, favicon_url, logo_url
    ])

    fastify.log.info(`🛠️ Admin ${req.user.email} updated app settings`)
    reply.send({ success: true })
  })

  // ✅ GET /admin/users (with filters)
  fastify.get('/admin/users', { preHandler: fastify.isAdmin }, async (req, reply) => {
    const {
      page = 1, limit = 20, search = '',
      is_verified, is_blocked, is_admin
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

    if (typeof is_verified === 'string') {
      conditions.push(`is_verified = $${i++}`)
      values.push(is_verified === 'true')
    }

    if (typeof is_blocked === 'string') {
      conditions.push(`is_blocked = $${i++}`)
      values.push(is_blocked === 'true')
    }

    if (typeof is_admin === 'string') {
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

  // ✅ GET /admin/users/:id
  fastify.get('/admin/users/:id', { preHandler: fastify.isAdmin }, async (req, reply) => {
  const { id } = req.params

  try {
    const result = await fastify.pg.query(`
      SELECT id, first_name, last_name, username, email, provider,
             is_verified, is_blocked, is_admin, created_at, updated_at
      FROM users
      WHERE id = $1
    `, [id])

    if (result.rowCount === 0) {
      return reply.code(404).send({ error: 'User not found' })
    }

    return reply.send({
      data: result.rows[0] // ✅ wrap in structured format
    })

  } catch (err) {
    fastify.log.error(err)
    return reply.code(500).send({ error: 'Internal server error' })
  }
})
  // ✅ PATCH /admin/users/:id
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

    if (!fields.length) {
      return reply.code(400).send({ error: 'No valid fields to update' })
    }

    values.push(id)
    await fastify.pg.query(`UPDATE users SET ${fields.join(', ')} WHERE id = $${i}`, values)

    fastify.log.info(`🔧 Admin ${req.user.email} updated user ${id}`)
    reply.send({ success: true })
  })

  // ✅ DELETE /admin/users/:id
  fastify.delete('/admin/users/:id', { preHandler: fastify.isAdmin }, async (req, reply) => {
  const { id } = req.params
  await fastify.pg.query('DELETE FROM users WHERE id = $1', [id])
  fastify.log.info(`🗑️ Admin ${req.user.email} deleted user ${id}`)
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
})