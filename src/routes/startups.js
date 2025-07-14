export default async function startupRoutes(fastify) {
  // Create a startup
  fastify.post('/startups', { preHandler: [fastify.auth] }, async (req, reply) => {
    try {
      const userId = req.user.id;
      const {
        name, tagline, industry, description,
        tech_stack, mvp_stage, is_public = false, logo_url
      } = req.body;

      const { rows } = await fastify.pg.query(
        `INSERT INTO startups (
          owner_id, name, tagline, industry, description,
          tech_stack, mvp_stage, is_public, logo_url
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
        [userId, name, tagline, industry, description, tech_stack, mvp_stage, is_public, logo_url]
      );

      return reply.code(201).send(rows[0]);
    } catch (err) {
      req.log.error(err);
      return reply.code(500).send({ message: 'Failed to create startup' });
    }
  });

  // Get all startups by current user
  fastify.get('/startups/me', { preHandler: [fastify.auth] }, async (req, reply) => {
    try {
      const { id: userId } = req.user;
      const { rows } = await fastify.pg.query(
        'SELECT * FROM startups WHERE owner_id = $1 ORDER BY created_at DESC',
        [userId]
      );
      return rows;
    } catch (err) {
      req.log.error(err);
      return reply.code(500).send({ message: 'Failed to fetch your startups' });
    }
  });

  // Get a single startup (if public or user is owner)
  fastify.get('/startups/:id', async (req, reply) => {
    try {
      const userId = req.user?.id;
      const { id } = req.params;

      const { rows } = await fastify.pg.query(
        'SELECT * FROM startups WHERE id = $1',
        [id]
      );

      const startup = rows[0];
      if (!startup) return reply.code(404).send({ message: 'Startup not found' });

      if (!startup.is_public && startup.owner_id !== userId) {
        return reply.code(403).send({ message: 'Access denied' });
      }

      return startup;
    } catch (err) {
      req.log.error(err);
      return reply.code(500).send({ message: 'Failed to fetch startup' });
    }
  });

  // Update a startup
  fastify.put('/startups/:id', { preHandler: [fastify.auth] }, async (req, reply) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      const check = await fastify.pg.query('SELECT * FROM startups WHERE id = $1', [id]);
      const startup = check.rows[0];
      if (!startup) return reply.code(404).send({ message: 'Startup not found' });
      if (startup.owner_id !== userId) return reply.code(403).send({ message: 'Unauthorized' });

      const {
        name, tagline, industry, description,
        tech_stack, mvp_stage, is_public, logo_url
      } = req.body;

      const { rows } = await fastify.pg.query(
        `UPDATE startups SET
          name = $1, tagline = $2, industry = $3, description = $4,
          tech_stack = $5, mvp_stage = $6, is_public = $7, logo_url = $8,
          updated_at = NOW()
        WHERE id = $9 RETURNING *`,
        [name, tagline, industry, description, tech_stack, mvp_stage, is_public, logo_url, id]
      );

      return rows[0];
    } catch (err) {
      req.log.error(err);
      return reply.code(500).send({ message: 'Failed to update startup' });
    }
  });

  // Delete a startup
  fastify.delete('/startups/:id', { preHandler: [fastify.auth] }, async (req, reply) => {
    try {
      const userId = req.user.id;
      const { id } = req.params;

      const check = await fastify.pg.query('SELECT * FROM startups WHERE id = $1', [id]);
      const startup = check.rows[0];
      if (!startup) return reply.code(404).send({ message: 'Startup not found' });
      if (startup.owner_id !== userId) return reply.code(403).send({ message: 'Unauthorized' });

      await fastify.pg.query('DELETE FROM startups WHERE id = $1', [id]);
      return { success: true };
    } catch (err) {
      req.log.error(err);
      return reply.code(500).send({ message: 'Failed to delete startup' });
    }
  });

fastify.get('/startups/public', async (req, reply) => {
  try {
    const { page = 1, limit = 10, industry, mvp_stage, sort = 'random' } = req.query
    const offset = (page - 1) * limit
    const values = []
    let where = 'WHERE is_public = true'

    if (industry) {
      values.push(industry)
      where += ` AND industry = $${values.length}`
    }

    if (mvp_stage) {
      values.push(mvp_stage)
      where += ` AND mvp_stage = $${values.length}`
    }

    let orderBy = 'ORDER BY RANDOM()'
    if (sort === 'recent') orderBy = 'ORDER BY created_at DESC'
    else if (sort === 'popular') orderBy = 'ORDER BY views DESC NULLS LAST'

    values.push(limit, offset)

    const { rows } = await fastify.pg.query(
      `SELECT * FROM startups ${where} ${orderBy} LIMIT $${values.length - 1} OFFSET $${values.length}`,
      values
    )

    return rows
  } catch (err) {
    req.log.error(err)
    return reply.code(500).send({ message: 'Failed to fetch startups' })
  }
})



// src/routes/startups.js (inside export default async function)

fastify.get('/startups/search', async (req, reply) => {
  const { keyword = '', page = 1, limit = 10, sort = 'latest' } = req.query;
  const offset = (page - 1) * limit;

  try {
    const values = [];
    let where = `WHERE is_public = true`;
    if (keyword.trim()) {
      values.push(`%${keyword.trim().toLowerCase()}%`);
      where += ` AND (LOWER(name) LIKE $${values.length} OR LOWER(tagline) LIKE $${values.length})`;
    }

    let orderBy = 'created_at DESC';
    if (sort === 'popular') orderBy = 'followers_count DESC'; // if you track it
    else if (sort === 'random') orderBy = 'RANDOM()';

    const query = `
      SELECT * FROM startups
      ${where}
      ORDER BY ${orderBy}
      LIMIT ${limit} OFFSET ${offset}
    `;

    const { rows } = await fastify.pg.query(query, values);
    return reply.send(rows);
  } catch (err) {
    req.log.error(err);
    return reply.code(500).send({ message: 'Search failed' });
  }
});

}