export default async function (fastify) {
  fastify.get('/users', {
    schema: {
      querystring: {
        type: 'object',
        properties: {
          search: { type: 'string' },
          page: { type: 'integer', default: 1 },
          limit: { type: 'integer', default: 10 }
        },
        required: ['search']
      }
    }
  }, async (request, reply) => {
    const { search, page = 1, limit = 10 } = request.query
    const offset = (page - 1) * limit
    const keyword = `%${search.toLowerCase()}%`

    try {
      const result = await fastify.pg.query(
        `
        SELECT id, username, first_name, last_name
        FROM users
        WHERE 
          LOWER(username) LIKE $1 OR
          LOWER(first_name) LIKE $1 OR
          LOWER(last_name) LIKE $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        `,
        [keyword, limit, offset]
      )

      reply.send({
        users: result.rows,
        has_more: result.rows.length === limit
      })
    } catch (err) {
      fastify.log.error(err)
      reply.code(500).send({ error: 'Search failed' })
    }
  })
}