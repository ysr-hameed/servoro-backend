import { z } from 'zod'

export default async function (fastify, opts) {
  // ✅ Get notifications (global + personal, with read tracking)
  fastify.get('/notifications', { preHandler: [fastify.auth] }, async (req, reply) => {
    const userId = req.user.id
    const { rows } = await fastify.pg.query(
      `SELECT n.id, n.title, n.message, n.created_at,
              CASE WHEN r.notification_id IS NOT NULL THEN true ELSE false END AS is_read
       FROM notifications n
       LEFT JOIN notification_reads r ON r.notification_id = n.id AND r.user_id = $1
       WHERE n.user_id = $1 OR n.user_id IS NULL
       ORDER BY n.created_at DESC`,
      [userId]
    )
    reply.send({ notifications: rows })
  })

  // ✅ Unread count
  fastify.get('/notifications/unread-count', { preHandler: [fastify.auth] }, async (req, reply) => {
    const userId = req.user.id
    const { rows } = await fastify.pg.query(
      `SELECT COUNT(*) FROM notifications n
       LEFT JOIN notification_reads r ON r.notification_id = n.id AND r.user_id = $1
       WHERE (n.user_id = $1 OR n.user_id IS NULL) AND r.notification_id IS NULL`,
      [userId]
    )
    reply.send({ count: parseInt(rows[0].count, 10) })
  })

  // ✅ Mark as read (insert into tracking table)
  fastify.post('/notifications/:id/read', { preHandler: [fastify.auth] }, async (req, reply) => {
    const notificationId = req.params.id
    const userId = req.user.id

    // Prevent duplicate reads
    const check = await fastify.pg.query(
      `SELECT 1 FROM notifications 
       WHERE id = $1 AND (user_id = $2 OR user_id IS NULL)`,
      [notificationId, userId]
    )

    if (check.rowCount === 0) {
      return reply.code(404).send({ error: 'Notification not found' })
    }

    await fastify.pg.query(
      `INSERT INTO notification_reads (user_id, notification_id)
       VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [userId, notificationId]
    )

    reply.send({ success: true })
  })

  // ✅ Admin: Send notification to selected or all users
  fastify.post('/admin/notifications', { preHandler: [fastify.adminAuth] }, async (req, reply) => {
    const schema = z.object({
      title: z.string().min(1, 'Title is required'),
      message: z.string().min(1, 'Message is required'),
      targets: z.array(z.string()).optional()
    })

    const result = schema.safeParse(req.body)
    if (!result.success) {
      return reply.code(400).send({ error: result.error.format() })
    }

    const { title, message, targets = [] } = result.data

    let users = []
    if (targets.length === 0) {
      const res = await fastify.pg.query('SELECT id FROM users WHERE is_blocked = false')
      users = res.rows.map(r => r.id)
    } else {
      const placeholders = targets.map((_, i) => `$${i + 1}`).join(',')
      const res = await fastify.pg.query(
        `SELECT id FROM users WHERE username IN (${placeholders}) OR email IN (${placeholders})`,
        [...targets, ...targets]
      )
      users = res.rows.map(r => r.id)
    }

    for (const userId of users) {
      await fastify.pg.query(
        `INSERT INTO notifications (user_id, title, message, created_at)
         VALUES ($1, $2, $3, NOW())`,
        [userId, title, message]
      )
    }

    return { success: true, sent: users.length }
  })
}