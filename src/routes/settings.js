export default async function (fastify, opts) {
  // GET settings
  fastify.get('/settings/app', async (req, reply) => {
    const { rows } = await fastify.pg.query('SELECT * FROM app_settings LIMIT 1')
    return rows[0]
  })

  // POST to update settings
  fastify.post('/settings/app', async (req, reply) => {
    const {
      app_name,
      tagline,
      description,
      favicon_url,
      logo_url,
      light_primary_color,
      dark_primary_color,
      support_email,
      contact_phone,
      default_language,
      maintenance_mode
    } = req.body

    const result = await fastify.pg.query('SELECT id FROM app_settings LIMIT 1')

    if (result.rowCount === 0) {
      await fastify.pg.query(`
        INSERT INTO app_settings (
          app_name, tagline, description, favicon_url, logo_url,
          light_primary_color, dark_primary_color, 
          support_email, contact_phone, default_language, maintenance_mode
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      `, [
        app_name,
        tagline,
        description,
        favicon_url,
        logo_url,
        light_primary_color,
        dark_primary_color,
        support_email,
        contact_phone,
        default_language,
        maintenance_mode
      ])
    } else {
      await fastify.pg.query(`
        UPDATE app_settings SET
          app_name = $1,
          tagline = $2,
          description = $3,
          favicon_url = $4,
          logo_url = $5,
          light_primary_color = $6,
          dark_primary_color = $7,
          support_email = $8,
          contact_phone = $9,
          default_language = $10,
          maintenance_mode = $11,
          updated_at = NOW()
      `, [
        app_name,
        tagline,
        description,
        favicon_url,
        logo_url,
        light_primary_color,
        dark_primary_color,
        support_email,
        contact_phone,
        default_language,
        maintenance_mode
      ])
    }

    return { success: true }
  })
}