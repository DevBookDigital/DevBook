module.exports = {
  name: 'add_clonepoint_projects',
  up: async (client) => {
    await client.query(`
      CREATE TABLE IF NOT EXISTS clonepoint_projects (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        spec_url TEXT,
        spec_data JSONB,
        endpoints_count INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS clonepoint_projects_user_id_idx ON clonepoint_projects(user_id)
    `);
  }
};
