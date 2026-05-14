# DevBook

A modern API workbench for developers — browser-based, with API key vault, template builder, and split-screen response viewer.

## Requirements

- Node.js 18+
- PostgreSQL database (Neon recommended)

## Environment Variables

- `DATABASE_URL` - PostgreSQL connection string (required)
- `PORT` - Server port (default: 3000)
- `JWT_SECRET` - Secret for JWT signing (auto-generated if not set, but set one for production)
- `ENCRYPTION_KEY` - Key for encrypting API keys at rest (defaults to JWT_SECRET)

## Endpoints

- `GET /` - Landing page
- `GET /login` - Auth page (sign in / sign up)
- `GET /app` - Main application
- `GET /health` - Health check (verifies database connection)

## Local Development

```bash
npm install
DATABASE_URL="postgresql://..." npm run dev
```

## Deployment (Render)

This project is configured for Render deployment via `render.yaml`.

1. Push this repo to GitHub
2. Connect the repo in Render dashboard
3. Set `DATABASE_URL` environment variable to your Neon connection string
4. Set `JWT_SECRET` to a random 64-character string
5. Deploy

## Domain

Production: https://devbook.digital
