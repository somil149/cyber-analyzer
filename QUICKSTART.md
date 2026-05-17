# Quick Start: Cloud Deployment

## Prerequisites
- GitHub account
- Cloudflare account (free)
- Railway account (free) or Render account (free)

## Quick Deployment Steps

### 1. Push to GitHub (5 minutes)
```bash
cd C:\Users\AVNI\projects\cyber
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/cyber-analyzer.git
git push -u origin main
```

### 2. Deploy Backend to Railway (5 minutes)
1. Go to https://railway.app
2. Sign up with GitHub
3. Click "New Project" → "Deploy from GitHub repo"
4. Select `cyber-analyzer` repository
5. Set root directory to `backend/`
6. Click "Deploy"
7. Add environment variables:
   - `OPENAI_API_KEY` = Your OpenAI API key
   - `SEMGREP_APP_TOKEN` = Your Semgrep token
   - `ENVIRONMENT` = `production`
8. Copy the Railway URL (e.g., `https://cyber-analyzer-backend-production.up.railway.app`)

### 3. Deploy Cloudflare Worker (5 minutes)
1. Install Wrangler: `npm install -g wrangler`
2. Login: `wrangler login`
3. Create KV namespace: `wrangler kv:namespace create "CYBER_ANALYZER_CACHE"`
4. Update `cloudflare-worker/wrangler.toml`:
   - Replace `your-kv-namespace-id` with the KV namespace ID
   - Replace `your-backend-url.railway.app` with your Railway URL
5. Deploy: `cd cloudflare-worker && npm install && wrangler deploy`
6. Copy the Worker URL (e.g., `https://cyber-analyzer-api-gateway.YOUR_SUBDOMAIN.workers.dev`)

### 4. Deploy Frontend to Cloudflare Pages (5 minutes)
1. Build frontend: `cd frontend && npm install && npm run build`
2. Deploy: `npx wrangler pages deploy ./out --project-name=cyber-analyzer`
3. Copy the Pages URL (e.g., `https://cyber-analyzer.pages.dev`)

### 5. Test (2 minutes)
1. Open your Cloudflare Pages URL in browser
2. Test all three modes (File, URL, Website)
3. Verify security analysis works

## Total Time: ~20-25 minutes

## Architecture
```
User → Cloudflare Pages → Cloudflare Workers → Railway Backend
```

## Cost
- **Free tier**: $0/month
- **After free credits**: ~$5-7/month

## Support
- Railway: https://docs.railway.app
- Cloudflare: https://developers.cloudflare.com
- Cloudflare Pages: https://developers.cloudflare.com/pages