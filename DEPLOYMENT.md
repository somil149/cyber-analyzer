# Cybersecurity Analyzer - Cloud Deployment Guide

## Architecture Overview

```
User → Cloudflare Pages (Frontend) → Cloudflare Workers (API Gateway) → Railway/Render (Python Backend)
```

## Deployment Steps

### Step 1: Set up GitHub Repository

1. **Initialize Git repository:**
```bash
cd C:\Users\AVNI\projects\cyber
git init
git add .
git commit -m "Initial commit"
```

2. **Create GitHub repository:**
   - Go to https://github.com/new
   - Create a new repository named `cyber-analyzer`
   - Don't initialize with README (we have files already)
   - Push your code:
```bash
git remote add origin https://github.com/YOUR_USERNAME/cyber-analyzer.git
git branch -M main
git push -u origin main
```

### Step 2: Deploy Backend to Railway (Recommended)

#### Option A: Railway Deployment

1. **Sign up for Railway:**
   - Go to https://railway.app
   - Sign up with GitHub
   - Get $5 free credit

2. **Create new project:**
   - Click "New Project"
   - Click "Deploy from GitHub repo"
   - Select `cyber-analyzer` repository
   - Select the `backend/` directory as root
   - Click "Deploy"

3. **Configure environment variables:**
   - In your Railway project, go to "Variables"
   - Add the following variables:
     ```
     OPENAI_API_KEY=your-openai-api-key
     SEMGREP_APP_TOKEN=your-semgrep-token
     ENVIRONMENT=production
     ```

4. **Get your Railway URL:**
   - Railway will provide a URL like: `https://cyber-analyzer-backend-production.up.railway.app`
   - Copy this URL for later use

#### Option B: Render Deployment

1. **Sign up for Render:**
   - Go to https://render.com
   - Sign up with GitHub
   - Get free tier access

2. **Create new web service:**
   - Click "New +"
   - Select "Web Service"
   - Connect your GitHub repository
   - Set root directory to `backend/`
   - Click "Create Web Service"

3. **Configure environment variables:**
   - In your Render service, go to "Environment"
   - Add the same variables as Railway

4. **Get your Render URL:**
   - Render will provide a URL like: `https://cyber-analyzer-backend.onrender.com`

### Step 3: Deploy Cloudflare Worker API Gateway

1. **Install Wrangler CLI:**
```bash
npm install -g wrangler
```

2. **Login to Cloudflare:**
```bash
wrangler login
```

3. **Create KV namespace for caching:**
```bash
wrangler kv:namespace create "CYBER_ANALYZER_CACHE"
```
Copy the namespace ID and update `cloudflare-worker/wrangler.toml`

4. **Update the backend URL in the Worker:**
   - Edit `cloudflare-worker/index.js`
   - Replace `https://your-backend-url.railway.app` with your actual Railway/Render URL

5. **Deploy the Worker:**
```bash
cd cloudflare-worker
wrangler deploy
```

6. **Note your Worker URL:**
   - It will be something like: `https://cyber-analyzer-api-gateway.YOUR_SUBDOMAIN.workers.dev`

### Step 4: Deploy Frontend to Cloudflare Pages

1. **Install Wrangler CLI** (if not already installed)
```bash
npm install -g wrangler
```

2. **Login to Cloudflare** (if not already logged in)
```bash
wrangler login
```

3. **Build the frontend:**
```bash
cd frontend
npm install
npm run build
```

4. **Deploy to Cloudflare Pages:**
```bash
npx wrangler pages deploy ./out --project-name=cyber-analyzer
```

5. **Configure custom domain (optional):**
   - Go to Cloudflare Dashboard
   - Pages → cyber-analyzer
   - Custom domains → Add domain

### Step 5: Update Cloudflare Worker Configuration

1. **Go to Cloudflare Dashboard**
2. **Workers & Pages → cyber-analyzer-api-gateway**
3. **Settings → Triggers**
4. **Update the backend URL** in the Worker code if needed
5. **Add custom routes** if you want custom domain

### Step 6: Test the Deployment

1. **Test the backend directly:**
   - Visit your Railway/Render URL + `/health`
   - Should return: `{"message":"Cybersecurity Analyzer API"}`

2. **Test the API gateway:**
   - Visit your Worker URL + `/health`
   - Should return: `{"status":"healthy","service":"api-gateway"}`

3. **Test the frontend:**
   - Visit your Cloudflare Pages URL
   - Test all three modes (File, URL, Website)

## Environment Variables Summary

### Backend (Railway/Render):
- `OPENAI_API_KEY` - Your OpenAI API key
- `SEMGREP_APP_TOKEN` - Your Semgrep token
- `ENVIRONMENT` - Set to `production`

### Cloudflare Worker:
- `BACKEND_URL` - Your Railway/Render backend URL
- `CACHE` - KV namespace for caching

### Frontend:
- `NEXT_PUBLIC_API_URL` - Cloudflare Worker URL (optional)

## Troubleshooting

### Backend Issues:
- Check Railway/Render logs
- Verify environment variables are set
- Ensure dependencies are installed correctly

### Cloudflare Worker Issues:
- Check Worker logs in Cloudflare Dashboard
- Verify KV namespace is correctly configured
- Ensure backend URL is correct and accessible

### Frontend Issues:
- Check Cloudflare Pages deployment logs
- Verify API URL is correct
- Check browser console for errors

## Cost Breakdown

### Cloudflare Pages: **FREE**
- Unlimited deployments
- Global CDN
- SSL certificates
- Custom domains

### Cloudflare Workers: **FREE**
- 100,000 requests/day
- KV storage: 100,000 reads/day, 1,000 writes/day
- Global edge network

### Railway: **FREE** (with $5 credit)
- 512MB RAM
- 0.5 vCPU
- 500 hours/month
- After credit: ~$5/month

### Render: **FREE**
- 512MB RAM
- 0.5 vCPU
- 750 hours/month
- After free tier: ~$7/month

## Monthly Cost Estimate

**Free tier usage:** $0/month
**After free credits:** ~$5-7/month

## Next Steps

1. Deploy backend to Railway/Render
2. Deploy Cloudflare Worker API gateway
3. Deploy frontend to Cloudflare Pages
4. Test the complete application
5. Set up monitoring and alerts
6. Configure custom domains (optional)