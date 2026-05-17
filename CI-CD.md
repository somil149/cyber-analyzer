# CI/CD Automation Setup

This repository is configured with automated CI/CD pipelines using GitHub Actions to automatically build and deploy your Cybersecurity Analyzer application when you push changes to the `main` branch.

## Architecture

```
GitHub Push → GitHub Actions → Deploy to:
  ├─ Railway (Backend)
  ├─ Cloudflare Workers (API Gateway)
  └─ Cloudflare Pages (Frontend)
```

## Workflows

### 1. Main CI/CD Pipeline (`.github/workflows/ci-cd.yml`)
- **Triggers**: Push to `main` branch, pull requests, manual dispatch
- **Jobs**:
  - **test-backend**: Validates Python syntax and dependencies
  - **test-frontend**: Runs linter, type check, and build
  - **deploy-all**: Deploys to all cloud platforms (only on main branch)

### 2. Individual Component Workflows
- **`deploy-cloudflare-worker.yml`**: Deploys only Cloudflare Worker when worker code changes
- **`deploy-frontend.yml`**: Deploys only frontend when frontend code changes  
- **`deploy-railway.yml`**: Deploys only backend when backend code changes

## Required GitHub Secrets

Configure these secrets in your GitHub repository (Settings → Secrets and variables → Actions):

### Cloudflare Secrets
```
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
CLOUDFLARE_ACCOUNT_ID=your_cloudflare_account_id
```

### Railway Secret
```
RAILWAY_TOKEN=your_railway_token
```

### Optional: OpenAI & Semgrep (if needed in CI)
```
OPENAI_API_KEY=your_openai_key
SEMGREP_APP_TOKEN=your_semgrep_token
```

## How to Add GitHub Secrets

1. Go to your GitHub repository: https://github.com/somil149/cyber-analyzer
2. Click on **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Add each secret with the corresponding value from above
5. Click **Add secret**

## How It Works

### Automatic Deployment
When you push changes to the `main` branch:
1. GitHub Actions triggers automatically
2. Tests run to validate code quality
3. If tests pass, deployments execute in parallel:
   - Backend deploys to Railway
   - API Gateway deploys to Cloudflare Workers
   - Frontend builds and deploys to Cloudflare Pages
4. Health checks verify all services are running
5. You get notified of success/failure

### Path-Based Deployment
Individual workflows trigger based on file changes:
- Changes in `cloudflare-worker/` → Worker deployment
- Changes in `frontend/` → Frontend deployment
- Changes in `backend/` → Backend deployment

### Manual Deployment
You can manually trigger any workflow:
1. Go to **Actions** tab in GitHub
2. Select the workflow you want to run
3. Click **Run workflow**
4. Choose branch and click **Run workflow**

## Deployment Process

### Backend (Railway)
- Uses Railway CLI for deployment
- Automatically builds from `backend/` directory
- Uses existing Railway project and service configuration
- Environment variables already configured in Railway dashboard

### Cloudflare Worker
- Uses Wrangler CLI for deployment
- Deploys from `cloudflare-worker/` directory
- Uses existing worker configuration
- Environment variables set in `wrangler.toml`

### Frontend (Cloudflare Pages)
- Builds Next.js static export
- Deploys to Cloudflare Pages using Wrangler
- Uses existing Pages project configuration
- Automatically updates production URL

## Monitoring Deployments

### GitHub Actions
- View all workflow runs in the **Actions** tab
- See real-time logs for each deployment step
- Get notified of deployment status via email

### Cloud Platforms
- **Railway**: https://railway.app/project/0f36f995-8d09-4cde-8ae6-2530c159d38c
- **Cloudflare**: https://dash.cloudflare.com/

## Adding New Features

When you add new features:

1. **Make changes locally** in your development environment
2. **Test locally** to ensure everything works
3. **Commit changes**: `git add . && git commit -m "Your feature description"`
4. **Push to GitHub**: `git push origin main`
5. **Automatic deployment**: GitHub Actions handles the rest
6. **Monitor**: Check Actions tab for deployment progress

## Rollback

If a deployment fails or introduces issues:

### Railway
- Go to Railway dashboard
- Select the backend service
- Click on **Deployments** tab
- Click on previous successful deployment
- Click **Redeploy**

### Cloudflare Worker
- Go to Cloudflare dashboard → Workers
- Select the worker
- Click on **Deployments** 
- Rollback to previous version

### Cloudflare Pages
- Go to Cloudflare dashboard → Pages
- Select the project
- Click on **History** tab
- Rollback to previous deployment

## Troubleshooting

### Deployment Fails
1. Check GitHub Actions logs for error details
2. Verify all secrets are configured correctly
3. Ensure cloud platform credentials are valid
4. Check if there are syntax errors in code

### Health Check Failures
- Wait a few minutes for deployments to fully start
- Check individual platform dashboards for service status
- Verify environment variables are set correctly
- Check logs for runtime errors

### Rate Limiting
- GitHub Actions has usage limits (free tier: 2000 minutes/month)
- Cloudflare has rate limits on API calls
- Railway has deployment limits on free tier

## Best Practices

1. **Test locally** before pushing to main
2. **Use feature branches** for development, merge to main when ready
3. **Monitor deployments** in GitHub Actions
4. **Keep secrets secure** - never commit them to repository
5. **Review logs** if deployments fail
6. **Use semantic versioning** for releases
7. **Document breaking changes** in commit messages

## Cost Monitoring

- **Railway**: Free tier includes $5/month credit
- **Cloudflare Workers**: Free tier includes 100,000 requests/day
- **Cloudflare Pages**: Free tier includes unlimited bandwidth
- **GitHub Actions**: Free tier includes 2000 minutes/month

Monitor usage in each platform's dashboard to avoid unexpected charges.
