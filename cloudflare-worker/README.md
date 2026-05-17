# Cloudflare Worker API Gateway

This Cloudflare Worker serves as the API gateway for the Cybersecurity Analyzer application.

## Purpose
- Route requests between Cloudflare Pages frontend and Railway/Render backend
- Implement caching for security scan results
- Rate limiting to prevent abuse
- CORS handling
- Security headers and request validation

## Features
- **Caching**: KV storage for security scan results (5-minute TTL)
- **Rate Limiting**: 10 requests per minute per IP
- **CORS**: Full CORS support for cross-origin requests
- **Security**: Request validation and IP-based rate limiting
- **Performance**: Edge caching and global CDN

## Configuration

### Environment Variables
- `BACKEND_URL`: Your Railway/Render backend URL
- `CACHE`: KV namespace for caching
- `ENVIRONMENT`: Set to "production"

### KV Namespace
Required for caching security scan results.

## Deployment
```bash
npm install
wrangler deploy
```

## Testing
```bash
# Test health endpoint
curl https://your-worker-url.workers.dev/health

# Test API routing
curl https://your-worker-url.workers.dev/api/analyze
```

## Monitoring
- View logs in Cloudflare Dashboard
- Monitor KV cache usage
- Track rate limiting metrics