/**
 * Cloudflare Worker API Gateway for Cybersecurity Analyzer
 * Routes requests between frontend and backend with caching, rate limiting, and security
 */

// Cache configuration
const CACHE_TTL = 300; // 5 minutes for security scan results
const ANALYSIS_CACHE_PREFIX = 'security_analysis:';

// Rate limiting configuration
const RATE_LIMIT = {
  requests: 10,
  window: 60 // 10 requests per minute
};

// Rate limit storage
const rateLimitMap = new Map();

async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const pathname = url.pathname;
  
  // Backend URL from environment variable or fallback
  const BACKEND_URL = env.BACKEND_URL || 'https://your-backend-url.railway.app';

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return handleCORS();
  }

  // Health check
  if (pathname === '/health') {
    return new Response(JSON.stringify({ status: 'healthy', service: 'api-gateway' }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // API routes - proxy to backend
  if (pathname.startsWith('/api/')) {
    return handleAPIRequest(request, pathname, env, ctx);
  }

  // Static files - serve from Cloudflare Pages
  return new Response('Not found', { status: 404 });
}

async function handleAPIRequest(request, pathname, env, ctx) {
  // Rate limiting
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!checkRateLimit(clientIP)) {
    return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }

  // Check cache for GET requests (if KV namespace is configured)
  if (request.method === 'GET' && env.CACHE) {
    const cacheKey = `${ANALYSIS_CACHE_PREFIX}${pathname}`;
    const cached = await env.CACHE.get(cacheKey);
    if (cached) {
      return new Response(cached, {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'X-Cache': 'HIT'
        }
      });
    }
  }

  // Proxy to backend
  const backendUrl = `${BACKEND_URL}${pathname}`;
  const backendRequest = new Request(backendUrl, {
    method: request.method,
    headers: {
      ...request.headers,
      'X-Forwarded-For': clientIP,
      'X-Real-IP': clientIP,
      'User-Agent': 'Cloudflare-Worker-Gateway/1.0'
    },
    body: request.body
  });

  try {
    const response = await fetch(backendRequest);
    const responseData = await response.text();

    // Cache successful GET responses (if KV namespace is configured)
    if (request.method === 'GET' && response.ok && env.CACHE) {
      const cacheKey = `${ANALYSIS_CACHE_PREFIX}${pathname}`;
      await env.CACHE.put(cacheKey, responseData, { expirationTtl: CACHE_TTL });
    }

    return new Response(responseData, {
      status: response.status,
      headers: {
        'Content-Type': response.headers.get('Content-Type') || 'application/json',
        'Access-Control-Allow-Origin': '*',
        'X-Cache': 'MISS'
      }
    });
  } catch (error) {
    return new Response(JSON.stringify({ 
      error: 'Backend request failed',
      message: error.message 
    }), {
      status: 502,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
}

function handleCORS() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400'
    }
  });
}

function checkRateLimit(clientIP) {
  const now = Date.now();
  const windowStart = now - (RATE_LIMIT.window * 1000);

  if (!rateLimitMap.has(clientIP)) {
    rateLimitMap.set(clientIP, []);
  }

  const requests = rateLimitMap.get(clientIP).filter(timestamp => timestamp > windowStart);
  requests.push(now);
  rateLimitMap.set(clientIP, requests);

  // Clean up old entries periodically
  if (rateLimitMap.size > 1000) {
    for (const [ip, timestamps] of rateLimitMap.entries()) {
      if (timestamps.every(timestamp => timestamp < windowStart)) {
        rateLimitMap.delete(ip);
      }
    }
  }

  return requests.length <= RATE_LIMIT.requests;
}

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  }
};