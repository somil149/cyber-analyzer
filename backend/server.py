import tempfile  # to create a file on disk for semgrep_scan
import os
import httpx
import re
import ssl
import socket
import json
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from dotenv import load_dotenv
from agents import Agent, Runner, trace
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from context import SECURITY_RESEARCHER_INSTRUCTIONS, get_analysis_prompt, enhance_summary
from mcp_servers import create_semgrep_server

load_dotenv(override=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown events."""
    # Startup
    print("Starting Cybersecurity Analyzer API...")
    print(f"Environment: {os.getenv('ENVIRONMENT', 'development')}")
    yield
    # Shutdown
    print("Shutting down Cybersecurity Analyzer API...")

app = FastAPI(title="Cybersecurity Analyzer API", lifespan=lifespan)

# Configure CORS for development and production
cors_origins = [
    "http://localhost:3000",  # Local development
    "http://frontend:3000",  # Docker development
]

# In production, allow same-origin requests (static files served from same domain)
if os.getenv("ENVIRONMENT") == "production":
    cors_origins.append(
        "*"
    )  # Allow all origins in production since we serve frontend from same domain

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class FetchUrlRequest(BaseModel):
    url: str


class FetchUrlResponse(BaseModel):
    code: str
    filename: str


class WebsiteScanRequest(BaseModel):
    url: str


class AnalyzeRequest(BaseModel):
    code: str


class SecurityIssue(BaseModel):
    title: str = Field(description="Brief title of the security vulnerability")
    description: str = Field(
        description="Detailed description of the security issue and its potential impact"
    )
    code: str = Field(
        description="The specific vulnerable code snippet that demonstrates the issue"
    )
    fix: str = Field(description="Recommended code fix or mitigation strategy")
    cvss_score: float = Field(description="CVSS score from 0.0 to 10.0 representing severity")
    severity: str = Field(description="Severity level: critical, high, medium, or low")


class SecurityReport(BaseModel):
    summary: str = Field(description="Executive summary of the security analysis")
    issues: List[SecurityIssue] = Field(description="List of identified security vulnerabilities")


def validate_url(url: str) -> None:
    """Validate the URL is safe and accessible."""
    try:
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            raise HTTPException(status_code=400, detail="Invalid URL format")

        if parsed.scheme not in ['http', 'https']:
            raise HTTPException(status_code=400, detail="Only HTTP and HTTPS URLs are allowed")

        # Basic security check - prevent local file access
        if parsed.hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
            raise HTTPException(status_code=400, detail="Local URLs are not allowed")

    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(status_code=400, detail="Invalid URL")


def analyze_security_headers(headers: dict) -> List[SecurityIssue]:
    """Analyze HTTP security headers and identify missing or misconfigured ones."""
    issues = []

    # Security headers that should be present
    security_headers = {
        'X-Frame-Options': {
            'description': 'Clickjacking protection',
            'severity': 'high',
            'cvss': 7.5
        },
        'X-Content-Type-Options': {
            'description': 'MIME-sniffing protection',
            'severity': 'medium',
            'cvss': 5.3
        },
        'X-XSS-Protection': {
            'description': 'XSS filter',
            'severity': 'medium',
            'cvss': 5.3
        },
        'Strict-Transport-Security': {
            'description': 'HSTS enforcement',
            'severity': 'high',
            'cvss': 7.5
        },
        'Content-Security-Policy': {
            'description': 'CSP policy',
            'severity': 'high',
            'cvss': 7.5
        },
        'Referrer-Policy': {
            'description': 'Referrer information control',
            'severity': 'low',
            'cvss': 3.7
        },
        'Permissions-Policy': {
            'description': 'Feature policy control',
            'severity': 'medium',
            'cvss': 5.3
        }
    }

    for header, config in security_headers.items():
        if header not in headers:
            issues.append(SecurityIssue(
                title=f"Missing Security Header: {header}",
                description=f"The {header} header is missing. {config['description']} is not implemented.",
                code=f"Header: {header} is not set in HTTP response",
                fix=f"Add the {header} header to your server configuration. Example: {header}: appropriate-value",
                cvss_score=config['cvss'],
                severity=config['severity']
            ))

    # Check for information disclosure
    if 'Server' in headers:
        issues.append(SecurityIssue(
            title="Server Information Disclosure",
            description=f"Server header exposes server information: {headers['Server']}",
            code=f"Server: {headers['Server']}",
            fix="Remove or minimize the Server header to avoid revealing server technology information",
            cvss_score=5.3,
            severity="medium"
        ))

    if 'X-Powered-By' in headers:
        issues.append(SecurityIssue(
            title="Technology Information Disclosure",
            description=f"X-Powered-By header exposes technology: {headers['X-Powered-By']}",
            code=f"X-Powered-By: {headers['X-Powered-By']}",
            fix="Remove the X-Powered-By header to avoid revealing technology stack information",
            cvss_score=5.3,
            severity="medium"
        ))

    return issues


def analyze_basic_vulnerabilities(html_content: str, url: str) -> List[SecurityIssue]:
    """Analyze HTML content for basic security vulnerabilities."""
    issues = []

    # Check for inline JavaScript (potential XSS risk)
    inline_js_pattern = r'<script[^>]*>.*?</script>'
    if re.search(inline_js_pattern, html_content, re.DOTALL | re.IGNORECASE):
        issues.append(SecurityIssue(
            title="Inline JavaScript Detected",
            description="Inline JavaScript can increase XSS attack surface",
            code="Inline <script> tags found in HTML",
            fix="Move JavaScript to external files and use Content-Security-Policy to restrict script sources",
            cvss_score=6.1,
            severity="medium"
        ))

    # Check for inline event handlers
    inline_events = r'on\w+\s*='
    if re.search(inline_events, html_content, re.IGNORECASE):
        issues.append(SecurityIssue(
            title="Inline Event Handlers Detected",
            description="Inline event handlers like onclick can be XSS vectors",
            code="HTML contains inline event handlers (e.g., onclick=)",
            fix="Remove inline event handlers and use addEventListener in external JavaScript",
            cvss_score=6.1,
            severity="medium"
        ))

    # Check for insecure forms
    if re.search(r'<form[^>]*action\s*=\s*["\']?http://', html_content, re.IGNORECASE):
        issues.append(SecurityIssue(
            title="Insecure Form Action",
            description="Form submits to HTTP instead of HTTPS",
            code="<form action=\"http://...\">",
            fix="Change form action to use HTTPS protocol",
            cvss_score=7.5,
            severity="high"
        ))

    # Check for potential sensitive data exposure
    sensitive_patterns = [
        (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password in HTML"),
        (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', "Hardcoded API key in HTML"),
        (r'secret[_-]?key\s*=\s*["\'][^"\']+["\']', "Hardcoded secret key in HTML"),
        (r'access[_-]?token\s*=\s*["\'][^"\']+["\']', "Hardcoded access token in HTML"),
    ]

    for pattern, description in sensitive_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            issues.append(SecurityIssue(
                title="Sensitive Data Exposure",
                description=description,
                code="Sensitive information found in HTML source",
                fix="Remove sensitive data from HTML and use secure server-side processing",
                cvss_score=8.6,
                severity="high"
            ))

    return issues


def analyze_html_javascript(html_content: str, url: str) -> List[SecurityIssue]:
    """Analyze HTML and JavaScript content for security issues."""
    issues = []

    try:
        soup = BeautifulSoup(html_content, 'html.parser')

        # Check for meta tags that could expose information
        generator_meta = soup.find('meta', attrs={'name': 'generator'})
        if generator_meta and generator_meta.get('content'):
            issues.append(SecurityIssue(
                title="Generator Meta Tag Information Disclosure",
                description=f"Generator meta tag reveals CMS/tool information: {generator_meta.get('content')}",
                code=f'<meta name="generator" content="{generator_meta.get("content")}">',
                fix="Remove generator meta tag to avoid revealing technology information",
                cvss_score=3.7,
                severity="low"
            ))

        # Check for comments with sensitive information
        comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
        for comment in comments:
            comment_lower = comment.lower()
            if any(keyword in comment_lower for keyword in ['password', 'api', 'secret', 'key', 'token', 'todo', 'fixme']):
                issues.append(SecurityIssue(
                    title="Sensitive Information in HTML Comments",
                    description="HTML comments contain potentially sensitive information",
                    code=f"<!-- {comment.strip()} -->",
                    fix="Remove sensitive information from HTML comments",
                    cvss_score=5.3,
                    severity="medium"
                ))
                break

        # Check for external scripts from non-HTTPS sources
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script.get('src', '')
            if src.startswith('http://'):
                issues.append(SecurityIssue(
                    title="Insecure External Script",
                    description=f"External script loaded over HTTP: {src}",
                    code=f'<script src="{src}">',
                    fix="Change external script sources to HTTPS",
                    cvss_score=7.5,
                    severity="high"
                ))

        # Check for missing integrity attributes on external scripts
        for script in scripts:
            src = script.get('src', '')
            if src.startswith(('http://', 'https://')) and not script.get('integrity'):
                issues.append(SecurityIssue(
                    title="Missing Subresource Integrity (SRI)",
                    description=f"External script without SRI: {src}",
                    code=f'<script src="{src}">',
                    fix="Add integrity attribute and crossorigin attribute for external scripts",
                    cvss_score=5.3,
                    severity="medium"
                ))

    except Exception as e:
        print(f"Error analyzing HTML/JavaScript: {e}")

    return issues


def analyze_ssl_tls(hostname: str, port: int = 443) -> List[SecurityIssue]:
    """Analyze SSL/TLS configuration and certificate."""
    issues = []

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()

        # Check TLS version
        if tls_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
            issues.append(SecurityIssue(
                title=f"Outdated TLS Version: {tls_version}",
                description=f"Server uses outdated TLS version {tls_version} which has known vulnerabilities",
                code=f"TLS Version: {tls_version}",
                fix="Disable outdated TLS versions and use TLS 1.2 or higher only",
                cvss_score=7.5,
                severity="high"
            ))

        # Check certificate expiration
        if cert and 'notAfter' in cert:
            expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (expiry_date - datetime.utcnow()).days

            if days_until_expiry < 0:
                issues.append(SecurityIssue(
                    title="SSL Certificate Expired",
                    description=f"SSL certificate expired on {expiry_date}",
                    code=f"Certificate expired: {expiry_date}",
                fix="Renew SSL certificate immediately",
                cvss_score=9.8,
                severity="critical"
                ))
            elif days_until_expiry < 30:
                issues.append(SecurityIssue(
                    title="SSL Certificate Expiring Soon",
                    description=f"SSL certificate expires in {days_until_expiry} days",
                    code=f"Certificate expires: {expiry_date}",
                    fix="Renew SSL certificate before expiration",
                    cvss_score=5.3,
                    severity="medium"
                ))

    except ssl.SSLError as e:
        issues.append(SecurityIssue(
            title="SSL/TLS Configuration Error",
            description=f"SSL/TLS handshake failed: {str(e)}",
            code=f"SSL Error: {str(e)}",
            fix="Fix SSL/TLS configuration on the server",
            cvss_score=7.5,
            severity="high"
        ))
    except Exception as e:
        print(f"SSL analysis error: {e}")

    return issues


def analyze_cookie_security(headers: dict, html_content: str) -> List[SecurityIssue]:
    """Analyze cookie security from Set-Cookie headers and JavaScript."""
    issues = []

    # Analyze Set-Cookie headers
    set_cookie_headers = headers.get('set-cookie', '')
    if set_cookie_headers:
        if isinstance(set_cookie_headers, str):
            cookies = [set_cookie_headers]
        else:
            cookies = set_cookie_headers

        for cookie in cookies:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split('=')[0].strip() if '=' in cookie else 'unknown'

            # Check for Secure flag
            if 'secure' not in cookie_lower:
                issues.append(SecurityIssue(
                    title=f"Insecure Cookie: {cookie_name}",
                    description=f"Cookie '{cookie_name}' lacks Secure flag, can be transmitted over HTTP",
                    code=f"Set-Cookie: {cookie.split(';')[0] if ';' in cookie else cookie}",
                    fix="Add Secure flag to cookie: Set-Cookie: {cookie_name}=value; Secure",
                    cvss_score=5.3,
                    severity="medium"
                ))

            # Check for HttpOnly flag
            if 'httponly' not in cookie_lower:
                issues.append(SecurityIssue(
                    title=f"Cookie Accessible to JavaScript: {cookie_name}",
                    description=f"Cookie '{cookie_name}' lacks HttpOnly flag, accessible to JavaScript (XSS risk)",
                    code=f"Set-Cookie: {cookie.split(';')[0] if ';' in cookie else cookie}",
                    fix="Add HttpOnly flag to cookie: Set-Cookie: {cookie_name}=value; HttpOnly",
                    cvss_score=6.1,
                    severity="medium"
                ))

            # Check for SameSite attribute
            if 'samesite' not in cookie_lower:
                issues.append(SecurityIssue(
                    title=f"Missing SameSite Attribute: {cookie_name}",
                    description=f"Cookie '{cookie_name}' lacks SameSite attribute, vulnerable to CSRF",
                    code=f"Set-Cookie: {cookie.split(';')[0] if ';' in cookie else cookie}",
                    fix="Add SameSite attribute: Set-Cookie: {cookie_name}=value; SameSite=Strict",
                    cvss_score=5.3,
                    severity="medium"
                ))

    # Check for document.cookie usage in JavaScript
    doc_cookie_pattern = r'document\.cookie'
    if re.search(doc_cookie_pattern, html_content, re.IGNORECASE):
        issues.append(SecurityIssue(
            title="JavaScript Cookie Access Detected",
            description="JavaScript code accesses document.cookie, potential XSS vulnerability",
            code="document.cookie found in JavaScript",
            fix="Review JavaScript cookie usage and implement proper security controls",
            cvss_score=5.3,
            severity="medium"
        ))

    return issues


def detect_technology_stack(html_content: str, headers: dict) -> List[SecurityIssue]:
    """Detect technology stack and identify potential security issues."""
    issues = []

    # Check for common frameworks and libraries
    framework_patterns = {
        'React': r'react|jsx|tsx',
        'Vue.js': r'vue\.js|vue\.min\.js',
        'Angular': r'angular|ng-app',
        'jQuery': r'jquery-[0-9]',
        'Bootstrap': r'bootstrap',
        'WordPress': r'wp-content|wordpress',
        'Drupal': r'drupal',
        'Joomla': r'joomla',
        'Laravel': r'laravel',
        'Django': r'django',
        'Flask': r'flask',
        'Ruby on Rails': r'rails',
        'Express.js': r'express',
        'Spring': r'spring',
        'ASP.NET': r'asp\.net',
        'PHP': r'\.php',
    }

    detected_frameworks = []
    for framework, pattern in framework_patterns.items():
        if re.search(pattern, html_content, re.IGNORECASE):
            detected_frameworks.append(framework)

    if detected_frameworks:
        # Check for outdated versions (basic pattern matching)
        version_patterns = r'(react|vue|angular|jquery|bootstrap)[_-]?([0-9]+\.[0-9]+\.[0-9]+)'
        versions = re.findall(version_patterns, html_content, re.IGNORECASE)

        if versions:
            for lib, version in versions:
                # Basic version check - in production you'd use a vulnerability database
                major_version = int(version.split('.')[0])
                if lib.lower() in ['jquery', 'react', 'angular'] and major_version < 2:
                    issues.append(SecurityIssue(
                        title=f"Potentially Outdated Library: {lib} {version}",
                        description=f"Detected {lib} version {version} which may have known vulnerabilities",
                        code=f"{lib} version {version}",
                        fix=f"Update {lib} to the latest stable version",
                        cvss_score=6.5,
                        severity="medium"
                    ))

    # Server technology detection
    server_header = headers.get('server', '')
    x_powered_by = headers.get('x-powered-by', '')

    if server_header:
        if any(tech in server_header.lower() for tech in ['apache', 'nginx', 'iis']):
            issues.append(SecurityIssue(
                title="Server Technology Information Disclosure",
                description=f"Server header reveals technology: {server_header}",
                code=f"Server: {server_header}",
                fix="Configure server to hide version information in Server header",
                cvss_score=3.7,
                severity="low"
            ))

    if x_powered_by:
        issues.append(SecurityIssue(
            title="Technology Stack Information Disclosure",
            description=f"X-Powered-By header reveals technology: {x_powered_by}",
            code=f"X-Powered-By: {x_powered_by}",
            fix="Remove X-Powered-By header to hide technology information",
            cvss_score=3.7,
            severity="low"
        ))

    return issues


def discover_api_endpoints(html_content: str, base_url: str) -> List[SecurityIssue]:
    """Discover potential API endpoints from JavaScript and HTML."""
    issues = []

    # API endpoint patterns
    api_patterns = [
        r'["\']https?://[^"\']*/api/[^"\']*["\']',
        r'["\']https?://[^"\']*/v[0-9]+/[^"\']*["\']',
        r'["\']https?://[^"\']*/graphql["\']',
        r'["\']https?://[^"\']*/rest/[^"\']*["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'\.get\(["\']([^"\']+)["\']',
        r'\.post\(["\']([^"\']+)["\']',
        r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
    ]

    endpoints = set()
    for pattern in api_patterns:
        matches = re.findall(pattern, html_content, re.IGNORECASE)
        if matches:
            for match in matches:
                if isinstance(match, tuple):
                    endpoints.add(match[1] if len(match) > 1 else match[0])
                else:
                    endpoints.add(match)

    if endpoints:
        # Check for common API security issues
        for endpoint in list(endpoints)[:5]:  # Limit to 5 to avoid overwhelming results
            if 'http:' in endpoint:
                issues.append(SecurityIssue(
                    title="Insecure API Endpoint",
                    description=f"API endpoint uses HTTP instead of HTTPS: {endpoint}",
                    code=f"Endpoint: {endpoint}",
                    fix="Change API endpoint to use HTTPS",
                    cvss_score=7.5,
                    severity="high"
                ))

            # Check for potential IDOR patterns
            if re.search(r'/users/[0-9]+|/accounts/[0-9]+|/profiles/[0-9]+', endpoint):
                issues.append(SecurityIssue(
                    title="Potential IDOR Vulnerability",
                    description=f"API endpoint may be vulnerable to IDOR: {endpoint}",
                    code=f"Endpoint: {endpoint}",
                    fix="Implement proper access controls and use UUIDs instead of sequential IDs",
                    cvss_score=8.1,
                    severity="high"
                ))

    return issues


def analyze_form_security(html_content: str) -> List[SecurityIssue]:
    """Deep analysis of form security."""
    issues = []

    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').lower()

            # Check for insecure form actions
            if form_action.startswith('http://'):
                issues.append(SecurityIssue(
                    title="Insecure Form Action",
                    description=f"Form submits to HTTP endpoint: {form_action}",
                    code=f'<form action="{form_action}">',
                    fix="Change form action to use HTTPS",
                    cvss_score=7.5,
                    severity="high"
                ))

            # Check for GET forms with sensitive data
            if form_method == 'get':
                sensitive_inputs = form.find_all('input', attrs={'type': re.compile(r'password|hidden', re.I)})
                if sensitive_inputs:
                    issues.append(SecurityIssue(
                        title="Sensitive Data in GET Request",
                        description="Form uses GET method with potentially sensitive data",
                        code='<form method="GET"> with sensitive inputs',
                        fix="Change form method to POST for sensitive data",
                        cvss_score=5.3,
                        severity="medium"
                    ))

            # Check for CSRF protection
            csrf_inputs = form.find_all('input', attrs={'name': re.compile(r'csrf|_token', re.I)})
            if not csrf_inputs and form_method == 'post':
                issues.append(SecurityIssue(
                    title="Missing CSRF Protection",
                    description="POST form lacks CSRF token",
                    code='<form method="POST"> without CSRF token',
                    fix='Add CSRF token to form: <input type="hidden" name="csrf_token" value="...">',
                    cvss_score=6.5,
                    severity="medium"
                ))

            # Check for autocomplete on sensitive fields
            password_inputs = form.find_all('input', attrs={'type': 'password'})
            for password_input in password_inputs:
                autocomplete = password_input.get('autocomplete', '')
                if autocomplete.lower() != 'off':
                    issues.append(SecurityIssue(
                        title="Password Field Autocomplete Enabled",
                        description="Password field has autocomplete enabled",
                        code='<input type="password" autocomplete="on">',
                        fix="Add autocomplete=\"off\" to password fields",
                        cvss_score=3.7,
                        severity="low"
                    ))

            # Check for file upload forms
            file_inputs = form.find_all('input', attrs={'type': 'file'})
            if file_inputs:
                accept_attr = file_inputs[0].get('accept', '')
                if not accept_attr:
                    issues.append(SecurityIssue(
                        title="Unrestricted File Upload",
                        description="File upload form lacks file type restrictions",
                        code='<input type="file"> without accept attribute',
                        fix="Add accept attribute to restrict file types: accept=\".jpg,.png,.pdf\"",
                        cvss_score=7.5,
                        severity="high"
                    ))

    except Exception as e:
        print(f"Form analysis error: {e}")

    return issues


async def discover_sensitive_files(base_url: str) -> List[SecurityIssue]:
    """Discover common sensitive files and directories."""
    issues = []

    sensitive_paths = [
        '.git',
        '.env',
        '.env.local',
        '.env.production',
        'config.php',
        'web.config',
        '.htaccess',
        '.htpasswd',
        'admin',
        'administrator',
        'login',
        'wp-admin',
        'phpmyadmin',
        'console',
        'debug',
        'backup',
        'backups',
        '.backup',
        'old',
        'temp',
        'tmp',
        'private',
        'protected',
    ]

    # Check a few common paths (limited to avoid excessive requests)
    paths_to_check = sensitive_paths[:5]  # Limit to 5 for performance

    async with httpx.AsyncClient(timeout=5.0) as client:
        for path in paths_to_check:
            try:
                url = urljoin(base_url, path)
                response = await client.get(url)
                if response.status_code == 200:
                    issues.append(SecurityIssue(
                        title=f"Sensitive File/Directory Exposed: {path}",
                        description=f"Sensitive path {path} is accessible",
                        code=f"GET {url} - 200 OK",
                        fix="Restrict access to sensitive files and directories",
                        cvss_score=7.5,
                        severity="high"
                    ))
                elif response.status_code == 403:
                    # This is actually good - access is restricted
                    pass
            except Exception:
                pass

    return issues


async def analyze_error_pages(base_url: str) -> List[SecurityIssue]:
    """Analyze error pages for information disclosure."""
    issues = []

    # Test common error conditions
    error_paths = [
        '/nonexistent-page-12345',
        '/admin',
        '/.git',
        '/config',
    ]

    async with httpx.AsyncClient(timeout=5.0) as client:
        for path in error_paths:
            try:
                url = urljoin(base_url, path)
                response = await client.get(url)

                # Check for information disclosure in error pages
                content = response.text.lower()
                if any(keyword in content for keyword in ['stack trace', 'fatal error', 'debug', 'exception', 'line', 'file']):
                    issues.append(SecurityIssue(
                        title="Information Disclosure in Error Page",
                        description=f"Error page at {path} reveals sensitive debugging information",
                        code=f"Error page contains debugging information",
                        fix="Disable detailed error messages in production",
                        cvss_score=5.3,
                        severity="medium"
                    ))
                    break  # Only report once to avoid duplicates

            except Exception:
                pass

    return issues


def analyze_cors_security(headers: dict) -> List[SecurityIssue]:
    """Analyze CORS configuration for security issues."""
    issues = []

    cors_headers = ['Access-Control-Allow-Origin', 'Access-Control-Allow-Methods',
                   'Access-Control-Allow-Headers', 'Access-Control-Allow-Credentials']

    for header in cors_headers:
        if header in headers:
            value = headers[header]

            if header == 'Access-Control-Allow-Origin':
                if value == '*':
                    issues.append(SecurityIssue(
                        title="Overly Permissive CORS Policy",
                        description="CORS allows requests from any origin (*)",
                        code=f"Access-Control-Allow-Origin: *",
                        fix="Restrict CORS to specific origins: Access-Control-Allow-Origin: https://yourdomain.com",
                        cvss_score=5.3,
                        severity="medium"
                    ))

            if header == 'Access-Control-Allow-Credentials' and value.lower() == 'true':
                origin = headers.get('Access-Control-Allow-Origin', '')
                if origin == '*':
                    issues.append(SecurityIssue(
                        title="Insecure CORS Configuration",
                        description="CORS allows credentials with wildcard origin",
                        code="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                        fix="Specify exact origin when using credentials",
                        cvss_score=7.5,
                        severity="high"
                    ))

    return issues


def analyze_session_security(headers: dict, html_content: str) -> List[SecurityIssue]:
    """Analyze session security configuration."""
    issues = []

    # Check for session cookies
    set_cookie = headers.get('set-cookie', '')
    if set_cookie:
        if isinstance(set_cookie, str):
            cookies = [set_cookie]
        else:
            cookies = set_cookie

        for cookie in cookies:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split('=')[0].strip() if '=' in cookie else 'unknown'

            # Check for session cookies
            if any(keyword in cookie_name.lower() for keyword in ['session', 'sessid', 'phpsessid', 'jsessionid']):
                # Check session cookie security
                if 'secure' not in cookie_lower:
                    issues.append(SecurityIssue(
                        title=f"Insecure Session Cookie: {cookie_name}",
                        description=f"Session cookie '{cookie_name}' lacks Secure flag",
                        code=f"Set-Cookie: {cookie_name}=... (missing Secure)",
                        fix="Add Secure flag to session cookies",
                        cvss_score=7.5,
                        severity="high"
                    ))

                if 'httponly' not in cookie_lower:
                    issues.append(SecurityIssue(
                        title=f"Session Cookie Accessible to JavaScript: {cookie_name}",
                        description=f"Session cookie '{cookie_name}' lacks HttpOnly flag",
                        code=f"Set-Cookie: {cookie_name}=... (missing HttpOnly)",
                        fix="Add HttpOnly flag to session cookies",
                        cvss_score=7.5,
                        severity="high"
                    ))

    # Check for session fixation risks
    if re.search(r'sessionid|session_id|sessid', html_content, re.IGNORECASE):
        issues.append(SecurityIssue(
            title="Potential Session Fixation Vulnerability",
            description="Session ID appears in HTML content, potential session fixation risk",
            code="Session ID found in HTML",
            fix="Ensure session IDs are not exposed in HTML and implement session regeneration",
            cvss_score=6.5,
            severity="medium"
        ))

    return issues


def analyze_owasp_top_10(html_content: str, headers: dict, base_url: str) -> List[SecurityIssue]:
    """Check for OWASP Top 10 vulnerabilities."""
    issues = []

    # A01:2021 - Broken Access Control
    if re.search(r'admin|dashboard|console|debug|test|hidden', html_content, re.IGNORECASE):
        issues.append(SecurityIssue(
            title="Potential Broken Access Control",
            description="URL paths suggest administrative or debug interfaces that may be improperly protected",
            code="Sensitive paths found in HTML",
            fix="Implement proper access controls and authentication for administrative interfaces",
            cvss_score=7.5,
            severity="high"
        ))

    # A02:2021 - Cryptographic Failures
    if re.search(r'md5|sha1|base64.*password|password.*base64', html_content, re.IGNORECASE):
        issues.append(SecurityIssue(
            title="Weak Cryptographic Practices",
            description="Use of weak cryptographic algorithms (MD5, SHA1) or insecure password handling detected",
            code="Weak cryptographic patterns found",
            fix="Use strong cryptographic algorithms (SHA-256+, bcrypt, Argon2)",
            cvss_score=7.5,
            severity="high"
        ))

    # A03:2021 - Injection
    injection_patterns = [
        (r'\$[a-zA-Z_]+\s*=\s*\$_GET|\$_POST|\$_REQUEST', "PHP SQL Injection Risk"),
        (r'query\.execute\(|db\.query\(', "SQL Injection Risk"),
        (r'eval\(|exec\(|system\(', "Command Injection Risk"),
    ]

    for pattern, description in injection_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            issues.append(SecurityIssue(
                title="Injection Vulnerability Risk",
                description=description,
                code="Potentially vulnerable code pattern found",
                fix="Use parameterized queries and proper input validation",
                cvss_score=9.8,
                severity="critical"
            ))

    # A05:2021 - Security Misconfiguration
    if re.search(r'debug|test|dev|development', headers.get('server', '').lower()):
        issues.append(SecurityIssue(
            title="Security Misconfiguration - Development Server",
            description="Server appears to be running in development mode",
            code=f"Server: {headers.get('server', '')}",
            fix="Ensure production configuration disables debugging features",
            cvss_score=7.5,
            severity="high"
        ))

    # A07:2021 - Identification and Authentication Failures
    auth_patterns = [
        r'password\s*=\s*["\']|pwd\s*=\s*["\']',
        r'api[_-]?key\s*=\s*["\']',
        r'secret[_-]?key\s*=\s*["\']',
    ]

    for pattern in auth_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            issues.append(SecurityIssue(
                title="Hardcoded Credentials Detected",
                description="Potential hardcoded credentials or API keys found",
                code="Hardcoded credential pattern found",
                fix="Remove hardcoded credentials and use secure secret management",
                cvss_score=9.8,
                severity="critical"
            ))

    return issues


def validate_request(request: AnalyzeRequest) -> None:
    """Validate the analysis request."""
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="No code provided for analysis")


def check_api_keys() -> None:
    """Verify required API keys are configured."""
    if not os.getenv("OPENAI_API_KEY"):
        raise HTTPException(status_code=500, detail="OpenAI API key not configured")


def create_security_agent(semgrep_server) -> Agent:
    """Create and configure the security analysis agent."""
    return Agent(
        name="Security Researcher",
        instructions=SECURITY_RESEARCHER_INSTRUCTIONS,
        model="gpt-4.1-mini",
        mcp_servers=[semgrep_server],
        output_type=SecurityReport,
    )


async def run_security_analysis(code: str) -> SecurityReport:
    """Execute the security analysis workflow."""
    with trace("Security Researcher"):
        async with create_semgrep_server() as semgrep:
            agent = create_security_agent(semgrep)
            try:
                with tempfile.NamedTemporaryFile(  # Creates a temporary file locally with teh code
                    mode="w", suffix=".py", delete=False
                ) as temp:
                    temp.write(code)
                    temp_path = temp.name
                try:
                    result = await Runner.run(
                        agent, input=get_analysis_prompt(code, temp_path)
                    )  # Sends code and path to the file
                    # Changed the following two lines to sort by CVSS in descending order
                    sorted_report = result.final_output_as(SecurityReport)
                    sorted_report.issues.sort(key=lambda issue: issue.cvss_score, reverse=True)

                    return sorted_report
                finally:
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass
            except Exception as err:
                print(f"Unexpected {err=}, {type(err)=}")
                raise


def format_analysis_response(code: str, report: SecurityReport) -> SecurityReport:
    """Format the final analysis response."""
    enhanced_summary = enhance_summary(len(code), report.summary)
    return SecurityReport(summary=enhanced_summary, issues=report.issues)


@app.post("/api/fetch-url", response_model=FetchUrlResponse)
async def fetch_url(request: FetchUrlRequest) -> FetchUrlResponse:
    """
    Fetch Python code from a public URL.

    This endpoint retrieves Python code from public URLs for security analysis.
    Supports GitHub raw URLs, GitLab raw URLs, and other public Python file URLs.
    """
    validate_url(request.url)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(request.url, follow_redirects=True)
            response.raise_for_status()

            content = response.text

            # Check if the content appears to be Python code
            if not content.strip():
                raise HTTPException(status_code=400, detail="No content found at URL")

            # Extract filename from URL
            parsed = urlparse(request.url)
            filename = os.path.basename(parsed.path) or 'fetched_code.py'

            # Ensure it has .py extension
            if not filename.endswith('.py'):
                filename += '.py'

            return FetchUrlResponse(code=content, filename=filename)

    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"Failed to fetch URL: {e.response.status_code}")
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Network error while fetching URL: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching URL: {str(e)}")


@app.post("/api/scan-website", response_model=SecurityReport)
async def scan_website(request: WebsiteScanRequest) -> SecurityReport:
    """
    Scan a website for security vulnerabilities with comprehensive analysis.

    This endpoint performs extensive security analysis including:
    - SSL/TLS certificate analysis
    - Security header analysis
    - Cookie security analysis
    - Technology stack detection
    - API endpoint discovery
    - Form security analysis
    - Sensitive file discovery
    - Error page analysis
    - JavaScript vulnerability deep dive
    - OWASP Top 10 vulnerability patterns
    - Session security analysis
    - CORS security analysis
    """
    validate_url(request.url)

    try:
        all_issues = []
        parsed_url = urlparse(request.url)
        hostname = parsed_url.hostname

        # Fetch the website
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(request.url)
            response.raise_for_status()

            # Analyze security headers
            header_issues = analyze_security_headers(dict(response.headers))
            all_issues.extend(header_issues)

            # Analyze HTML content for vulnerabilities
            html_content = response.text
            vuln_issues = analyze_basic_vulnerabilities(html_content, request.url)
            all_issues.extend(vuln_issues)

            # Analyze HTML/JavaScript specific issues
            js_issues = analyze_html_javascript(html_content, request.url)
            all_issues.extend(js_issues)

            # SSL/TLS analysis
            if parsed_url.scheme == 'https':
                ssl_issues = analyze_ssl_tls(hostname)
                all_issues.extend(ssl_issues)

            # Cookie security analysis
            cookie_issues = analyze_cookie_security(dict(response.headers), html_content)
            all_issues.extend(cookie_issues)

            # Technology stack detection
            tech_issues = detect_technology_stack(html_content, dict(response.headers))
            all_issues.extend(tech_issues)

            # API endpoint discovery
            api_issues = discover_api_endpoints(html_content, request.url)
            all_issues.extend(api_issues)

            # Form security analysis
            form_issues = analyze_form_security(html_content)
            all_issues.extend(form_issues)

            # Sensitive file discovery (limited)
            sensitive_issues = await discover_sensitive_files(request.url)
            all_issues.extend(sensitive_issues)

            # Error page analysis
            error_issues = await analyze_error_pages(request.url)
            all_issues.extend(error_issues)

            # CORS security analysis
            cors_issues = analyze_cors_security(dict(response.headers))
            all_issues.extend(cors_issues)

            # Session security analysis
            session_issues = analyze_session_security(dict(response.headers), html_content)
            all_issues.extend(session_issues)

            # OWASP Top 10 analysis
            owasp_issues = analyze_owasp_top_10(html_content, dict(response.headers), request.url)
            all_issues.extend(owasp_issues)

        # Sort issues by CVSS score (descending)
        all_issues.sort(key=lambda issue: issue.cvss_score, reverse=True)

        # Create comprehensive summary
        critical_count = sum(1 for issue in all_issues if issue.severity == 'critical')
        high_count = sum(1 for issue in all_issues if issue.severity == 'high')
        medium_count = sum(1 for issue in all_issues if issue.severity == 'medium')
        low_count = sum(1 for issue in all_issues if issue.severity == 'low')

        summary = f"Extensive security analysis completed for {request.url}. "
        summary += f"Found {len(all_issues)} total security issues: "
        summary += f"{critical_count} critical, {high_count} high, {medium_count} medium, {low_count} low severity. "
        summary += "Analysis included SSL/TLS, headers, cookies, technology stack, API endpoints, forms, sensitive files, OWASP Top 10, and more."

        return SecurityReport(summary=summary, issues=all_issues)

    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"Failed to scan website: {e.response.status_code}")
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Network error while scanning website: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error scanning website: {str(e)}")


@app.post("/api/analyze", response_model=SecurityReport)
async def analyze_code(request: AnalyzeRequest) -> SecurityReport:
    """
    Analyze Python code for security vulnerabilities using OpenAI Agents and Semgrep.

    This endpoint combines static analysis via Semgrep with AI-powered security analysis
    to provide comprehensive vulnerability detection and remediation guidance.
    """
    validate_request(request)
    check_api_keys()

    try:
        report = await run_security_analysis(request.code)
        return format_analysis_response(request.code, report)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "message": "Cybersecurity Analyzer API"}


# Mount static files for frontend (only if directory exists)
# This must come after the health endpoint to avoid route conflicts
if os.path.exists("static"):
    app.mount("/", StaticFiles(directory="static", html=True), name="static")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
