from core.tool_transport import guarded_dns as dns
from core.tool_transport import guarded_requests as requests
from core.tool_decorator import langchain_tool as tool
from core.auth_store import get_auth_kwargs

# Fingerprints populer for Subdomain Takeover
FINGERPRINTS = {
    # ── Cloud Hosting ─────────────────────────────────────────────────────────
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "herokucdn.com/error-pages/no-such-app.html",
    "herokussl.com": "herokucdn.com/error-pages/no-such-app.html",
    "cloudfront.net": "Bad Gateway: The proxy server received an invalid response",
    "s3.amazonaws.com": "The specified bucket does not exist",
    "s3-website": "The specified bucket does not exist",
    "azurewebsites.net": "404 Web Site not found",
    "azure-api.net": "404 API not found",
    "azurehdinsight.net": "404 Not Found",
    "azureedge.net": "404 Not Found",
    "azurecontainer.io": "404 Not Found",
    "database.windows.net": "404 Not Found",
    "azuredatalakestore.net": "404 Not Found",
    "search.windows.net": "404 Not Found",
    "azurecr.io": "404 Not Found",
    "redis.cache.windows.net": "404 Not Found",
    "azurehdinsight.net": "404 Not Found",
    "servicebus.windows.net": "404 Not Found",
    "visualstudio.com": "404 Not Found",

    # ── CMS / Blog ───────────────────────────────────────────────────────────
    "wordpress.com": "Do you want to register",
    "ghost.io": "The thing you were looking for is no longer here",
    "pantheon.io": "404 error unknown site!",
    "tumblr.com": "Whatever you were looking for doesn't currently exist at this address",

    # ── E-commerce / Payment ──────────────────────────────────────────────────
    "myshopify.com": "Sorry, this shop is currently unavailable.",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",

    # ── Analytics / Marketing ─────────────────────────────────────────────────
    "helpjuice.com": "We could not find what you're looking for.",
    "helpscoutdocs.com": "No documentation was found at this location.",
    "cargocollective.com": "If you're moving your domain away from Cargo you must make this configuration change first.",
    "statuspage.io": "Better StatusPage",
    "pingdom.com": "Sorry, couldn't find the status page",
    "tave.com": "404 Not Found",
    "helpshift.com": "404 Not Found",
    "airee.ru": "404 Not Found",
    "ning.com": "Hey, this domain isn't linked to any Ning Community yet.",
    "canny.io": "Company Not Found",
    "sprint.ly": "404 Not Found",
    "brightcovegallery.com": "404 Not Found",
    "jazzhr.com": "404 Not Found",
    "landingi.com": "It looks like you're lost",
    "wishpond.com": "https://www.wishpond.com/404?agency=true",
    "campaignmonitor.com": "404 Not Found",
    "acid.alphacoders.com": "No User Found",
    "afternic.com": "This domain is for sale",
    "feedpress.me": "404 Not Found",
    "freshdesk.com": "404 Not Found",
    "ghostnote.io": "404 Not Found",
    "guerrillamail.com": "404 Not Found",
    "helpdeskeddy.com": "404 Not Found",
    "heroku.statuspage.io": "404 Not Found",
    "hubspot.com": "404 Not Found",
    "intercom.io": "This page is reserved for artistic dogs",
    "jetbrains.com": "404 Not Found",
    "landingi.com": "404 Not Found",
    "launchrock.com": "404 Not Found",
    "mashery.com": "Unrecognized domain",
    "ngrok.io": "404 Not Found",
    "npmjs.com": "404 Not Found",
    "readme.io": "404 Not Found",
    "simplebooklet.com": "404 Not Found",
    "smugmug.com": "404 Not Found",
    "strikingly.com": "404 Not Found",
    "tave.com": "404 Not Found",
    "teamwork.com": "404 Not Found",
    "thinkific.com": "404 Not Found",
    "tictail.com": "404 Not Found",
    "tumblr.com": "404 Not Found",
    "uberflip.com": "404 Not Found",
    "unbounce.com": "404 Not Found",
    "uservoice.com": "404 Not Found",
    "virb.com": "404 Not Found",
    "woocommerce.com": "404 Not Found",
    "wordpress.com": "404 Not Found",
    "wpengine.com": "404 Not Found",
    "zenefits.com": "404 Not Found",
    "zoho.com": "404 Not Found",
    "zoom.us": "404 Not Found",

    # ── Development / DevOps ──────────────────────────────────────────────────
    "github.io": "404 Not Found",
    "gitlab.io": "404 Not Found",
    "bitbucket.io": "404 Not Found",
    "firebaseapp.com": "404 Not Found",
    "web.app": "404 Not Found",
    "appspot.com": "404 Not Found",
    "now.sh": "404 Not Found",
    "vercel.app": "404 Not Found",
    "netlify.app": "404 Not Found",
    "render.com": "404 Not Found",
    "fly.dev": "404 Not Found",
    "railway.app": "404 Not Found",
    "onrender.com": "404 Not Found",
}

@tool("detect_subdomain_takeover")
def detect_subdomain_takeover(subdomain: str) -> str:
    """
    Nge-cek apakah sebuah subdomain rentan terhadap Subdomain Takeover 
    with menganalisa DNS CNAME dan fingerprint response HTTP-nya.
    """
    subdomain = subdomain.strip().replace("http://", "").replace("https://", "").split("/")[0]
    
    try:
        # 1. Cek CNAME Record
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        cname_target = str(answers[0].target).lower()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return f"[+] {subdomain}: Not memiliki CNAME record that mengarah ke external service (Aman)."

    # 2. Cek apakah CNAME mengarah ke cloud provider that kita kenal
    matched_provider = None
    for provider, sig in FINGERPRINTS.items():
        if provider in cname_target:
            matched_provider = provider
            break
            
    if not matched_provider:
        return f"[+] {subdomain}: Memiliki CNAME ke {cname_target}, tapi not cocok with signature takeover that diketahui."

    # 3. Kirim request HTTP for confirmation Fingerprint (Vulnerable atau Nggak)
    try:
        # Kirim request ke HTTP dan HTTPS with timeout cepat
        url = f"http://{subdomain}"
        auth_kw = get_auth_kwargs(subdomain)
        response = auth_get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"}, **auth_kw)
        response_text = response.text
        
        expected_fingerprint = FINGERPRINTS[matched_provider]
        if expected_fingerprint in response_text:
            return f"[CRITICAL] VULNERABLE TO SUBDOMAIN TAKEOVER! Subdomain '{subdomain}' mengarah ke CNAME '{cname_target}' dan mengembalikan fingerprint '{expected_fingerprint}'. Segera klaim atau laporkan!"
            
        return f"[+] {subdomain}: Mengarah ke {matched_provider} ({cname_target}), tetapi layanannya tampaknya aktif / already diklaim."
        
    except requests.RequestException:
        return f"[-] {subdomain}: Failed memvalidasi HTTP response for CNAME {cname_target} (Server down / RTO)."