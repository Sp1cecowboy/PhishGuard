from __future__ import annotations

from urllib.parse import urlsplit
import ipaddress
import re
from difflib import SequenceMatcher

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, field_validator

app = FastAPI(
    title="PhishGuard",
    description="Explainable, heuristic URL risk analysis for educational use.",
    version="0.1.0",
)


SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "top", "work", "country",
    "gq", "tk", "ml", "cf", "rest", "buzz", "fit"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "ow.ly", "buff.ly", "rb.gy",
    "shorturl.at", "rebrand.ly"
}

# Common official domains. This is a small allowlist,
# not a complete list of every legitimate brand domain.
BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "google": {"google.com", "youtube.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.de"},
    "dhl": {"dhl.com", "dhl.de"},
    "instagram": {"instagram.com"},
    "facebook": {"facebook.com", "fb.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
}

SUSPICIOUS_WORDS = {
    "login", "log-in", "signin", "sign-in", "verify",
    "verification", "account", "secure", "update",
    "password", "billing", "confirm", "wallet",
    "recover", "recovery", "unlock", "authentication",
    "webscr", "credential", "payment", "suspended"
}




class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("URL must not be empty")
        if any(ord(ch) < 32 for ch in value):
            raise ValueError("URL must not contain control characters")
        return value


class Finding(BaseModel):
    code: str
    severity: str
    points: int
    explanation: str


class AnalyzeResponse(BaseModel):
    normalized_url: str
    risk_score: int
    risk_level: str
    findings: list[Finding]
    disclaimer: str



def analyze_url(raw_url: str) -> AnalyzeResponse:
    candidate = raw_url.strip()

    # Reject non-web schemes.
    if re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*:",
        candidate
    ) and not re.match(
        r"^https?://", candidate, flags=re.IGNORECASE
    ):
        raise ValueError("Only HTTP and HTTPS URLs are supported")

    if not re.match(r"^https?://", candidate, flags=re.IGNORECASE):
        candidate = "https://" + candidate

    try:
        parsed = urlsplit(candidate)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Malformed URL or port") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported")

    if not hostname or (
        "." not in hostname and hostname != "localhost"
    ):
        raise ValueError("URL must contain a valid hostname")

    if any(not label for label in hostname.split(".")):
        raise ValueError("Malformed hostname")

    findings: list[Finding] = []

    def add(
        code: str,
        severity: str,
        points: int,
        explanation: str
    ) -> None:
        findings.append(
            Finding(
                code=code,
                severity=severity,
                points=points,
                explanation=explanation
            )
        )

    # Check whether hostname is an IP address.
    try:
        ipaddress.ip_address(hostname)
        host_is_ip = True
    except ValueError:
        host_is_ip = False

    if parsed.scheme.lower() == "http":
        add(
            "NO_HTTPS", "low", 8,
            "The URL uses HTTP rather than HTTPS. "
            "This alone does not mean phishing."
        )

    if host_is_ip:
        add(
            "IP_HOST", "high", 25,
            "The destination uses an IP address instead of a domain name."
        )

    # User-info can make a URL's real destination less obvious.
    if parsed.username is not None or parsed.password is not None:
        add(
            "URL_CREDENTIALS", "high", 30,
            "The URL contains user-info before the hostname, "
            "which can disguise the real destination."
        )

    if "@" in parsed.netloc and parsed.username is None:
        add(
            "AT_SYMBOL", "high", 20,
            "The URL contains '@', which may disguise the destination."
        )

    if hostname.startswith("xn--") or ".xn--" in hostname:
        add(
            "PUNYCODE", "medium", 18,
            "The hostname contains a punycode label. "
            "Check for lookalike characters."
        )

    if len(hostname) > 50:
        add(
            "LONG_HOSTNAME", "low", 8,
            "The hostname is unusually long."
        )

    labels = hostname.split(".")

    if len(labels) >= 5:
        add(
            "MANY_SUBDOMAINS", "medium", 12,
            "The hostname has many subdomain levels."
        )

    if re.search(r"[-_]{2,}", hostname):
        add(
            "REPEATED_SEPARATORS", "low", 6,
            "The hostname contains repeated separators."
        )

    if any(ch.isdigit() for ch in hostname) and not host_is_ip:
        add(
            "DIGITS_IN_HOST", "low", 4,
            "The hostname contains digits. This is a weak signal."
        )

    tld = labels[-1] if labels else ""

    if tld in SUSPICIOUS_TLDS:
        add(
            "UNCOMMON_TLD", "low", 10,
            f"The top-level domain '.{tld}' deserves extra scrutiny."
        )

    if hostname in URL_SHORTENERS:
        add(
            "URL_SHORTENER", "medium", 15,
            "A URL shortener hides the final destination."
        )

    # Check sensitive words in hostname and path.
    text_to_check = (
        hostname + " " + parsed.path.lower()
    ).replace("-", " ").replace("_", " ")

    matched_words = sorted(
        word for word in SUSPICIOUS_WORDS
        if re.search(
            r"(?<![a-z0-9])" + re.escape(word) + r"(?![a-z0-9])",
            text_to_check
        )
    )

    if matched_words:
        points = min(24, 8 + 4 * (len(matched_words) - 1))
        add(
            "SENSITIVE_KEYWORDS", "medium", points,
            "The hostname or path contains sensitive terms: "
            + ", ".join(matched_words) + "."
        )

    # Detect brand names in unrecognized hostnames.
    for brand, official_domains in BRAND_DOMAINS.items():
        brand_in_host = any(
            brand in label for label in labels
        )

        if not brand_in_host:
            continue

        is_official = any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in official_domains
        )

        if not is_official:
            add(
                "BRAND_IN_DOMAIN", "high", 25,
                f"The brand '{brand}' appears in a hostname "
                "not recognized as an official domain."
            )
            break

    # Detect some possible typosquatting attempts.
    if not host_is_ip:
        for brand, official_domains in BRAND_DOMAINS.items():
            is_official = any(
                hostname == domain or hostname.endswith("." + domain)
                for domain in official_domains
            )

            if is_official:
                continue

            typo_found = False

            for label in labels[:-1]:
                if len(label) < 5 or label == brand:
                    continue

                similarity = SequenceMatcher(
                    None, label, brand
                ).ratio()

                if similarity >= 0.78:
                    typo_found = True
                    break

            if typo_found:
                add(
                    "POSSIBLE_BRAND_TYPO", "high", 25,
                    f"A hostname label resembles '{brand}'. "
                    "Verify the domain independently."
                )
                break

    # Calculate the risk score.
    score = min(100, sum(item.points for item in findings))

    if score < 15:
        level = "low"
    elif score < 35:
        level = "medium"
    elif score < 60:
        level = "high"
    else:
        level = "critical"

    normalized = candidate.rstrip("#")

    return AnalyzeResponse(
        normalized_url=normalized,
        risk_score=score,
        risk_level=level,
        findings=findings,
        disclaimer=(
            "Heuristic estimate only, not a verdict. A low score does not "
            "prove a URL is safe, and a high score does not prove it is "
            "malicious. This prototype does not check live threat "
            "intelligence and does not open or fetch the destination."
        ),
    )



@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home() -> str:
    return """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishGuard</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#131b2e;--line:#27334c;--text:#eef3ff;--muted:#aab6ce;--accent:#70e1c1}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top right,#192947,var(--bg) 55%);color:var(--text);font:16px system-ui,sans-serif;min-height:100vh;display:grid;place-items:center;padding:24px}
main{width:min(760px,100%)}.eyebrow{color:var(--accent);font-weight:700;letter-spacing:.12em;text-transform:uppercase;font-size:.8rem}
h1{font-size:clamp(2rem,6vw,3.5rem);margin:.35rem 0}.lead{color:var(--muted);line-height:1.6}
.panel{background:#131b2eeF;border:1px solid var(--line);border-radius:20px;padding:24px;margin-top:24px;box-shadow:0 20px 80px #0004}
form{display:flex;gap:10px;flex-wrap:wrap}input{flex:1;min-width:220px;padding:14px;border-radius:10px;border:1px solid var(--line);background:#0b1020;color:var(--text);font:inherit}
button{padding:14px 18px;border:0;border-radius:10px;background:var(--accent);color:#092019;font-weight:800;font:inherit;cursor:pointer}
button:disabled{opacity:.6;cursor:wait}.result{margin-top:20px}.score{font-size:2.5rem;font-weight:800}.muted{color:var(--muted)}.finding{border:1px solid var(--line);padding:12px;border-radius:10px;margin:8px 0}.tag{font-size:.75rem;text-transform:uppercase;color:var(--accent);font-weight:700}.error{color:#ff9eaa}.foot{font-size:.85rem;color:var(--muted);line-height:1.5;margin-top:18px}
</style>
</head>
<body><main>
<div class="eyebrow">Security tooling · MVP 0.1</div><h1>PhishGuard</h1>
<p class="lead">Explainable URL risk analysis. Paste a URL to inspect suspicious indicators — without opening or fetching the destination.</p>
<section class="panel">
<form id="form"><input id="url" type="text" placeholder="https://example.com/login" required maxlength="2048" autocomplete="url"><button id="submit">Analyze URL</button></form>
<div id="result" class="result" aria-live="polite"></div>
<p class="foot">Educational prototype. Heuristic scores can produce false positives and false negatives. Never enter private or sensitive URLs.</p>
</section>
</main>
<script>
const form=document.querySelector('#form'), input=document.querySelector('#url'), result=document.querySelector('#result'), button=document.querySelector('#submit');
form.addEventListener('submit',async e=>{e.preventDefault();button.disabled=true;result.textContent='Analyzing…';
try{const r=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:input.value})});const data=await r.json();if(!r.ok)throw new Error(data.detail||'Request failed');
result.replaceChildren();const heading=document.createElement('div');heading.className='score';heading.textContent=`${data.risk_score}/100 · ${data.risk_level.toUpperCase()} RISK`;result.append(heading);
const url=document.createElement('p');url.className='muted';url.textContent=data.normalized_url;result.append(url);
if(!data.findings.length){const p=document.createElement('p');p.textContent='No configured indicators were detected.';result.append(p)}
for(const f of data.findings){const div=document.createElement('div');div.className='finding';const tag=document.createElement('div');tag.className='tag';tag.textContent=`${f.severity} · +${f.points} · ${f.code}`;const p=document.createElement('p');p.textContent=f.explanation;div.append(tag,p);result.append(div)}
const note=document.createElement('p');note.className='foot';note.textContent=data.disclaimer;result.append(note);
}catch(err){result.textContent='Error: '+err.message;result.className='result error'}finally{button.disabled=false}});
</script></body></html>
"""


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    try:
        return analyze_url(request.url)
    except ValueError as exc:
        from fastapi import HTTPException
        raise HTTPException(status_code=422, detail=str(exc)) from exc
if __name__ == "__main__":
    import threading
    import webbrowser
    import uvicorn

    threading.Timer(
        1.5,
        lambda: webbrowser.open("http://127.0.0.1:8000")
    ).start()

    uvicorn.run(app, host="127.0.0.1", port=8000)