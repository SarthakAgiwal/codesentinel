"""Threat model generated from the code, then editable by the analyst.

1. Discover what the application is made of, from the source (static - nothing is run):
   entry points (web routes, APIs, mobile components, CLI), data stores, external services,
   authentication, frameworks and deployment files - each with the file:line it was seen at.
2. Draw it as a data-flow diagram: actors -> entry points -> application -> data stores / services,
   grouped in trust boundaries (Internet, application, data, third parties).
3. List STRIDE threats per element. Each threat links to the scan findings that prove it
   ("finding exists"), shows mitigations seen in the code ("mitigation seen"), or asks for review.

The model is saved as threatmodel.json next to the scan results. Changes made in the diagram
(moved, renamed, added or deleted elements, threat status and notes) are kept, and marked as
analyst edits so a regeneration never overwrites them.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .source import NOT_OWN_CODE, _language

MAX_FILE = 600_000

STRIDE = {
    "S": "Spoofing", "T": "Tampering", "R": "Repudiation", "I": "Information disclosure",
    "D": "Denial of service", "E": "Elevation of privilege",
}
# CWE -> STRIDE letters (a finding can prove more than one threat type)
CWE_STRIDE = {
    **{c: "S" for c in (287, 290, 294, 295, 306, 307, 384, 521, 522, 613, 640, 1390, 1391)},
    **{c: "SI" for c in (259, 798, 321)},
    **{c: "T" for c in (20, 77, 79, 80, 89, 90, 91, 94, 95, 116, 352, 434, 470, 601, 611, 643, 915, 917, 943, 1321,
                        1336, 1427)},
    **{c: "TE" for c in (78, 22, 23, 36, 73, 502, 120, 119, 121, 122, 134, 787, 416)},
    **{c: "R" for c in (117, 223, 778, 532)},
    **{c: "I" for c in (200, 201, 209, 215, 312, 319, 326, 327, 328, 330, 338, 359, 538, 548, 916, 1004, 614, 489)},
    **{c: "D" for c in (400, 409, 674, 770, 776, 1333, 835)},
    **{c: "E" for c in (250, 269, 276, 284, 285, 639, 862, 863, 732, 266)},
    918: "IE", 942: "I", 346: "S", 353: "T", 693: "E", 1188: "E",
}


@dataclass
class Element:
    id: str
    kind: str                 # actor | entry | process | store | service | infra
    name: str
    zone: str                 # internet | app | data | third-party | device
    details: str = ""
    evidence: list = field(default_factory=list)     # ["file:line", ...]
    x: float = 0
    y: float = 0
    manual: bool = False      # added or edited by the analyst


@dataclass
class Flow:
    id: str
    src: str
    dst: str
    label: str
    crosses: bool = False     # crosses a trust boundary
    manual: bool = False


@dataclass
class Threat:
    id: str
    stride: str               # one letter
    element: str              # element id
    title: str
    description: str
    mitigation: str
    status: str = "Needs review"     # Finding exists | Control seen - verify | Needs review | Not applicable | Mitigated
    findings: list = field(default_factory=list)     # fingerprints
    evidence: list = field(default_factory=list)     # mitigation evidence "file:line"
    note: str = ""
    manual: bool = False


@dataclass
class ThreatModel:
    project: str
    generated: str
    summary: dict = field(default_factory=dict)
    elements: list = field(default_factory=list)
    flows: list = field(default_factory=list)
    threats: list = field(default_factory=list)
    edited: str = ""

    def el(self, eid: str) -> Element | None:
        return next((e for e in self.elements if e.id == eid), None)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ThreatModel":
        return cls(project=d.get("project", ""), generated=d.get("generated", ""), summary=d.get("summary", {}),
                   elements=[Element(**e) for e in d.get("elements", [])],
                   flows=[Flow(**f) for f in d.get("flows", [])],
                   threats=[Threat(**t) for t in d.get("threats", [])], edited=d.get("edited", ""))

    def save(self, folder: str | Path) -> Path:
        p = Path(folder) / "threatmodel.json"
        p.write_text(json.dumps(self.to_dict(), indent=1), encoding="utf-8")
        return p


def load(folder: str | Path) -> ThreatModel | None:
    p = Path(folder) / "threatmodel.json"
    try:
        return ThreatModel.from_dict(json.loads(p.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError):
        return None


# ---------------------------------------------------------------- discovery patterns
ROUTE_PATTERNS = [
    # (framework, regex with a group for METHOD (optional) and PATH)
    ("Flask/FastAPI", re.compile(r"@\w+\.(route|get|post|put|delete|patch)\(\s*['\"]([^'\"]+)")),
    ("Django", re.compile(r"\b(path|re_path|url)\(\s*r?['\"]([^'\"]*)['\"]\s*,")),
    ("Express/Koa", re.compile(r"(?<!@)\b(?:app|router|server|api)\.(get|post|put|delete|patch|all|use)\(\s*['\"`](/[^'\"`]*)")),
    ("Spring", re.compile(r"@(Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*\"([^\"]*)")),
    ("JAX-RS", re.compile(r"@(Path)\(\s*\"([^\"]+)")),
    ("ASP.NET", re.compile(r"\[(Http(?:Get|Post|Put|Delete|Patch)|Route)\(\s*\"([^\"]*)")),
    ("Laravel", re.compile(r"Route::(get|post|put|delete|patch|any|match)\(\s*['\"]([^'\"]+)")),
    ("Rails", re.compile(r"^\s*(get|post|put|patch|delete|resources?)\s+['\":]([\w/:{}-]+)")),
    ("aiohttp", re.compile(r"\.add_route\(\s*['\"](\w+)['\"]\s*,\s*r?['\"]([^'\"]+)")),
    ("aiohttp", re.compile(r"\.add_(get|post|put|delete|patch)\(\s*r?['\"]([^'\"]+)")),
    ("Go", re.compile(r"\.(HandleFunc|Handle|GET|POST|PUT|DELETE|PATCH|Get|Post)\(\s*\"(/[^\"]*)")),
    ("PHP page", re.compile(r"\$_(GET|POST|REQUEST|COOKIE)\[\s*['\"]([^'\"]+)")),
]
GRAPHQL = re.compile(r"\b(ApolloServer|graphqlHTTP|GraphQLSchema|strawberry\.Schema|graphene\.Schema|@QueryMapping)\b")
WEBSOCKET = re.compile(r"\b(socket\.io|WebSocketServer|websockets\.serve|@ServerEndpoint|SignalR|ws\.Server)\b")
CLI = re.compile(r"\b(argparse\.ArgumentParser|click\.command|typer\.Typer|process\.argv|commander|cobra\.Command|"
                 r"static void main\s*\(\s*String)\b")
QUEUES = re.compile(r"\b(KafkaConsumer|kafka\.Consumer|pika\.|amqplib|@RabbitListener|@KafkaListener|SQS|"
                    r"celery|bullmq|Bull\(|sidekiq)\b", re.I)

STORES = {
    "SQL database": re.compile(r"\b(sqlite3|psycopg2?|mysql\.connector|pymysql|SQLAlchemy|sequelize|knex|"
                               r"typeorm|prisma|mysql2|pg\.Pool|new Pool\(|aiopg|asyncpg|aiomysql|DriverManager\.getConnection|"
                               r"JdbcTemplate|EntityManager|DbContext|PDO\(|mysqli_connect|database/sql|gorm\.)", re.I),
    "MongoDB": re.compile(r"\b(pymongo|MongoClient|mongoose|mongodb://|MongoRepository)\b"),
    "Redis cache": re.compile(r"\b(redis\.Redis|ioredis|aioredis|RedisStorage|createClient\(|Jedis|StackExchange\.Redis|redis://)\b"),
    "Elasticsearch": re.compile(r"\b(Elasticsearch\(|@elastic/elasticsearch|RestHighLevelClient)\b"),
    "File storage": re.compile(r"\b(multer|UploadedFile|MultipartFile|request\.files|IFormFile|move_uploaded_file|"
                               r"fs\.writeFile|createWriteStream)\b"),
    "Cloud object storage": re.compile(r"\b(boto3\.client\(\s*['\"]s3|S3Client|AmazonS3|BlobServiceClient|"
                                       r"google\.cloud\.storage|@aws-sdk/client-s3)\b"),
}
SERVICES = {
    "Payment provider": re.compile(r"\b(stripe|braintree|paypal|razorpay|adyen)\b", re.I),
    "Email / SMS": re.compile(r"\b(smtplib|nodemailer|sendgrid|twilio|mailgun|JavaMailSender|SmtpClient)\b", re.I),
    "Identity provider (OAuth/SSO)": re.compile(r"\b(oauth2|passport-(google|facebook|github|saml)|openid|"
                                               r"auth0|okta|keycloak|cognito|msal|firebase\.auth)\b", re.I),
    "Cloud APIs": re.compile(r"\b(boto3|aws-sdk|@aws-sdk|google\.cloud|googleapis|azure\.|@azure/)\b"),
    "AI / LLM API": re.compile(r"\b(openai|anthropic|langchain|ollama|huggingface)\b", re.I),
    "Analytics / monitoring": re.compile(r"\b(sentry|datadog|newrelic|prometheus|google-analytics|mixpanel)\b", re.I),
}
OUTBOUND_HTTP = re.compile(r"""(requests\.(get|post|put|delete)|axios\.(get|post)|fetch\(|urlopen\(|HttpClient|
                               RestTemplate|WebClient|http\.Get\(|curl_exec|Net::HTTP)\s*\(?\s*[f'"`]?(?P<url>https?://[^'"`\s)]+)?""",
                           re.X)
AUTH = {
    "JWT tokens": re.compile(r"\b(jsonwebtoken|jwt\.(sign|verify|encode|decode)|PyJWT|JwtBuilder|Jwts\.|"
                             r"System\.IdentityModel\.Tokens\.Jwt|express-jwt)\b"),
    "Session cookies": re.compile(r"\b(express-session|flask_login|session\[|HttpSession|SessionMiddleware|"
                                  r"cookie-session|\$_SESSION)\b"),
    "Framework security": re.compile(r"\b(spring-boot-starter-security|@PreAuthorize|@Secured|SecurityFilterChain|"
                                     r"\[Authorize\]|login_required|@login_required|IsAuthenticated|passport\.authenticate|"
                                     r"Devise|has_secure_password)\b"),
    "Password hashing": re.compile(r"\b(bcrypt|argon2|scrypt|pbkdf2|PasswordEncoder|password_hash\()\b", re.I),
}
MITIGATIONS = {
    "CSRF protection": (re.compile(r"\b(csurf|CSRFProtect|csrf_token|@csrf|AntiForgery|csrf\(\)|"
                                   r"ValidateAntiForgeryToken)\b", re.I), "T"),
    "Rate limiting": (re.compile(r"\b(express-rate-limit|rateLimit|slowapi|flask_limiter|Bucket4j|"
                                 r"RateLimiter|throttle)\b", re.I), "D"),
    "Security headers": (re.compile(r"\b(helmet|Talisman|Content-Security-Policy|X-Frame-Options|"
                                    r"Strict-Transport-Security)\b"), "TI"),
    "Input validation": (re.compile(r"\b(joi|yup|zod|express-validator|pydantic|marshmallow|@Valid|"
                                    r"Validator|FluentValidation|class-validator)\b"), "T"),
    "Audit logging": (re.compile(r"\b(audit|winston|bunyan|pino|logging\.getLogger|log4j|slf4j|Serilog|"
                                 r"ILogger)\b", re.I), "R"),
    "TLS enforced": (re.compile(r"\b(requireHttps|HTTPS_ONLY|SECURE_SSL_REDIRECT|UseHttpsRedirection|"
                                r"requiresSecure|hsts)\b", re.I), "I"),
    "Parameterised queries": (re.compile(r"(\?\s*,|%s\s*\"?\s*,\s*\(|PreparedStatement|:\w+\s*\)|bindParam|"
                                         r"\$\d\b|@Param\()"), "T"),
    "Access control checks": (re.compile(r"\b(@PreAuthorize|@Secured|\[Authorize|login_required|isAuthenticated|"
                                         r"requireAuth|authorize\(|can\?|Gate::|@RolesAllowed|permission_required)\b"),
                              "E"),
}
INFRA = {
    "Docker container": re.compile(r"(^|/)Dockerfile[^/]*$|(^|/)docker-compose[^/]*\.ya?ml$", re.I),
    "Kubernetes": re.compile(r"(^|/)(k8s|kubernetes|helm|charts)/|kind:\s*(Deployment|Service|Ingress)", re.I),
    "Terraform / cloud": re.compile(r"\.tf$", re.I),
    "CI/CD pipeline": re.compile(r"(^|/)(\.github/workflows/|\.gitlab-ci\.ya?ml$|Jenkinsfile$|azure-pipelines)", re.I),
}
FRAMEWORK_DEPS = {
    "flask": "Flask", "django": "Django", "fastapi": "FastAPI", "express": "Express", "koa": "Koa",
    "@nestjs/core": "NestJS", "next": "Next.js", "spring-boot": "Spring Boot", "laravel/framework": "Laravel",
    "rails": "Ruby on Rails", "gin-gonic/gin": "Gin", "aiohttp": "aiohttp", "angular": "Angular", "react": "React",
    "vue": "Vue", "flutter": "Flutter",
}


# ---------------------------------------------------------------- generic STRIDE catalogue per element kind
CATALOGUE = {
    "actor": [
        ("S", "Attacker impersonates a legitimate user",
         "Stolen, guessed or reused credentials or session tokens let an attacker act as {name}.",
         "Strong authentication, MFA for sensitive roles, account lockout, secure session handling."),
        ("R", "User denies an action",
         "Without reliable logs, {name} can deny having performed a sensitive action.",
         "Record security-relevant actions with user, time and source in tamper-resistant logs."),
    ],
    "entry": [
        ("S", "Unauthenticated access to {name}",
         "Requests to {name} may be accepted without verifying who sent them.",
         "Require authentication on every non-public route; deny by default."),
        ("T", "Malicious input through {name}",
         "Parameters, headers, bodies and files sent to {name} can carry injection, XSS, path traversal or "
         "deserialization payloads.",
         "Validate input with allow-lists, use parameterised queries, encode output, avoid dangerous APIs."),
        ("I", "Sensitive data exposed by {name}",
         "Responses or errors from {name} may leak internal data, stack traces or other users' records.",
         "Return only needed fields, generic error messages, enforce TLS."),
        ("D", "{name} flooded or abused",
         "Expensive requests to {name} can exhaust CPU, memory or downstream services.",
         "Rate limiting, request size limits, timeouts, pagination."),
        ("E", "Broken access control on {name}",
         "A user may reach functions or other users' data through {name} (IDOR, missing role checks).",
         "Check authorisation on the server for every object and action."),
    ],
    "process": [
        ("T", "Application logic or components tampered with",
         "Vulnerable third-party components or unsafe code paths let an attacker change application behaviour.",
         "Patch vulnerable dependencies, review dangerous code paths, sign and verify builds."),
        ("R", "Security events not logged",
         "Logins, permission changes and data exports may not be logged, so incidents cannot be investigated.",
         "Centralised audit logging of security events without sensitive data."),
        ("I", "Weak or misused cryptography",
         "Broken hashes (MD5/SHA-1), weak ciphers, predictable random numbers or disabled certificate checks "
         "expose or let attackers forge protected data.",
         "Use vetted algorithms (AES-GCM, SHA-256+, bcrypt/argon2 for passwords), secure random, keep TLS "
         "verification on."),
        ("I", "Secrets and keys exposed",
         "Hard-coded credentials, keys in the repository or verbose logs disclose secrets.",
         "Keep secrets in a vault or environment, rotate leaked ones, scrub logs."),
        ("E", "Code execution in the application",
         "Command injection, unsafe deserialization or vulnerable components can give an attacker the "
         "application's privileges.",
         "Avoid shell/eval/deserialization of untrusted data; run with least privilege."),
    ],
    "store": [
        ("T", "Data in {name} modified by an attacker",
         "Injection or broken access control lets an attacker change records in {name}.",
         "Parameterised queries, least-privilege database accounts, integrity checks."),
        ("I", "Data in {name} disclosed",
         "Records in {name} may be read through injection, backups or weak encryption.",
         "Encrypt sensitive data at rest, restrict network access, least-privilege accounts."),
        ("D", "{name} unavailable",
         "Heavy or malicious queries can exhaust {name}.",
         "Query limits, timeouts, connection pooling, backups."),
    ],
    "service": [
        ("S", "Fake or compromised {name}",
         "If the connection to {name} is not authenticated, an attacker can impersonate it.",
         "Verify TLS certificates, use signed webhooks and scoped API keys."),
        ("I", "Data sent to {name} exposed",
         "Data shared with {name} leaves your control; keys for it may leak.",
         "Send minimal data, protect API keys, review the provider's security."),
        ("E", "Server-side request forgery via {name} calls",
         "If request URLs are built from user input, attackers can make the server call internal systems.",
         "Allow-list destinations, block internal addresses, never forward raw user URLs."),
    ],
    "infra": [
        ("E", "Insecure deployment configuration ({name})",
         "Containers or cloud resources running as root, with open ports or public access widen any compromise.",
         "Least privilege, non-root containers, private networking, review IaC findings."),
        ("T", "Build or deployment pipeline tampering ({name})",
         "A compromised pipeline or base image can inject malicious code into releases.",
         "Pin images and actions, protect pipeline secrets, require reviews."),
    ],
}


# ---------------------------------------------------------------- discovery
def _files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file() or p.is_symlink():
            continue
        rel = p.relative_to(root).as_posix()
        if any(part in NOT_OWN_CODE for part in rel.split("/")[:-1]):
            continue
        yield rel, p


def discover(root: str | Path) -> dict:
    root = Path(root)
    found = {"routes": defaultdict(list), "graphql": [], "websocket": [], "cli": [], "queues": [],
             "stores": defaultdict(list), "services": defaultdict(list), "auth": defaultdict(list),
             "mitigations": defaultdict(list), "infra": defaultdict(list), "outbound": [], "frameworks": set(),
             "android": [], "ios": False, "frontend": False}
    for rel, p in _files(root):
        for name, rx in INFRA.items():
            if rx.search(rel):
                found["infra"][name].append(rel)
        low = rel.lower()
        if low.endswith("androidmanifest.xml"):
            txt = p.read_text(encoding="utf-8", errors="replace")
            for m in re.finditer(r"<(activity|service|receiver|provider)[^>]*android:name=\"([^\"]+)\"[^>]*>", txt):
                if 'android:exported="true"' in m.group(0) or "<intent-filter" in txt[m.end():m.end() + 400]:
                    line = txt[:m.start()].count("\n") + 1
                    found["android"].append((f"{m.group(1)} {m.group(2).split('.')[-1]}", f"{rel}:{line}"))
            continue
        if low.endswith(("info.plist", ".xcodeproj/project.pbxproj")):
            found["ios"] = True
        if low.endswith("package.json") or low.endswith(
                ("requirements.txt", "pom.xml", "build.gradle", "composer.json", "gemfile", "go.mod", "pubspec.yaml")):
            txt = p.read_text(encoding="utf-8", errors="replace").lower()
            for dep, fw in FRAMEWORK_DEPS.items():
                if re.search(r"(^|[\"'\s/:])" + re.escape(dep) + r"($|[\"'\s=<>~^:@\[,])", txt, re.M):
                    found["frameworks"].add(fw)
        lang = _language(p)
        if not lang or lang[0] in ("JSON", "YAML", "XML", "Properties", "CSS", "SCSS"):
            continue
        if lang[0] in ("HTML", "Vue", "Svelte") or "/frontend/" in f"/{low}" or "/src/app/" in f"/{low}":
            found["frontend"] = True
        try:
            if p.stat().st_size > MAX_FILE:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()

        def where(pos: int) -> str:
            return f"{rel}:{text.count(chr(10), 0, pos) + 1}"

        is_test = re.search(r"(^|/)(tests?|spec|__tests__|cypress|e2e)/|\.(test|spec)\.", low)
        if not is_test and "/frontend/" not in f"/{low}":
            for fw, rx in ROUTE_PATTERNS:
                for m in rx.finditer(text):
                    path = m.group(2)
                    if fw == "Express/Koa" and m.group(1) == "use" and not path.startswith("/"):
                        continue
                    if fw == "Django" and "urls" not in low:
                        continue
                    method = m.group(1).upper() if m.group(1) and fw not in ("Django", "JAX-RS", "PHP page") else ""
                    if method in ("ROUTE", "USE", "ALL", "REQUEST", "RESOURCES", "RESOURCE", "HANDLE", "HANDLEFUNC"):
                        method = ""
                    if fw == "PHP page":
                        path, method = "/" + rel, f"{m.group(1)} {m.group(2)}"
                    found["routes"][fw].append((method, path, where(m.start())))
            for key, rx in (("graphql", GRAPHQL), ("websocket", WEBSOCKET), ("cli", CLI), ("queues", QUEUES)):
                if (m := rx.search(text)):
                    found[key].append(where(m.start()))
        if is_test:
            continue
        for name, rx in STORES.items():
            if (m := rx.search(text)):
                found["stores"][name].append(where(m.start()))
        for name, rx in SERVICES.items():
            if (m := rx.search(text)):
                found["services"][name].append(where(m.start()))
        for name, rx in AUTH.items():
            if (m := rx.search(text)):
                found["auth"][name].append(where(m.start()))
        for name, (rx, _) in MITIGATIONS.items():
            if (m := rx.search(text)):
                found["mitigations"][name].append(where(m.start()))
        for m in OUTBOUND_HTTP.finditer(text):
            url = m.group("url") or ""
            host = re.sub(r"^https?://", "", url).split("/")[0] if url else ""
            if host and not re.match(r"(localhost|127\.|0\.0\.0\.0|example\.|\$\{)", host):
                found["outbound"].append((host, where(m.start())))
        del lines
    return found


def _group_routes(routes: dict) -> list[tuple[str, list]]:
    """Group routes by their first path segment: /api/users/1 and /api/users -> 'api/users'."""
    groups = defaultdict(list)
    for fw, items in routes.items():
        for method, path, ev in items:
            segs = [s for s in re.split(r"[/]", path) if s and not s.startswith((":", "{", "<", "*", "("))]
            key = "/" + "/".join(segs[:2]) if segs else "/"
            if segs and segs[0] in ("api", "rest", "v1", "v2", "v3") and len(segs) > 1:
                key = "/" + "/".join(segs[:2])
            elif segs:
                key = "/" + segs[0]
            groups[key].append((fw, method, path, ev))
    return sorted(groups.items(), key=lambda kv: -len(kv[1]))


# ---------------------------------------------------------------- build
def build(project: str, root: str | Path, findings: list[dict], inventory: dict | None = None,
          previous: ThreatModel | None = None, max_entry_groups: int = 12) -> ThreatModel:
    f = discover(root)
    inv = inventory or {}
    els: list[Element] = []
    flows: list[Flow] = []

    def add(kind, name, zone, details="", evidence=()):
        eid = f"{kind}-{re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')[:40]}"
        if any(e.id == eid for e in els):
            return eid
        els.append(Element(eid, kind, name, zone, details, list(evidence)[:12]))
        return eid

    fws = sorted(f["frameworks"])
    app = add("process", "Application server" if f["routes"] or f["graphql"] else "Application", "app",
              ", ".join(fws) or ", ".join(list((inv.get("languages") or {}).keys())[:3]))
    user = add("actor", "User (browser / client)" if f["routes"] or f["frontend"] or f["graphql"] else "User",
               "internet", "Anyone who can reach the application, including attackers")
    if f["frontend"]:
        fe = add("process", "Web front-end", "device", "Code running in the user's browser - fully attacker-controlled")
        flows.append(Flow("f-user-fe", user, fe, "uses", False))
    groups = _group_routes(f["routes"])
    for key, items in groups[:max_entry_groups]:
        methods = sorted({m for _, m, _, _ in items if m})
        eid = add("entry", f"{key} ({len(items)} route{'s' if len(items) != 1 else ''})", "app",
                  f"{', '.join(sorted({fw for fw, *_ in items}))}; methods: {', '.join(methods) or 'any'}; "
                  f"e.g. {', '.join(sorted({p for _, _, p, _ in items})[:4])}", [ev for *_, ev in items])
        src = fe if f["frontend"] else user
        flows.append(Flow(f"f-{src}-{eid}", src, eid, "HTTP(S) request", True))
        flows.append(Flow(f"f-{eid}-{app}", eid, app, "calls", False))
    if len(groups) > max_entry_groups:
        rest = groups[max_entry_groups:]
        eid = add("entry", f"Other routes ({sum(len(i) for _, i in rest)})", "app",
                  ", ".join(k for k, _ in rest[:10]), [i[0][3] for _, i in rest[:10]])
        flows.append(Flow(f"f-{user}-{eid}", fe if f["frontend"] else user, eid, "HTTP(S) request", True))
        flows.append(Flow(f"f-{eid}-{app}", eid, app, "calls", False))
    for key, label in (("graphql", "GraphQL API"), ("websocket", "WebSocket channel"), ("queues", "Message queue consumer"),
                       ("cli", "Command-line interface")):
        if f[key]:
            eid = add("entry", label, "app", "", f[key])
            src = user if key in ("graphql", "websocket") else add("actor", "Operator / other system", "internet")
            flows.append(Flow(f"f-{src}-{eid}", src, eid, "input", True))
            flows.append(Flow(f"f-{eid}-{app}", eid, app, "calls", False))
    if f["android"] or f["ios"]:
        dev = add("process", "Mobile app on the device", "device",
                  "Runs on devices you do not control - assume it can be reverse-engineered")
        flows.append(Flow(f"f-{user}-{dev}", user, dev, "uses", False))
        for name, ev in f["android"][:8]:
            eid = add("entry", f"Android {name} (exported)", "device", "Reachable by other apps on the device", [ev])
            other = add("actor", "Other apps on the device", "device", "Including malicious apps")
            flows.append(Flow(f"f-{other}-{eid}", other, eid, "intent / IPC", True))
            flows.append(Flow(f"f-{eid}-{dev}", eid, dev, "calls", False))
        if f["routes"]:
            flows.append(Flow(f"f-{dev}-{app}", dev, app, "API calls", True))
    if not groups and not f["graphql"] and not f["android"] and not f["cli"]:
        flows.append(Flow(f"f-{user}-{app}", user, app, "input", True))
    for name, ev in f["stores"].items():
        sid = add("store", name, "data", "", ev)
        flows.append(Flow(f"f-{app}-{sid}", app, sid, "reads / writes", True))
    for name, ev in f["services"].items():
        sid = add("service", name, "third-party", "", ev)
        flows.append(Flow(f"f-{app}-{sid}", app, sid, "API calls", True))
    hosts = defaultdict(list)
    for h, ev in f["outbound"]:
        hosts[h].append(ev)
    for h, ev in sorted(hosts.items(), key=lambda kv: -len(kv[1]))[:6]:
        sid = add("service", h, "third-party", "Outbound HTTP calls", ev)
        flows.append(Flow(f"f-{app}-{sid}", app, sid, "HTTPS", True))
    for name, ev in f["infra"].items():
        add("infra", name, "app", ", ".join(ev[:5]), ev)
    auth = {k: v for k, v in f["auth"].items()}
    if auth:
        e = next(e for e in els if e.id == app)
        e.details += ("; " if e.details else "") + "auth: " + ", ".join(auth)
        e.evidence += [v[0] for v in auth.values()]

    # ---- threats
    threats: list[Threat] = []
    mitig = {k: v for k, v in f["mitigations"].items()}
    for e in els:
        for letter, title, desc, fix in CATALOGUE.get(e.kind, []):
            t = Threat(id=f"T-{len(threats) + 1:03d}", stride=letter, element=e.id, title=title.format(name=e.name),
                       description=desc.format(name=e.name), mitigation=fix)
            for mname, ev in mitig.items():
                if letter in MITIGATIONS[mname][1]:
                    t.evidence.append(f"{mname}: {ev[0]}")
            threats.append(t)
    _link_findings(threats, els, findings)

    tm = ThreatModel(project=project, generated=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     elements=els, flows=flows, threats=threats)
    tm.summary = {"frameworks": fws, "entry_points": sum(len(v) for v in f["routes"].values()),
                  "auth": sorted(auth), "mitigations_seen": sorted(mitig), "stores": sorted(f["stores"]),
                  "services": sorted(f["services"]) + [h for h in sorted(hosts)[:6]],
                  "infra": sorted(f["infra"])}
    layout(tm)
    if previous:
        merge_edits(tm, previous)
    return tm


def _cwe_num(cwe: str) -> int | None:
    m = re.search(r"(\d+)", cwe or "")
    return int(m.group(1)) if m else None


def _link_findings(threats: list[Threat], els: list[Element], findings: list[dict]) -> None:
    """Attach open findings to the STRIDE threats they prove, on the most specific element."""
    by_el = defaultdict(list)
    for t in threats:
        by_el[t.element].append(t)
    entries = [e for e in els if e.kind == "entry"]
    stores = [e for e in els if e.kind == "store"]
    app = next((e for e in els if e.kind == "process" and e.zone == "app"), None)
    for d in findings:
        if d.get("verdict") != "open":
            continue
        cat = d.get("category")
        letters = CWE_STRIDE.get(_cwe_num(d.get("cwe", "")), "")
        if cat == "secret":
            letters = "SI"
        elif cat == "sca":
            letters = "TE"
        elif cat in ("iac", "cicd"):
            letters = "ET"
        if not letters:
            letters = "T"
        # where does it belong? entry point whose evidence file matches, a store for injection, else the app
        target = None
        if cat in ("iac", "cicd"):
            target = next((e for e in els if e.kind == "infra"), None)
        if target is None and cat == "sast":
            target = next((e for e in entries if any(ev.split(":")[0] == d.get("file") for ev in e.evidence)), None)
        if target is None and cat == "sast" and _cwe_num(d.get("cwe", "")) in (89, 943, 90, 91, 643) and stores:
            want = "MongoDB" if _cwe_num(d.get("cwe", "")) == 943 else "SQL database"
            target = next((s for s in stores if s.name == want), None) or stores[0]
        target = target or app
        if not target:
            continue
        num = _cwe_num(d.get("cwe", ""))
        hint = ("cryptography" if num in (295, 326, 327, 328, 330, 338, 916, 319) else
                "Secrets" if cat == "secret" or num in (259, 798, 321, 312, 532) else "")
        for letter in letters:
            cands = [t for t in by_el[target.id] if t.stride == letter] or \
                    ([t for t in by_el[app.id] if t.stride == letter] if app else [])
            if hint:
                cands = sorted(cands, key=lambda t: hint.lower() not in t.title.lower())
            if cands:
                t = cands[0]
                if d["fingerprint"] not in t.findings:
                    t.findings.append(d["fingerprint"])
    for t in threats:
        if t.findings:
            t.status = "Finding exists"
        elif t.evidence:
            t.status = "Control seen - verify"


ZONE_COL = {"internet": 0, "device": 1, "app": 2, "data": 3, "third-party": 3}


def layout(tm: ThreatModel) -> None:
    """Columns: internet | device | application | data & third parties. Rows stacked per column."""
    cols = defaultdict(list)
    for e in tm.elements:
        c = ZONE_COL.get(e.zone, 2)
        if e.kind == "process" and e.zone == "app":
            c = 2.6                                   # the app server sits right of its entry points
        if e.kind == "infra":
            c = 2.6
        cols[c].append(e)
    xs = {c: 40 + 250 * i for i, c in enumerate(sorted(cols))}       # only the columns in use, no gaps
    for c, items in cols.items():
        order = sorted(items, key=lambda e: (e.zone == "third-party", e.kind == "infra", e.kind != "process"))
        for i, e in enumerate(order):
            e.x, e.y = xs[c], 60 + i * 95


def merge_edits(new: ThreatModel, old: ThreatModel) -> None:
    """Keep the analyst's work: positions, manual elements/flows/threats, statuses and notes."""
    oldel = {e.id: e for e in old.elements}
    for e in new.elements:
        if e.id in oldel:
            o = oldel[e.id]
            e.x, e.y = o.x, o.y
            if o.manual:
                e.name, e.details, e.manual = o.name, o.details, True
    ids = {e.id for e in new.elements}
    new.elements += [e for e in old.elements if e.manual and e.id not in ids]
    deleted = set(old.summary.get("deleted", []))
    new.elements = [e for e in new.elements if e.id not in deleted]
    fids = {f.id for f in new.flows}
    new.flows += [f for f in old.flows if f.manual and f.id not in fids]
    new.flows = [f for f in new.flows if f.src not in deleted and f.dst not in deleted
                 and f.id not in set(old.summary.get("deleted_flows", []))]
    oldt = {(t.element, t.stride, t.title): t for t in old.threats}
    for t in new.threats:
        o = oldt.get((t.element, t.stride, t.title))
        if o and o.status in ("Not applicable", "Mitigated") or (o and o.note):
            t.status, t.note = (o.status if o.status in ("Not applicable", "Mitigated") else t.status), o.note
    new.threats += [t for t in old.threats if t.manual]
    new.threats = [t for t in new.threats if t.element not in deleted]
    new.summary["deleted"] = sorted(deleted)
    new.summary["deleted_flows"] = old.summary.get("deleted_flows", [])
    new.edited = old.edited


def stride_counts(tm: ThreatModel) -> dict:
    out = {k: {"total": 0, "finding": 0} for k in STRIDE}
    for t in tm.threats:
        out[t.stride]["total"] += 1
        out[t.stride]["finding"] += t.status == "Finding exists"
    return out
