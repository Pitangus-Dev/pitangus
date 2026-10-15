const express = require("express"); const cp = require("child_process"); const fs = require("fs"); const jwt = require("jsonwebtoken");
const app = express();
// ruleid: appsec.js.command-injection
app.get("/run", (req, res) => { const cmd = req.query.cmd; cp.exec("ls " + cmd, () => {}); res.send("ok"); });
// ruleid: appsec.js.path-traversal
app.get("/file", (req, res) => { const p = req.params.name; fs.readFileSync("/data/" + p); });
// ruleid: appsec.js.open-redirect
app.get("/go", (req, res) => { res.redirect(req.query.next); });
// ruleid: appsec.js.dom-xss-sink
function render(el, html) { el.innerHTML = html; }
// ruleid: appsec.js.eval-non-literal
function calc(expr) { return eval(expr); }
// ruleid: appsec.js.jwt-hardcoded-secret
jwt.sign({ id: 1 }, "super-secret-hardcoded-value");
// ruleid: appsec.js.tls-reject-unauthorized-false
const agent = { rejectUnauthorized: false };
// ruleid: appsec.js.sql-injection
app.get("/u", (req, res) => { db.query("SELECT * FROM users WHERE id = " + req.query.id); });
// ruleid: appsec.js.jwt-none-algorithm
jwt.verify(token, secret, { algorithms: ["HS256", "none"] });
// ruleid: appsec.js.weak-hash
const crypto = require("crypto"); crypto.createHash("md5");

// What the rules must leave alone: `exec` that isn't child_process's.
function notShell(req) {
  const pattern = /^[a-z]+$/;
  // ok: appsec.js.command-injection
  pattern.exec(req.query.name);
  const queue = require('./queue');
  // ok: appsec.js.command-injection
  queue.exec(req.query.job);
}

// Safe counterparts: what the rules must leave alone.
function safe(req, res, db, el, jwt, crypto, fs, path, https) {
  // ok: appsec.js.eval-non-literal
  eval("1 + 1");
  // ok: appsec.js.sql-injection
  db.query("SELECT * FROM users WHERE id = $1", [req.query.id]);
  // ok: appsec.js.dom-xss-sink
  el.textContent = req.query.name;
  // ok: appsec.js.dom-xss-sink
  document.getElementById("record").innerHTML = document.getElementById(id).innerHTML;
  // ok: appsec.js.dom-xss-sink
  content.innerHTML = policy.createHTML(data.content);
  // ok: appsec.js.dom-xss-sink
  preview.innerHTML = DOMPurify.sanitize(req.query.html);
  // ok: appsec.js.dom-xss-sink
  el.insertAdjacentHTML("beforeend", "<li>static</li>");
  // ruleid: appsec.js.dom-xss-sink
  bubble.innerHTML = message;
  // ruleid: appsec.js.dom-xss-sink
  cell.innerHTML = '<input value="' + user['first_name'] + '" />';
  // ok: appsec.js.path-traversal
  fs.readFileSync(path.join("/data", path.basename(req.query.file)));
  // ok: appsec.js.open-redirect
  res.redirect("/dashboard");
  // ok: appsec.js.jwt-none-algorithm
  jwt.verify(req.headers.authorization, process.env.JWT_KEY, { algorithms: ["RS256"] });
  // ok: appsec.js.jwt-hardcoded-secret
  jwt.sign({ sub: 1 }, process.env.JWT_KEY);
  // ok: appsec.js.tls-reject-unauthorized-false
  https.request({ host: "api.example.com", rejectUnauthorized: true });
  // ok: appsec.js.weak-hash
  crypto.createHash("sha256");
}

// AI-generated code, the usual slips.
// ruleid: appsec.js.supabase-service-role-key
const supabaseAdmin = createClient(url, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiYyIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJpYXQiOjF9.fakeSignatureForTestsOnly123"); // gitleaks:allow
// ok: appsec.js.supabase-service-role-key
const supabaseAnon = createClient(url, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiYyIsInJvbGUiOiJhbm9uIn0.fakeSignatureForTestsOnly123"); // gitleaks:allow
// ruleid: appsec.js.public-env-secret
const stripe = new Stripe(process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY);
// ruleid: appsec.js.public-env-secret
const admin = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY);
// ok: appsec.js.public-env-secret
const anon = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);
// ok: appsec.js.public-env-secret
const serverOnly = process.env.STRIPE_SECRET_KEY;
// ruleid: appsec.js.public-env-secret
const openai = new OpenAI({ apiKey: import.meta.env.VITE_OPENAI_API_KEY, dangerouslyAllowBrowser: true });
// ruleid: appsec.js.public-env-secret
const octokit = new Octokit({ auth: process.env.NEXT_PUBLIC_GITHUB_TOKEN });
// ruleid: appsec.js.public-env-secret
const mail = sendgrid(process.env.REACT_APP_SENDGRID_APIKEY);
// ruleid: appsec.js.public-env-secret
const s3 = new S3({ accessKeyId: import.meta.env.VITE_AWS_ACCESS_KEY_ID, secretAccessKey: import.meta.env.VITE_AWS_SECRET_ACCESS_KEY });
// ruleid: appsec.js.public-env-secret
const db = connect(process.env.EXPO_PUBLIC_DB_PASSWORD);
// ok: appsec.js.public-env-secret
const browserSupabase = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_ANON_KEY);
// ok: appsec.js.public-env-secret
const stripeJs = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);
// ok: appsec.js.public-env-secret
const firebaseApp = initializeApp({ apiKey: import.meta.env.VITE_FIREBASE_API_KEY });
// ok: appsec.js.public-env-secret
const maps = new Loader({ apiKey: process.env.NEXT_PUBLIC_GOOGLE_MAPS_API_KEY });
// ok: appsec.js.public-env-secret
mapboxgl.accessToken = import.meta.env.VITE_MAPBOX_ACCESS_TOKEN;
// ok: appsec.js.public-env-secret
const captcha = process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY;
// ok: appsec.js.public-env-secret
const tokenUrl = process.env.NEXT_PUBLIC_AUTH_TOKEN_URL;
// ok: appsec.js.public-env-secret
const storageKey = import.meta.env.VITE_STORAGE_KEY;
// ok: appsec.js.public-env-secret
const serverAi = process.env.OPENAI_API_KEY;
// ruleid: appsec.js.cors-any-origin-with-credentials
app.use(cors({ origin: "*", credentials: true }));
// ruleid: appsec.js.cors-any-origin-with-credentials
app.use(cors({ credentials: true, origin: true }));
// ok: appsec.js.cors-any-origin-with-credentials
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
// ok: appsec.js.cors-any-origin-with-credentials
app.use(cors({ origin: "*" }));
function corsByHand(req, res) {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
  // ruleid: appsec.js.cors-any-origin-with-credentials
  res.setHeader("Access-Control-Allow-Credentials", "true");
}
function corsByHandFixed(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "https://app.example.com");
  // ok: appsec.js.cors-any-origin-with-credentials
  res.setHeader("Access-Control-Allow-Credentials", "true");
}
const decodeOnly = (token) => {
  // ruleid: appsec.js.jwt-decode-unverified
  const claims = jwt.decode(token);
  return claims.isAdmin;
};
const verified = (token) => {
  const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });
  // ok: appsec.js.jwt-decode-unverified
  const header = jwt.decode(token, { complete: true });
  return payload.sub;
};
// A middleware mounted before the routes covers them only when it authenticates.
const parsed = express();
parsed.use(express.json());
parsed.get("/me", requireAuth, (req, res) => res.json(req.user));
// ruleid: appsec.js.route-without-auth
parsed.get("/admin/users", (req, res) => res.json([]));
const hardened = express();
hardened.use(helmet());
hardened.use(cors());
hardened.use(session({ secret: process.env.SESSION_SECRET }));
hardened.use(express.static(path.join(__dirname, "auth-assets")));
hardened.post("/orders", isAuthenticated, (req, res) => res.json({}));
// ruleid: appsec.js.route-without-auth
hardened.delete("/orders/:id", (req, res) => res.json({}));
const guarded = express();
guarded.use(express.json());
guarded.use(passport.authenticate("jwt", { session: false }));
guarded.get("/me", requireAuth, (req, res) => res.json(req.user));
// ok: appsec.js.route-without-auth
guarded.get("/admin/users", (req, res) => res.json([]));
const checked = express();
checked.use((req, res, next) => (req.session.user ? next() : res.status(401).end()));
checked.get("/me", requireAuth, (req, res) => res.json(req.user));
// ok: appsec.js.route-without-auth
checked.get("/admin/users", (req, res) => res.json([]));
const authored = express();
authored.use(authorRoutes);
authored.get("/me", requireAuth, (req, res) => res.json(req.user));
// ruleid: appsec.js.route-without-auth
authored.get("/admin/users", (req, res) => res.json([]));
function mount(app, sessionHandler) {
  const isLoggedIn = sessionHandler.isLoggedInMiddleware;
  // ok: appsec.js.route-without-auth
  app.get("/", sessionHandler.displayWelcomePage);
  app.get("/dashboard", isLoggedIn, sessionHandler.displayWelcomePage);
  // ruleid: appsec.js.route-without-auth
  app.post("/", sessionHandler.handleTransfer);
}
const orders = express.Router();
orders.post("/", requireAuth, (req, res) => res.json({}));
// ruleid: appsec.js.route-without-auth
orders.get("/", (req, res) => res.json([]));
