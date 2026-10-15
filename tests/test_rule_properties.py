"""Properties of the conditions inside Pitangus' own Opengrep rules, checked on the regexes the rules carry.

`make rules-test` runs each rule on its `ok:`/`ruleid:` cases with the real engine; these tests generate the names the
cases only sample. The engine evaluates the same PCRE subset Python's `re` does for these patterns (anchored at the
start, as `metavariable-regex` is)."""

import os
import re
import unittest
from functools import cache
from pathlib import Path

import yaml
from hypothesis import given, settings, strategies as st

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1


@cache
def rule(name: str) -> dict:
    language = name.split(".")[1]
    files = {"js": "javascript.yml", "py": "python.yml"}
    return next(item for item in yaml.safe_load((RULES_DIR / files[language]).read_text())["rules"] if item["id"] == name)


def _negations(node) -> list[dict]:
    return [item["pattern-not-inside"] for item in node.get("patterns", []) if isinstance(item.get("pattern-not-inside"), dict)]


@cache
def guard_regexes() -> list[re.Pattern]:
    """The conditions a middleware mounted with `$APP.use(...)` must meet to cover the routes after it."""
    found = []
    for negation in _negations(rule("appsec.js.route-without-auth")):
        found += [re.compile(item["metavariable-regex"]["regex"]) for item in negation["patterns"]
                  if (item.get("metavariable-regex") or {}).get("metavariable") == "$GLOBAL"]
    return found


def covers(expression: str) -> bool:
    return any(regex.match(expression) for regex in guard_regexes())


identifier = st.from_regex(r"[a-z][a-zA-Z0-9]{0,8}", fullmatch=True)
receiver = st.lists(identifier, max_size=2).map(lambda parts: "".join(f"{part}." for part in parts))
# Anything an argument list may say, including the words that name a guard: they never make one.
arguments = st.lists(st.sampled_from(['"jwt"', "{ session: false }", '"auth-assets"', "process.env.AUTH_SECRET", "token",
                                      "{ secret: authKey }", "path.join(__dirname, 'auth')", "42", "[]", "() => requireAuth"]),
                     max_size=3).map(", ".join)
GUARDS = ["auth", "Auth", "authenticate", "Authenticated", "authorize", "jwt", "Jwt", "JWT", "protect", "guard", "Guard",
          "LoggedIn", "loggedIn", "ensureLoggedIn", "requireLogin", "requireUser", "requireRole", "requireAdmin",
          "verifyToken", "checkSession", "ensureSession", "sessionRequired", "signedIn"]
NOT_GUARDS = ["json", "urlencoded", "text", "raw", "static", "helmet", "cors", "session", "cookieSession", "cookieParser",
              "morgan", "compression", "rateLimit", "slowDown", "csrf", "csurf", "multer", "hpp", "methodOverride",
              "serveFavicon", "responseTime", "timeout", "i18n", "authorRoutes", "authors", "logger", "errorHandler"]


class RouteGuardTests(unittest.TestCase):
    def test_the_rule_carries_its_guard_conditions(self):
        self.assertEqual(len(guard_regexes()), 2)

    @settings(max_examples=200 * SCALE)
    @given(receiver, identifier, st.sampled_from(GUARDS), identifier, st.booleans(), arguments)
    def test_a_middleware_named_for_authentication_covers_the_routes_after_it(self, prefix, before, word, after, called, args):
        name = f"{prefix}{before if word[0].isupper() else ''}{word}"
        name += after.capitalize() if not after.startswith(("or", "Or")) else ""
        expression = f"{name}({args})" if called else name
        self.assertTrue(covers(expression), expression)

    @settings(max_examples=200 * SCALE)
    @given(st.sampled_from(["", "express.", "bodyParser.", "app.locals."]), st.sampled_from(NOT_GUARDS), st.booleans(), arguments)
    def test_any_other_middleware_never_does_whatever_its_arguments_say(self, prefix, name, called, args):
        expression = f"{prefix}{name}({args})" if called else f"{prefix}{name}"
        self.assertFalse(covers(expression), expression)

    @given(st.sampled_from(["req.session.user", "req.user", "req.isAuthenticated()", "req.headers.authorization"]),
           st.sampled_from(["res.status(401).end()", "res.sendStatus(403)", 'res.redirect("/login")', "next(new Unauthorized())"]),
           st.sampled_from(["(req, res, next) => ", "async (req, res, next) => ", "function (req, res, next) "]))
    def test_an_inline_function_that_checks_the_user_and_refuses_covers_them(self, check, refusal, head):
        self.assertTrue(covers(f"{head}{{ if (!{check}) return {refusal}; next(); }}"))

    @given(st.sampled_from(["(req, res, next) => ", "function (req, res, next) "]),
           st.sampled_from(['res.setHeader("X-Frame-Options", "DENY")', "req.start = Date.now()", "res.locals.user = req.user"]))
    def test_an_inline_function_that_refuses_nobody_does_not(self, head, body):
        self.assertFalse(covers(f"{head}{{ {body}; next(); }}"))


@cache
def public_env_regex() -> re.Pattern:
    (condition,) = [item["metavariable-regex"] for item in rule("appsec.js.public-env-secret")["patterns"] if "metavariable-regex" in item]
    return re.compile(condition["regex"])


PUBLIC_PREFIXES = ["NEXT_PUBLIC", "VITE", "REACT_APP", "EXPO_PUBLIC", "PUBLIC", "NUXT_PUBLIC", "GATSBY"]
SAYS_SECRET = ["SECRET", "SECRET_KEY", "CLIENT_SECRET", "PRIVATE_KEY", "PASSWORD", "DB_PASSWD", "SERVICE_ROLE_KEY",
               "ADMIN_KEY", "MASTER_KEY"]
SAYS_KEY = ["API_KEY", "APIKEY", "ACCESS_KEY", "SECRET_ACCESS_KEY", "AUTH_TOKEN", "ACCESS_TOKEN", "TOKEN", "BOT_TOKEN",
            "ENCRYPTION_KEY", "SIGNING_KEY", "JWT_KEY", "API_TOKENS"]
# Keys their providers hand to the browser on purpose (the Supabase anon key among them: public by design).
PUBLIC_BY_DESIGN = ["SUPABASE_ANON_KEY", "ANON_KEY", "STRIPE_PUBLISHABLE_KEY", "CLERK_PUBLISHABLE_KEY", "FIREBASE_API_KEY",
                    "GOOGLE_MAPS_API_KEY", "MAPS_KEY", "MAPBOX_ACCESS_TOKEN", "RECAPTCHA_SITE_KEY", "HCAPTCHA_SITEKEY",
                    "TURNSTILE_SITE_KEY", "POSTHOG_KEY", "POSTHOG_API_KEY", "MIXPANEL_TOKEN", "AMPLITUDE_API_KEY",
                    "SEGMENT_WRITE_KEY", "ALGOLIA_SEARCH_API_KEY", "ALGOLIA_SEARCH_ONLY_KEY", "GA_MEASUREMENT_ID",
                    "MAPBOX_PUBLIC_TOKEN"]
MARKERS = ("ANON", "PUBLISHABLE", "PUBLIC", "SITE", "FIREBASE", "MAPS", "MAPBOX", "CAPTCHA", "TURNSTILE", "POSTHOG",
           "MIXPANEL", "AMPLITUDE", "SEGMENT", "SEARCH", "MEASUREMENT", "SECRET", "PRIVATE", "PASSW", "SERVICE", "ADMIN",
           "MASTER", "KEY", "TOKEN", "VITE", "REACT", "EXPO", "NUXT", "GATSBY", "NEXT")
segment = st.from_regex(r"[A-Z][A-Z0-9]{0,6}", fullmatch=True).filter(lambda word: not any(marker in word for marker in MARKERS))
middle = st.lists(segment, max_size=3).map(lambda words: "".join(f"{word}_" for word in words))


class PublicEnvSecretTests(unittest.TestCase):
    def matches(self, name: str) -> bool:
        return public_env_regex().match(name) is not None

    @settings(max_examples=150 * SCALE)
    @given(st.sampled_from(PUBLIC_PREFIXES), middle, st.sampled_from(SAYS_SECRET + SAYS_KEY))
    def test_a_public_variable_whose_name_says_secret_or_key_is_reported(self, prefix, between, word):
        self.assertTrue(self.matches(f"{prefix}_{between}{word}"), f"{prefix}_{between}{word}")

    @settings(max_examples=150 * SCALE)
    @given(st.sampled_from(PUBLIC_PREFIXES), middle, st.sampled_from(PUBLIC_BY_DESIGN))
    def test_a_key_public_by_design_is_not(self, prefix, between, name):
        self.assertFalse(self.matches(f"{prefix}_{between}{name}"), f"{prefix}_{between}{name}")

    @given(st.sampled_from(PUBLIC_PREFIXES), st.sampled_from(PUBLIC_BY_DESIGN), st.sampled_from(SAYS_SECRET))
    def test_a_name_that_says_secret_counts_even_next_to_a_public_provider(self, prefix, provider, word):
        self.assertTrue(self.matches(f"{prefix}_{provider.rsplit('_', 1)[0]}_{word}"))

    @given(middle, st.sampled_from(SAYS_SECRET + SAYS_KEY))
    def test_without_a_public_prefix_the_bundler_never_ships_it(self, between, word):
        self.assertFalse(self.matches(f"{between}{word}"))

    @given(st.sampled_from(PUBLIC_PREFIXES), middle, st.sampled_from([word for word in SAYS_KEY if "SECRET" not in word]),
           st.sampled_from(["_URL", "_ID", "_HEADER", "_ENDPOINT", "_NAME"]))
    def test_a_key_or_token_word_that_names_something_else_is_not(self, prefix, between, word, tail):
        self.assertFalse(self.matches(f"{prefix}_{between}{word}{tail}"))


if __name__ == "__main__":
    unittest.main()
