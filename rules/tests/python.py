import os, pickle, subprocess, yaml, hashlib, requests
from flask import Flask, request, render_template_string
app = Flask(__name__)
@app.route("/q")
def q():
    name = request.args.get("name")
    # ruleid: appsec.py.sql-injection-from-request, appsec.py.sql-string-building
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    # ruleid: appsec.py.sql-injection-from-request, appsec.py.sql-string-building
    cur.execute("SELECT * FROM t WHERE id = %s" % request.args.get("id"))
    # ruleid: appsec.py.ssti-render-template-string
    return render_template_string("Hola " + name)
# ruleid: appsec.py.pickle-load
def load(blob): return pickle.loads(blob)
# ruleid: appsec.py.yaml-load-unsafe
def cfg(text): return yaml.load(text)
# ruleid: appsec.py.shell-command-non-literal
def run(cmd): subprocess.call(cmd, shell=True)
# ruleid: appsec.py.eval-exec-non-literal
def ev(s): return eval(s)
# ruleid: appsec.py.weak-password-hash
def h(password): return hashlib.md5(password.encode()).hexdigest()
# ruleid: appsec.py.requests-verify-false, appsec.py.ssrf-from-request
def fetch(): return requests.get(request.args.get("url"), verify=False)
# ruleid: appsec.py.flask-debug-true
app.run(debug=True)
from django.utils.safestring import mark_safe
import jwt
# ruleid: appsec.py.django-mark-safe-non-literal
def safe(name): return mark_safe(name)
# ruleid: appsec.py.jwt-decode-unverified
def tok(t): return jwt.decode(t, options={"verify_signature": False})
# ruleid: appsec.py.path-traversal-from-request
def read(): return open("/data/" + request.args.get("f")).read()

# What the rules must leave alone.
def not_http(signer, payload):
    # ok: appsec.py.requests-verify-false
    return signer.sign(payload, verify=False)


def safe_counterparts(cur, session, app, data, token, user_file):
    from flask import request, render_template, send_file
    from werkzeug.utils import secure_filename
    import hashlib, json, os, subprocess, requests, jwt, yaml
    from django.utils.safestring import mark_safe
    # ok: appsec.py.eval-exec-non-literal
    eval("1 + 1")
    # ok: appsec.py.shell-command-non-literal
    subprocess.run(["ls", user_file], check=True)
    # ok: appsec.py.sql-string-building
    cur.execute("SELECT * FROM users WHERE name = %s", (user_file,))
    # ruleid: appsec.py.sql-string-building
    cur.execute("SELECT * FROM users WHERE name = '" + user_file + "'")
    # ok: appsec.py.sql-injection-from-request
    cur.execute("SELECT * FROM users WHERE id = %s", (request.args["id"],))
    # ok: appsec.py.ssti-render-template-string
    render_template("hello.html", name=request.args["name"])
    # ok: appsec.py.pickle-load
    json.loads(data)
    # ok: appsec.py.yaml-load-unsafe
    yaml.load(data, Loader=yaml.SafeLoader)
    # ok: appsec.py.flask-debug-true
    app.run(debug=False)
    # ok: appsec.py.jwt-decode-unverified
    jwt.decode(token, "key", algorithms=["HS256"])
    # ok: appsec.py.weak-password-hash
    hashlib.sha256(data)
    # ok: appsec.py.django-mark-safe-non-literal
    mark_safe("<b>fixed</b>")
    # ok: appsec.py.path-traversal-from-request
    send_file(os.path.join("/data", secure_filename(request.args["file"])))
    # ok: appsec.py.ssrf-from-request
    requests.get("https://api.example.com/search", params={"q": request.args["q"]}, timeout=5)


# AI-generated code, the usual slips.
from fastapi import APIRouter, Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from flask_cors import CORS
from jose import jwt as jose_jwt

api = FastAPI()
# ruleid: appsec.py.cors-any-origin-with-credentials
api.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"])
# ok: appsec.py.cors-any-origin-with-credentials
api.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)
# ok: appsec.py.cors-any-origin-with-credentials
api.add_middleware(CORSMiddleware, allow_origins=["*"])
# ruleid: appsec.py.cors-any-origin-with-credentials
CORS(flask_app, supports_credentials=True)
# ok: appsec.py.cors-any-origin-with-credentials
CORS(flask_app, origins=["https://app.example.com"], supports_credentials=True)

# ruleid: appsec.py.jwt-decode-unverified
def claims(token): return jose_jwt.get_unverified_claims(token)

router = APIRouter()


@router.get("/me")
async def me(user=Depends(get_current_user)):
    return user


@router.post("/orders")
async def create_order(order: dict, user: dict = Depends(get_current_user)):
    return order


# ruleid: appsec.py.fastapi-route-without-auth
@router.delete("/orders/{order_id}")
async def delete_order(order_id: int):
    return {"deleted": order_id}


# ok: appsec.py.fastapi-route-without-auth
@router.post("/login")
async def login(form: dict):
    return {"token": "x"}


# ok: appsec.py.fastapi-route-without-auth
@router.get("/orders/{order_id}", dependencies=[Depends(get_current_user)])
async def read_order(order_id: int):
    return {"id": order_id}


# A router where every route depends on the same authentication function with different arguments: nothing to say.
guarded = APIRouter()


# ok: appsec.py.fastapi-route-without-auth
@guarded.get("/assets")
def assets(context: Context = Depends(guard(Policy(action="list-assets")))):
    return []


# ok: appsec.py.fastapi-route-without-auth
@guarded.post("/assets/exclusions")
def exclusions(context: Context = Depends(guard(Policy(action="save-exclusions", role="admin")))):
    return {}
