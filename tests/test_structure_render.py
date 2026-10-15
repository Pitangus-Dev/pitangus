"""Structure, never values (shared/render.py): a value written anywhere never leaves Pitangus, tested as a property.

A random value (any alphabet: letters and digits, symbols and brackets, hex, digits only, lowercase only, accented
and Cyrillic letters, base64 with its padding) is written in any position a value can take in code in several
languages, JSON, YAML (quoted, plain, block scalars, anchors and tags, flow lists), XML (text, attributes, CDATA),
.properties, INI, TOML, .env, .netrc, pgpass, htpasswd, connection strings, shell and PowerShell commands, SQL, URLs
and an engine's sentences. Nothing tells the renderer that it is a credential, and no name around it says so. It is
then reported by every adapter that reads text (Opengrep's lines and message, zizmor's job, an imported SARIF's
snippet, context region and message, a web scanner's evidence, an engine's stderr) and followed into every place it
can reach: the database rows, the stored run and report and SARIF, the registry, the prompts (CLI and panel), the
CLI's JSON, SARIF, text and Markdown, the PDF's text, the Jira issue, the notifications and the logs. No fragment of
it appears in any of them (`leaked`: no run of four or more of its letters and digits that the renderer wouldn't keep
as a common word), and the renderer is idempotent. The seed cases of the validation and of the adversarial review are
examples here; the property is what the night checks with new values (`HYPOTHESIS_PROFILE=nightly`).
"""

import json
import os
import random
import re
import string
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from hypothesis import HealthCheck, example, given, settings, strategies as st

from pitangus.modules.findings import canonical, registry
from pitangus.modules.scanning.config_engines import parse_zizmor
from pitangus.shared import render
from pitangus.shared.code_identity import normalized_code
from pitangus.shared.masking import sanitize_finding

from test_credential_masking import _code_engines, _outputs, _rows, _sarif
from test_secret_masking import _captured_logs
from value_oracle import fragments, leaked

PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "pitangus")
settings.register_profile("pitangus", derandomize=True, database=None, print_blob=True)
settings.register_profile("nightly", derandomize=False, database=None, print_blob=True)
settings.load_profile(PROFILE)
SCALE = 30 if PROFILE == "nightly" else 1

B62 = string.ascii_letters + string.digits
ALPHABETS = {
    "alnum": B62,
    "symbols": B62 + "!#$%&*+-./:;=?@^_~()[]{}|,",
    "hex": "0123456789abcdef",
    "digits": string.digits,
    "lower": string.ascii_lowercase,
    "accents": "ñáéíóúüçßøåæœжлфыЖЛ" + string.ascii_letters,
    "base64": B62 + "+/",
}


def _value(alphabet: str, seed: int) -> str:
    rng = random.Random(seed)
    letters = ALPHABETS[alphabet]
    while True:
        size = rng.randint(10 if alphabet in ("digits", "lower") else 8, 40)
        value = "".join(rng.choice(letters) for _ in range(size))
        if alphabet == "base64":
            value += "=" * rng.randint(0, 2)
        # A value is something someone chose: it has a run of four or more letters or digits that the renderer doesn't
        # keep (a value made only of symbols, numbers of up to three digits and common words reads as code: render.py).
        if fragments(value):
            return value


# Every position a value takes, by format: (file, text with `{v}` where the value goes). Nothing around the value says
# it is a credential in most of them (`build`, `item`, `data`): the renderer must not need a name to replace it.
FORMATS = {
    # Code: string literals, arguments, assignments, defaults.
    "py_string": ("app.py", 'cur.execute("SELECT * FROM t WHERE k = \'{v}\'" + q)'),
    "py_kwarg": ("app.py", "client = Client(host=host, build='{v}', retries=3)"),
    "py_bytes": ("app.py", "seed = b\"{v}\"\nrun(seed)"),
    "py_fstring": ("app.py", 'log.info(f"started {{name}} with {v}")'),
    "py_triple": ("app.py", 'TEMPLATE = """\nheader\n{v}\nfooter\n"""'),
    "py_dict": ("app.py", "settings = {{'item': '{v}', 'debug': True}}"),
    "js_template": ("app.js", "const url = `https://api.local/v1/${{id}}?k={v}`;"),
    "js_object": ("app.js", "module.exports = {{ item: '{v}', port: 8080 }};"),
    "java_args": ("Db.java", 'Connection c = DriverManager.getConnection(url, "app", "{v}");'),
    "java_field": ("App.java", 'private static final String BUILD = "{v}";'),
    "go_raw": ("main.go", "var build = `{v}`"),
    "csharp_verbatim": ("App.cs", 'var build = @"{v}";'),
    "php_array": ("config.php", "$config = ['item' => '{v}'];"),
    "ruby_hash": ("config.rb", "CONFIG = {{ item: '{v}' }}"),
    "kotlin_call": ("App.kt", 'val c = connect("db", "app", "{v}")'),
    "rust_call": ("main.rs", 'let c = Client::new("app", "{v}");'),
    "comment": ("app.py", "# rotate this one later: {v}\nrun()"),
    "c_define": ("app.h", "#define BUILD {v}"),
    # Data and configuration.
    "json_value": ("config.json", '{{"name": "API_SECRET", "value": "{v}"}}'),
    "json_array": ("config.json", '{{"items": ["first", "{v}"]}}'),
    "json_multiline": ("config.json", '{{\n  "contrasenia": "{v}",\n  "port": 5432\n}}'),
    "yaml_plain": ("config.yml", "item: {v}"),
    "yaml_quoted": ("config.yml", "item: '{v}'"),
    "yaml_nested": ("config.yml", "db:\n  options:\n    item: {v}\n  port: 5432"),
    "yaml_list": ("config.yml", "items:\n  - first\n  - {v}"),
    "yaml_flow": ("config.yml", "items: [first, {v}]"),
    "yaml_block": ("config.yml", "item: |\n  {v}\n  second line\nnext: true"),
    "yaml_folded": ("config.yml", "item: >-\n  {v}\nnext: true"),
    "yaml_anchor": ("config.yml", "item: &anchor {v}\nother: *anchor"),
    "yaml_tag": ("config.yml", "item: !!str {v}"),
    "xml_text": ("web.xml", '<entry key="db.item">{v}</entry>'),
    "xml_attribute": ("web.config", '<add key="Item" value="{v}" />'),
    "xml_attribute_first": ("web.config", '<add value="{v}" key="Item"/>'),
    "xml_cdata": ("app.xml", "<item><![CDATA[{v}]]></item>"),
    "xml_nested": ("pom.xml", "<server>\n  <id>repo</id>\n  <item>{v}</item>\n</server>"),
    "properties": ("app.properties", "db.item={v}"),
    "properties_spaced": ("app.properties", "db.item = {v}"),
    "properties_space": ("app.properties", "db.item {v}"),
    "properties_colon": ("app.properties", "db.item\\:x: {v}"),
    "ini": ("app.ini", "[database]\nitem = {v}"),
    "toml": ("app.toml", '[server]\nitem = "{v}"'),
    "env": (".env", "ITEM={v}"),
    "env_export": ("deploy.sh", "export ITEM={v}"),
    "netrc": (".netrc", "machine api.local login deploy password {v}"),
    "netrc_multiline": (".netrc", "machine api.local\n  login deploy\n  password {v}"),
    "pgpass": (".pgpass", "db.local:5432:app:admin:{v}"),
    "htpasswd_file": (".htpasswd", "admin:{v}"),
    "connection_string": ("appsettings.json", '"Server=db;Database=app;User Id=sa;Password={v};"'),
    "dsn": ("main.go", "dsn := fmt.Sprintf(\"app:{v}@tcp(db:3306)/app\")"),
    "csv": ("users.csv", "user,item\nadmin,{v}"),
    "hcl": ("main.tf", 'resource "x" "y" {{\n  item = "{v}"\n}}'),
    "dockerfile_env": ("Dockerfile", "ENV ITEM {v}"),
    "dockerfile_arg": ("Dockerfile", "ARG ITEM={v}"),
    # Commands.
    "cli_flag": ("deploy.sh", "docker login -u deploy -p {v} registry.local"),
    "cli_long_flag": ("deploy.sh", "tool --item {v} --verbose"),
    "cli_attached": ("restore.sh", "mysql -uroot -p{v} app < dump.sql"),
    "cli_positional": ("setup.sh", "htpasswd -b -c /etc/htpasswd admin {v}"),
    "sqlcmd": ("deploy.sh", 'sqlcmd -S db -U sa -P {v} -Q "select 1"'),
    "curl_user": ("deploy.sh", "curl -u admin:{v} https://api.local/v1"),  # gitleaks:allow (a template, no value)
    "powershell": ("deploy.ps1", "$p = ConvertTo-SecureString {v} -AsPlainText -Force"),
    "powershell_quoted": ("deploy.ps1", '$p = ConvertTo-SecureString "{v}" -AsPlainText -Force'),
    "ldap": ("auth.py", 'l.simple_bind_s("cn=admin,dc=local", "{v}")'),
    "sql_identified": ("schema.sql", "CREATE USER app IDENTIFIED BY '{v}';"),
    "sql_values": ("seed.sql", "INSERT INTO items (name, item) VALUES ('a', '{v}');"),
    "heredoc": ("setup.sh", "cat <<EOF > /etc/app\n{v}\nEOF"),
    # URLs.
    "url_userinfo": ("app.py", "REMOTE = https://deploy:{v}@git.local/org/repo.git"),
    "url_query": ("app.py", "see https://app.local/login?next=/home&item={v}"),
    "url_query_es": ("app.py", "see https://app.local/login?contrasenia={v}&pw=1"),
    "url_fragment": ("app.py", "see https://app.local/cb#state=1&item={v}"),
    "url_matrix": ("app.py", "see https://app.local/app;item={v}/home"),
    # Sentences an engine writes.
    "sentence": ("app.py", "Matched the value {v} in this file"),
    "sentence_colon": ("app.py", "error: rejected {v}"),
    "logfmt": ("app.py", 'level=error msg="login rejected" item={v}'),
    # The adversarial review of the first renderer (it kept words for their position): a comment, a call's argument,
    # an operand, a word before `(…)`, what follows `,` `;` `&` inside a value, a key or an identifier that is the
    # value, URL path segments with `:` and `.`, and every form it tried.
    "comment_slash": ("app.py", "def connect():\n    # creds: admin / {v}\n    return db.connect(q)"),
    "comment_call": ("app.py", "def connect():\n    # login(admin, {v})\n    return db.connect(q)"),
    "shell_compare": ("deploy.sh", "if [ $T == {v} ]; then\n  run\nfi"),
    "yaml_paren": ("config.yml", "password: {v}(Prod)"),
    "env_semicolon": (".env", "DB_PASSWORD=Hx7;{v}=1"),
    "env_comma_colon": (".env", "DB_PASSWORD=Hx7,{v}:8nB"),
    "properties_semicolon": ("app.properties", "spring.datasource.password=Hx7Lp2Qz;{v}=1"),
    "dict_key": ("app.py", 'API_KEYS = {{"{v}": "acme"}}'),
    "identifier": ("app.js", "const {v} = 1"),
    "telegram_url": ("bot.yml", "webhook: https://api.telegram.org/bot5843210987:{v}/sendMessage"),
    "url_ext": ("app.yml", "download: https://cdn.local/files/{v}.json"),
    "url_dotted": ("app.yml", "download: https://cdn.local/files/x.{v}"),
    "url_percent": ("app.yml", "download: https://cdn.local/files/{v}%21"),
    "adv_json_key": ('config.json', '{{"{v}": "admin"}}'),
    "adv_yaml_key": ('config.yml', '{v}: admin'),
    "adv_yaml_flow_key": ('config.yml', 'keys: {{{v}: admin}}'),
    "adv_py_dict_key": ('app.py', 'API_KEYS = {{"{v}": "customer"}}'),
    "adv_env_list_pairs": ('.env', 'API_KEYS=abc:admin,{v}:ci'),
    "adv_identifier": ('app.txt', 'const {v} = 1'),
    "adv_hcl_heredoc": ('main.tf', 'password = <<EOT\n{v}\nEOT'),
    "adv_hcl_heredoc_indent": ('main.tf', '  value = <<-EOT\n    {v}\n  EOT'),
    "adv_dockerfile_env_eq": ('Dockerfile', 'ENV PASS={v} OTHER=1'),
    "adv_dockerfile_run": ('Dockerfile', 'RUN echo {v} > /tmp/x'),
    "adv_makefile": ('Makefile', 'PASS := {v}'),
    "adv_makefile_recipe": ('Makefile', 'deploy:\n\t./deploy {v}'),
    "adv_nginx": ('nginx.conf', 'proxy_set_header Authorization Basic {v};'),
    "adv_nginx2": ('app.txt', '    auth_basic_user_file /etc/{v};'),
    "adv_apache": ('httpd.conf', 'SetEnv API_KEY {v}'),
    "adv_systemd": ('app.service', 'Environment=API_KEY={v}'),
    "adv_systemd2": ('app.txt', 'Environment="A=1" "API_KEY={v}"'),
    "adv_k8s_secret": ('secret.yml', 'data:\n  password: {v}'),
    "adv_graphql": ('query.graphql', 'mutation {{ login(token: {v}) }}'),
    "adv_gql_enum": ('query.graphql', 'query {{ user(role: ADMIN, key: {v}) }}'),
    "adv_jupyter": ('nb.ipynb', '{{"cell_type": "code", "source": ["api_key = \'{v}\'\\n", "run()"]}}'),
    "adv_md_fence": ('README.md', '```bash\nexport TOKEN={v}\n```'),
    "adv_md_inline": ('README.md', 'Use the token `{v}` for staging.'),
    "adv_csv_first": ('keys.csv', '{v},admin'),
    "adv_csv_quoted": ('keys.csv', '"{v}","admin"'),
    "adv_sql_unquoted": ('seed.sql', 'UPDATE users SET token = {v} WHERE id = 1;'),
    "adv_lua": ('init.lua', 'local t = {{ "{v}" }}'),
    "adv_perl": ('run.pl', 'my @keys = qw({v} other);'),
    "adv_bash_array": ('run.sh', 'KEYS=({v} other)'),
    "adv_bash_array2": ('run.sh', 'declare -a KEYS=( first {v} )'),
    "adv_kotlin_raw": ('App.kt', 'val k = """{v}"""'),
    "adv_swift_ml": ('App.swift', 'let k = """\n{v}\n"""'),
    "adv_go_backtick": ('main.go', 'k := `{v}`'),
    "adv_py_fstring": ('app.py', 'x = f"{v}"'),
    "adv_py_implicit": ('app.py', 'x = ("abc"\n     "{v}")'),
    "adv_escaped_quote": ('app.txt', 'x = "a\\"{v}"'),
    "adv_zwsp": ('app.txt', 'x = {v}'),
    "adv_comment_only": ('app.txt', '# {v}'),
    "adv_comment_js": ('app.txt', '// key - {v}'),
    "adv_dash_list": ('app.txt', 'API key - {v}'),
    "adv_op_operand": ('app.txt', 'a || {v}'),
    "adv_op_and": ('app.txt', 'test -f x && {v}'),
    "adv_call_arg": ('app.txt', 'login(user, {v})'),
    "adv_call_arg_list": ('app.txt', 'f([{v}])'),
    "adv_return_kw": ('app.txt', 'return {v}'),
    "adv_import_kw": ('app.txt', 'import {v}'),
    "adv_type_decl": ('app.txt', 'String {v} = x'),
    "adv_two_words_eq": ('app.txt', '{v} name = x'),
    "adv_netrc_default": ('.netrc', 'default login x password {v}'),
    "adv_pip_conf": ('pip.conf', 'extra-index-url = https://{v}@pypi.local/simple'),
    "adv_npmrc": ('.npmrc', '//registry.npmjs.org/:_authToken={v}'),
    "adv_docker_cfg": ('config.json', '{{"auths": {{"r": {{"auth": "{v}"}}}}}}'),
    "adv_ssh_key": ('id_ed25519', '-----BEGIN OPENSSH PRIVATE KEY-----\n{v}\n-----END OPENSSH PRIVATE KEY-----'),
    "adv_url_path": ('links.txt', 'https://hooks.slack.com/services/T000/B000/{v}'),
    "adv_url_token_path": ('links.txt', 'https://api.local/{v}/data'),
    "adv_git_remote": ('.gitconfig', 'url = https://{v}@github.com/org/repo'),
    "adv_url_noscheme": ('links.txt', 'git@github.com:{v}/repo.git'),
    "adv_basic_header": ('request.http', 'Authorization: Basic {v}'),
    "adv_bearer": ('call.sh', '-H "Authorization: Bearer {v}"'),
    "adv_bearer_bare": ('call.sh', '-H Authorization:Bearer {v}'),
    "adv_xml_comment": ('app.xml', '<!-- {v} -->'),
    "adv_html_attr_unq": ('index.html', '<input value={v}>'),
    "adv_xml_pi": ('app.xml', '<?xml version="1.0"?><k>{v}</k>'),
    "adv_toml_array": ('app.toml', 'keys = [\n  "{v}",\n]'),
    "adv_ini_colon": ('app.ini', '[s]\nkey: {v}'),
    "adv_logfmt_spaces": ('app.log', 'msg=hello token {v} user=x'),
    "adv_semicolon_list": ('app.txt', 'a=1; {v}; b=2'),
    "adv_tab_sep": ('users.tsv', 'admin\t{v}'),
    "adv_pipe_table": ('README.md', '| key | {v} |'),
    "adv_dollar": ('run.ps1', '$token = {v}'),
    "adv_php_define": ('config.php', "define('KEY', {v});"),
    "adv_ps_param": ('run.ps1', 'Invoke-Thing -Token {v}'),
    "adv_ps_hash": ('run.ps1', '@{{ Token = {v} }}'),
    "adv_ruby_sym": ('config.rb', 'token: {v}'),
    "adv_elixir": ('config.exs', 'config :app, key: {v}'),
    "adv_erlang": ('app.erl', '{{key, {v}}}.'),
    "adv_clojure": ('core.clj', '(def key {v})'),
    "adv_lisp_call": ('core.lisp', '(login {v})'),
    "adv_haskell": ('Main.hs', 'key = {v}'),
    "adv_asm": ('boot.asm', 'mov eax, {v}'),
}
# What zizmor reads: a workflow's job running a command with the value in it.
WORKFLOW = """on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          {line}
      - run: make test
"""


@st.composite
def cases(draw):
    return (_value(draw(st.sampled_from(sorted(ALPHABETS))), draw(st.integers(0, 2**32))), draw(st.sampled_from(sorted(FORMATS))))


def _text(value: str, form: str) -> tuple[str, str]:
    path, template = FORMATS[form]
    return path, template.format(v=value)


class RendererPropertyTests(unittest.TestCase):
    """The renderer alone, on many more examples than the end-to-end test."""

    @settings(max_examples=1500 * SCALE, deadline=None)
    @given(cases())
    # The seeds of the validation (and its forms): a .netrc password, `docker login -p`, `sqlcmd -P`, a JSON pair
    # named in Spanish, an XML entry, a .config `add`, CDATA, .properties with a space and with `\:`, YAML block,
    # folded, anchored and tagged scalars, pgpass, `htpasswd -b`, ConvertTo-SecureString, simple_bind_s, URL
    # parameters named in Spanish, pw, auth and code.
    @example(("HarborLights-2024!", "netrc"))
    @example(("HarborLights-2024!", "cli_flag"))
    @example(("QuarryStone#77x", "sqlcmd"))
    @example(("QuarryStone#77x", "json_multiline"))
    @example(("QuarryStone#77x", "json_value"))
    @example(("Zq9xK2mP7vL4wR8tY1nB", "xml_text"))
    @example(("Zq9xK2mP7vL4wR8tY1nB", "xml_attribute_first"))
    @example(("Zq9xK2mP7vL4wR8tY1nB", "xml_cdata"))
    @example(("correcthorsebatterystaple", "properties_space"))
    @example(("correcthorsebatterystaple", "properties_colon"))
    @example(("Xk7#pq!2Lm", "yaml_block"))
    @example(("Xk7#pq!2Lm", "yaml_folded"))
    @example(("Xk7#pq!2Lm", "yaml_anchor"))
    @example(("Xk7#pq!2Lm", "yaml_tag"))
    @example(("Xk7#pq!2Lm", "pgpass"))
    @example(("Xk7#pq!2Lm", "cli_positional"))
    @example(("Xk7#pq!2Lm", "powershell"))
    @example(("Xk7#pq!2Lm", "ldap"))
    @example(("Xk7#pq!2Lm", "url_query_es"))
    @example(("YWJjZGVmZ2hpams=", "yaml_list"))
    @example(("8F2A9C0D1E3B4A5F6C7D", "cli_attached"))
    # Nightly: a password that starts with digits and holds `/` read as a port and a path (`deploy:6/…@git.local`).
    @example(("6/vLNzREyd2ruXgAc4f8ZC8ZeSeCZf6UR", "url_userinfo"))
    @example(("12345/AbCdEfGhIjKlMnOpQr", "url_userinfo"))
    # The adversarial review: what the first renderer kept for its position, and URL segments with `:` `.` `%`.
    @example(("Winter2024Corp", "comment_slash"))
    @example(("Winter2024Corp", "comment_call"))
    @example(("Winter2024Corp", "yaml_paren"))
    @example(("ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a", "shell_compare"))
    @example(("vL7qR4tYw8", "env_comma_colon"))
    @example(("Vb9Rt4Kw", "properties_semicolon"))
    @example(("Vb9Rt4KwQz7x", "env_semicolon"))
    @example(("sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc", "dict_key"))
    @example(("Qz7xK9mPwL4tR8vY2nBd", "identifier"))
    @example(("AAFq7Zk3pLmN9vX2bQwE8rT4yU6iO1aSdFg", "telegram_url"))
    @example(("Vb9Rt4KwQz7xLp2Hx7Q", "url_ext"))
    @example(("Vb9Rt4KwQz7xLp2Hx7Q", "url_dotted"))
    @example(("Vb9Rt4KwQz7xLp2Hx7Q", "url_percent"))
    @example(("(C93qZ0}-K8[-V{]@6,%0aCd", "telegram_url"))   # nightly: `%0aCd` decodes to common words, reads as `0aCd`
    def test_no_value_in_any_position_of_any_format(self, case):
        value, form = case
        _, text = _text(value, form)
        for render_ in (render.prose,):
            shown = render_(text)
            self.assertEqual(leaked(value, shown, FORMATS[form][1]), [], f"{render_.__name__}: {text!r} → {shown!r}")
            self.assertNotIn(value, shown)
            self.assertEqual(render_(shown), shown, f"{render_.__name__} is idempotent: {text!r}")

    @settings(max_examples=1500 * SCALE, deadline=None)
    @given(cases(), st.booleans())
    def test_collapsed_onto_one_line_nothing_changes(self, case, prose):
        """A text whose lines were joined (what an adapter may do) keeps every value out just the same: no decision
        reads where a line starts."""
        value, form = case
        text = " ".join(_text(value, form)[1].split())
        shown = render.prose(text)
        self.assertEqual(leaked(value, shown, FORMATS[form][1]), [], f"{text!r} → {shown!r}")

    @settings(max_examples=300 * SCALE, deadline=None)
    @given(st.lists(st.sampled_from(sorted(FORMATS)), min_size=2, max_size=6), st.integers(0, 2**32), st.sampled_from(sorted(ALPHABETS)))
    def test_formats_mixed_in_one_text_keep_every_value_out(self, forms, seed, alphabet):
        values = [_value(alphabet, seed + index) for index in range(len(forms))]
        text = "\n".join(_text(value, form)[1] for value, form in zip(values, forms))
        templates = "\n".join(FORMATS[form][1] for form in forms)
        for render_ in (render.prose,):
            shown = render_(text)
            for value in values:
                self.assertEqual(leaked(value, shown, templates), [], text)
            self.assertEqual(render_(shown), shown)

    @settings(max_examples=1000 * SCALE, deadline=None)
    @given(st.sampled_from(sorted(FORMATS)), st.one_of(st.sampled_from(sorted(word for word in render.lexicon() if re.fullmatch(r"\w+(?:'\w+)*", word))), st.from_regex(r"[A-Za-z0-9_]{1,24}", fullmatch=True)))
    def test_a_word_is_kept_or_not_wherever_it_is(self, form, word):
        """Position never saves a word: in every position of every format, a word shows exactly when `render.kept`
        says, which reads the word alone."""
        template = FORMATS[form][1]
        if re.search(rf"(?<!\w){re.escape(word)}(?!\w)", template.replace("{v}", " ")):
            return   # the template has it already
        text = template.format(v=f" {word} ")
        shown = render.prose(text)
        present = re.search(rf"(?<!\w){re.escape(word)}(?!\w)", shown) is not None
        self.assertEqual(present, render.kept(word), f"{text!r} → {shown!r}")

    def test_a_value_survives_only_made_of_common_words_and_short_numbers(self):
        for word in ("admin123", "deploy", "db_password", "getConnection", "HTTPServer", "v2", "i", "42", "10.0.0.1", "doesn't"):
            self.assertTrue(render.kept(word) or "." in word, word)
            self.assertIn(word, render.prose(f"password: {word}"))
        for word in ("Winter2024Corp", "xK9", "Vb9Rt4KwQz", "1234", "correcthorsebatterystaple", "3be470cd08", "IsAtOnIf",
                     "ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a", "contraseñaSegura9x", "q", "Winter2024Corp's"):
            self.assertFalse(render.kept(word), word)
            self.assertNotIn(word, render.prose(f"# {word}"))

    def test_code_stays_readable(self):
        # A lone letter that isn't a word goes too (`q`): position never keeps it.
        for text, shown in (('cur.execute("SELECT * FROM users WHERE id = " + query)', 'cur.execute("SELECT * FROM users WHERE id = " + query)'),
                            ("cur.execute(\"SELECT k FROM t WHERE v = 'Zq9xK2mP'\" + q)", "cur.execute(\"SELECT *** FROM *** WHERE *** = '***'\" + ***)"),
                            ("result = eval(request.args['expr'])", "result = eval(request.args['expr'])"),
                            ('Connection conn = DriverManager.getConnection(url, "sa", "Hx7Lp2Qz");',
                             'Connection conn = DriverManager.getConnection(url, "sa", "***");'),
                            ("subprocess.call(cmd, shell=True)", "subprocess.call(cmd, shell=True)"),
                            ("def login(username: str, password: str):", "def login(username: str, password: str):"),
                            ("docker login -u deploy -p Hx7Lp2Qz registry.local", "docker login -u deploy -p *** registry.local"),
                            ('<entry key="db.password">Hx7Lp2Qz</entry>', '<entry key="db.password">***</entry>'),
                            ("password: |\n  Hx7Lp2Qz\nnext: true", "password: |\n  ***\nnext: true"),
                            ("# creds: admin / Winter2024Corp", "# ***: admin / ***"),
                            ("spring.datasource.password=Hx7Lp2Qz;Vb9Rt4Kw=1", "***.***.password=***;***=1"),
                            ("webhook: https://api.telegram.org/bot5843210987:AAFq7Zk3pLmN9vX2bQwE8rT4yU6iO1aSdFg/sendMessage",
                             "webhook: https://api.***.org/***:***/sendMessage"),
                            ("REMOTE = https://deploy:Hx7Lp2Qz@git.local/org/repo.git?ref=main#L10",
                             "REMOTE = https://***@git.local/org/repo.git?ref=***#***")):
            self.assertEqual(render.prose(text), shown)

    def test_rendering_is_fast_on_adversarial_text(self):
        import time
        for text in ("password: " * 5000, "[" * 50000, "a(" * 25000, "<a>" * 10000, '<a b="c">x</a>' * 3000, "a=" * 25000,
                     '"' * 50000, "'a" * 25000, "x\n  " * 12000, "key: |\n" + "  v\n" * 20000, "-p " * 15000, "https://a/" + "b;c=d/" * 7000):
            started = time.monotonic()
            render.prose(text)
            render.prose(text)
            self.assertLess(time.monotonic() - started, 5, text[:20])


def _job_report(text: str, path: str) -> list:
    """zizmor's excessive-permissions pointing at the whole job (its offsets in the file, as zizmor reports them)."""
    start = text.index("  build:")
    end = len(text)
    return [{"ident": "excessive-permissions", "desc": "overly broad permissions", "url": "https://docs.zizmor.sh/audits/",
             "determinations": {"confidence": "High", "severity": "Medium"},
             "locations": [{"symbolic": {"key": {"Local": {"verbatim_path": f"/src/{path}"}}, "annotation": "this job uses write-all permissions",
                                         "route": {"route": [{"Key": "jobs"}, {"Key": "build"}]}, "kind": "Primary"},
                            "concrete": {"location": {"start_point": {"row": text[:start].count("\n"), "column": 2},
                                                      "end_point": {"row": text.count("\n"), "column": 0}, "offset_span": {"start": start, "end": end}}}}]}]


def _codeql(path: str, text: str, line: str, where: str) -> dict:
    """A CodeQL-like SARIF: the value in the result's snippet, its context region or its message."""
    region = {"startLine": 3, **({"snippet": {"text": line}} if where == "snippet" else {})}
    context = {"startLine": 1, "endLine": 5, "snippet": {"text": text}} if where == "context" else None
    message = f"This value flows to a sink: {line}" if where == "message" else "Untrusted data flows to a sink."
    return _sarif("CodeQL", {"id": "py/sql-injection", "shortDescription": {"text": "SQL query built from user-controlled sources"},
                             "properties": {"tags": ["security", "external/cwe/cwe-089"], "security-severity": "8.8"}},
                  {"ruleId": "py/sql-injection", "message": {"text": message},
                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": region,
                                                       **({"contextRegion": context} if context else {})}}]})


ENGINES = ("opengrep", "zizmor", "sarif_snippet", "sarif_context", "sarif_message", "stderr", "web")


def _drop_schema(data_dir: Path) -> None:
    """The database schema a data folder had (PITANGUS_DB_ISOLATE=data-dir), dropped."""
    from sqlalchemy import text as sql
    from pitangus.shared import db
    schema = db.schema_for(data_dir)
    if schema is not None:
        with db.engine().begin() as connection:
            connection.execute(sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))   # a hash-derived name
        db._ready.pop(schema, None)


class NoValueAnywhereTests(unittest.TestCase):
    """For a value in any position of any format, through every adapter that reads text: nowhere in storage or output."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.examples = 0

    def _repository(self, data_dir: Path, source: dict, files: dict[str, str], replay: tuple) -> dict:
        from pitangus.modules.scanning.repository import scan_repository
        root = data_dir / "snapshot"
        for path, text in files.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text, encoding="utf-8")
        if not files:
            root.mkdir(parents=True, exist_ok=True)
            (root / "README.md").write_text("# api\n", encoding="utf-8")
        return scan_repository(root, source, data_dir=data_dir, replay=replay, feeds={"kev": {}, "epss": {}})

    def _imported(self, document: dict, source: dict) -> dict:
        from pitangus.modules.runs.imports import _record
        from pitangus.modules.scanning import sarif_import
        parsed = sarif_import.parse(document)[0]
        return _record(parsed, source, scope="full", commit=None, branch=None, requested_by="test", now=datetime.now(timezone.utc).isoformat())

    def check(self, value: str, form: str, engine: str):
        self.examples += 1
        path, text = _text(value, form)
        lines = text.split("\n")
        line = next(item for item in lines if value in item)
        data_dir = Path(self.directory.name) / f"data-{self.examples}"
        key = f"github#{self.examples}"
        source = {"id": "github:org/api", "uid": key, "name": "org/api", "provider": "github"}
        try:
            self._check(value, form, engine, path, text, line, data_dir, key, source)
        finally:
            _drop_schema(data_dir)   # each example has its own schema: the nightly's thousands mustn't pile up

    def _check(self, value: str, form: str, engine: str, path: str, text: str, line: str, data_dir: Path, key: str, source: dict):
        lines = text.split("\n")
        with _captured_logs() as logs:
            cli_from = "scan"
            if engine == "opengrep":
                content = "# start\n" + text + "\n# end\n"
                report = {"results": [{"check_id": "rules.third.party.rule", "path": f"/src/{path}", "start": {"line": 2},
                                       "end": {"line": 1 + len(lines)},
                                       "extra": {"lines": text, "message": f"Matched {text}", "severity": "ERROR",
                                                 "metadata": {"cwe": [89], "confidence": "HIGH", "category": "security"}}}]}
                record = self._repository(data_dir, source, {path: content}, _code_engines({"opengrep": report}))
                self.assertTrue(record["findings"])
            elif engine == "zizmor":
                workflow = WORKFLOW.format(line=line)
                where = ".github/workflows/ci.yml"
                record = self._repository(data_dir, source, {where: workflow}, _code_engines({"zizmor": _job_report(workflow, where)}))
                self.assertTrue(any(item["tool"] == "zizmor" for item in record["findings"]))
            elif engine == "stderr":
                record = self._repository(data_dir, source, {}, _code_engines({}, {"checkov": (line, f"Traceback...\n{line}\n")}))
            elif engine == "web":
                from test_credential_masking import _zap
                record, cli_from = self._imported(_zap(f"https://app.local/search?q={value}", line), source), "saved"
            else:
                record, cli_from = self._imported(_codeql(path, text, line, engine.split("_")[1]), source), "saved"
                self.assertTrue(record["findings"])
            outputs = _outputs(data_dir, record, key, "v2", cli_from=cli_from)
            if cli_from == "scan":
                outputs["scan"] = json.dumps(record, ensure_ascii=False)
        outputs["logs"] = "\n".join(logs)
        for name, shown in outputs.items():
            self.assertNotIn(value, shown, f"{name}: {form}/{engine}")
            # No fragment either (a number of fewer than eight digits alone aside: every output has dates and counts).
            self.assertEqual(leaked(value, shown, FORMATS[form][1], numbers=8), [], f"{name}: {form}/{engine}")

    @settings(max_examples=70 * SCALE, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    @given(cases(), st.sampled_from(ENGINES))
    # The seeds: zizmor's excessive-permissions over a job with a .netrc password, `docker login -p` and `sqlcmd -P`;
    # Opengrep's multi-line fragments with a Spanish JSON key and a {"name", "value"} pair; CodeQL's snippet and
    # context region; and the forms the masking function missed.
    @example(("HarborLights-2024!", "netrc"), "zizmor")
    @example(("HarborLights-2024!", "cli_flag"), "zizmor")
    @example(("QuarryStone#77x", "sqlcmd"), "zizmor")
    @example(("QuarryStone#77x", "json_multiline"), "opengrep")
    @example(("QuarryStone#77x", "json_value"), "opengrep")
    @example(("Zq9xK2mP7vL4wR8tY1nB", "py_string"), "sarif_snippet")
    @example(("Zq9xK2mP7vL4wR8tY1nB", "yaml_block"), "sarif_context")
    @example(("Zq9xK2mP7vL4wR8tY1nB", "xml_text"), "sarif_message")
    @example(("Xk7#pq!2Lm", "properties_space"), "opengrep")
    @example(("Xk7#pq!2Lm", "url_query_es"), "web")
    @example(("Xk7#pq!2Lm", "logfmt"), "stderr")
    # The adversarial review: through Opengrep, an imported SARIF (snippet, context region, message) and stderr.
    @example(("Winter2024Corp", "comment_slash"), "opengrep")
    @example(("Winter2024Corp", "comment_call"), "sarif_context")
    @example(("Winter2024Corp", "yaml_paren"), "sarif_snippet")
    @example(("Winter2024Corp", "shell_compare"), "sarif_snippet")
    @example(("Vb9Rt4KwQz7x", "env_semicolon"), "stderr")
    @example(("Vb9Rt4KwQz7x", "properties_semicolon"), "sarif_message")
    @example(("Vb9Rt4KwQz7x", "env_comma_colon"), "zizmor")
    @example(("Vb9Rt4KwQz7x", "dict_key"), "opengrep")
    @example(("AAFq7Zk3pLmN9vX2bQwE8rT4yU6iO1aSdFg", "telegram_url"), "sarif_context")
    @example(("Vb9Rt4KwQz7x", "url_ext"), "web")
    @example(("Vb9Rt4KwQz7x", "adv_hcl_heredoc"), "sarif_context")
    def test_a_value_in_any_position_shows_nowhere(self, case, engine):
        value, form = case
        self.check(value, form, engine)

    def test_the_adversarial_reviews_forms_through_every_text_adapter(self):
        """Each form the adversarial review broke the first renderer with, through each adapter that reads text."""
        forms = ("comment_slash", "comment_call", "shell_compare", "yaml_paren", "env_semicolon", "env_comma_colon",
                 "properties_semicolon", "dict_key", "identifier", "telegram_url", "url_ext", "url_dotted", "url_percent")
        for form in forms:
            value = "AAFq7Zk3pLmN9vX2bQwE8rT4yU6iO1aSdFg" if form.endswith("url") else "Winter2024Corp" if form.startswith(("comment", "yaml", "shell")) \
                else "Vb9Rt4KwQz7x"
            for engine in ("opengrep", "sarif_snippet", "sarif_context", "sarif_message", "stderr"):
                with self.subTest(form=form, engine=engine):
                    self.check(value, form, engine)


class FailedJobLogTests(unittest.TestCase):
    def test_what_an_exception_says_is_logged_rendered(self):
        """A scan that fails logs the last line of its traceback (what the exception says, which may quote a file's
        line): rendered, not only redacted."""
        from unittest.mock import patch
        from pitangus.modules.runs import jobs
        value = "Vb9Rt4KwQz7x"
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(jobs.ScanJobs, "__init__", lambda self, data_dir: setattr(self, "data_dir", data_dir)), \
                patch.object(jobs, "load_run", return_value={"id": "a" * 32, "progress": [], "status": "queued"}), \
                patch.object(jobs.ScanJobs, "_save", lambda self, record: None), \
                patch.object(jobs.ScanJobs, "_fail", lambda self, record, message: None), \
                patch.object(jobs.ScanJobs, "_revision", side_effect=ValueError(f"bad line 3: spring.datasource.password=x;{value}=1")), \
                _captured_logs() as logs:
            jobs.ScanJobs(Path(directory))._execute({"run_id": "a" * 32})
        self.assertTrue(any("escaneo fallido" in line for line in logs), logs)
        self.assertEqual(leaked(value, "\n".join(logs)), [])


class IdentityBeforeRenderingTests(unittest.TestCase):
    """The identity is read from the original: rendering never makes a finding look new, fixed or moved."""

    @settings(max_examples=200 * SCALE, deadline=None)
    @given(cases(), cases())
    def test_rendering_keeps_identities_and_tells_different_code_apart(self, first, second):
        def finding(value, form):
            path, text = _text(value, form)
            return {"fingerprint": "a" * 64, "scanner": "sast", "tool": "opengrep", "rule_id": "r", "path": path, "line": 2, "snippet": text}
        one, other = finding(*first), finding(*second)
        stored_one, stored_other = sanitize_finding(one), sanitize_finding(other)
        self.assertEqual(canonical.identity_of(stored_one), canonical.identity_of(one))
        self.assertEqual(canonical.anywhere(stored_one), canonical.anywhere(one))
        # Different code (comments and formatting aside) is a different finding, however alike it renders.
        if normalized_code(one["snippet"], one["path"]) != normalized_code(other["snippet"], other["path"]) or one["path"] != other["path"]:
            self.assertNotEqual(canonical.identity_of(stored_one), canonical.identity_of(stored_other))
        self.assertEqual(sanitize_finding(stored_one), stored_one)

    def test_zizmor_keeps_no_yaml_and_keeps_its_identity(self):
        value = "HarborLights-2024!"
        workflow = WORKFLOW.format(line=f"echo {value} | docker login -u x --password-stdin && sqlcmd -P {value}")
        where = ".github/workflows/ci.yml"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / where).write_text(workflow, encoding="utf-8")
            finding = parse_zizmor(_job_report(workflow, where), root)[0]
        self.assertNotIn("snippet", finding)   # the YAML is read for its identity, never kept
        self.assertNotIn(value, json.dumps(finding))
        # The identity, the fingerprint and the identity anywhere were read from the job's YAML, as before.
        feature = " ".join(workflow[workflow.index("  build:"):].split())[:300]
        from pitangus.shared.code_identity import content_identity
        self.assertEqual(finding["identity"], content_identity({**finding, "snippet": f"{feature}\nthis job uses write-all permissions"}))


class RenderStoredTextsMigrationTests(unittest.TestCase):
    """`render_stored_texts` renders what earlier versions stored (zizmor's YAML, multi-line fragments, an imported
    snippet and context, an engine's message), and every finding keeps its identity."""

    def setUp(self):
        from pitangus.app import data_migrations as migrations
        from pitangus.shared import documents
        self.migrations = migrations
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.data_dir = Path(self.directory.name) / "data"
        self.data_dir.mkdir()
        position = [migration.name for migration in migrations.MIGRATIONS].index("render_stored_texts")
        documents.save(self.data_dir, migrations.VERSION_DOCUMENT, {"version": position, "history": []})

    def test_stored_texts_are_rendered_and_identities_kept(self):
        from pitangus.modules.runs.store import _persist, artifact, load_run, render_repository_report, render_repository_sarif
        netrc, docker, sqlcmd, spanish, pair, codeql = ("Mx7Lq2Wz9Rt", "Pv8Kd3Hs6Yn", "Qw4Er7Ty1Ui", "Zx5Cv8Bn2Mk", "Lp9Ok3Ij7Uh", "Gt6Fr2De8Sw")
        base = {"title": "A finding", "confidence": 8, "cwe": [], "owasp": [], "cve": [], "ghsa": [], "verdict": "candidate",
                "priority": {"action": "attend", "factors": []}, "remediation": "Fix it.", "package": None, "advisory": None, "reason": "Why."}
        zizmor = {**base, "fingerprint": "a" * 64, "finding_id": "a" * 16, "scanner": "cicd", "tool": "zizmor", "rule_id": "excessive-permissions",
                  "path": ".github/workflows/ci.yml", "line": 4, "severity": "medium", "cwe": [250],
                  "snippet": f"build: runs-on: ubuntu-latest steps: - run: | echo 'machine x login y password {netrc}' > ~/.netrc "
                             f"docker login -u x -p {docker} sqlcmd -S db -U sa -P {sqlcmd}\nthis job uses write-all permissions"}
        opengrep = {**base, "fingerprint": "b" * 64, "finding_id": "b" * 16, "scanner": "sast", "tool": "opengrep", "rule_id": "x.y",
                    "path": "config.json", "line": 2, "severity": "high",
                    "snippet": f'{{\n  "contrasenia": "{spanish}",\n  "env": [{{"name":"API_SECRET","value":"{pair}"}}]\n}}'}
        sarif = {**base, "fingerprint": "c" * 64, "finding_id": "c" * 16, "scanner": "sast", "tool": "CodeQL", "rule_id": "py/sql-injection",
                 "path": "app.py", "line": 3, "severity": "high", "snippet": f"cur.execute(\"SELECT k FROM t WHERE v = '{codeql}'\")",
                 "reason": {"$t": "scanning.sarif.reason", "params": {"tool": "CodeQL", "message": f"flows to a sink: {codeql}"}}}
        stored = [zizmor, opengrep, sarif]
        before = {item["fingerprint"]: (canonical.identity_of(item), canonical.anywhere(item)) for item in stored}
        record = {"schema_version": "0.3.0", "id": "f" * 32, "created_at": datetime.now(timezone.utc).isoformat(), "type": "repository_scan",
                  "status": "completed", "target": "org/api", "source": {"id": "github:org/api", "uid": "github#1", "name": "org/api", "provider": "github"},
                  "findings": stored, "steps": [], "owasp_coverage": [], "limitations": [f"engine said: password {netrc}"], "context": "",
                  "summary": {"files": 3, "dependencies": 0, "candidates": 3, "severities": {}, "priorities": {}, "kev": 0, "fixable": 0, "tools": []}}
        _persist(self.data_dir, record, render_repository_report(record), render_repository_sarif(record))
        registry._save(self.data_dir, {"asset": "github#1", "name": "org/api", "applied": [], "findings": {
            item["fingerprint"]: {"status": "open", "finding": item} for item in stored}})

        self.assertIn("render_stored_texts", self.migrations.upgrade(self.data_dir))
        run = load_run(self.data_dir, "f" * 32)
        entries = registry.load(self.data_dir, "github#1")["findings"]
        texts = [json.dumps(run), json.dumps(entries), artifact(self.data_dir, "f" * 32, "report.md").decode(),
                 artifact(self.data_dir, "f" * 32, "findings.sarif").decode(), _rows(self.data_dir)]
        for text in texts:
            for value in (netrc, docker, sqlcmd, spanish, pair, codeql):
                self.assertNotIn(value, text)
        for item in [*run["findings"], *(entry["finding"] for entry in entries.values())]:
            self.assertEqual((canonical.identity_of(item), canonical.anywhere(item)), before[item["fingerprint"]], item["fingerprint"])
        ziz = next(item for item in run["findings"] if item["tool"] == "zizmor")
        self.assertNotIn("snippet", ziz)
        self.assertEqual(self.migrations._render_stored_texts(self.data_dir), 0)  # idempotent

    def test_what_the_positional_renderer_kept_is_rendered_again(self):
        """`render_stored_texts_lexicon`: a database that already ran `render_stored_texts` with the first renderer
        (which kept words for their position) has every such word rendered again, imported rule texts too; the
        identities stay and a second run changes nothing."""
        from pitangus.modules.runs.store import _persist, artifact, load_run, render_repository_report, render_repository_sarif
        from pitangus.shared import documents
        position = [migration.name for migration in self.migrations.MIGRATIONS].index("render_stored_texts_lexicon")
        documents.save(self.data_dir, self.migrations.VERSION_DOCUMENT, {"version": position, "history": []})
        comment, operand, pair, key, title = "Winter2024Corp", "Qz7xK9mPwL", "Vb9Rt4KwQz7x", "Lp9Ok3Ij7Uh", "Mx7Lq2Wz9Rt"
        base = {"confidence": 8, "cwe": [], "owasp": [], "cve": [], "ghsa": [], "verdict": "candidate", "severity": "high",
                "priority": {"action": "attend", "factors": []}, "remediation": "Fix it.", "package": None, "advisory": None}
        # As the first renderer stored them: a comment, an operand, what follows `;` in a value, a dict key.
        code = {**base, "title": "A finding", "fingerprint": "d" * 64, "finding_id": "d" * 16, "scanner": "sast", "tool": "opengrep",
                "rule_id": "x.y", "path": "app.py", "line": 2, "reason": f"engine said: DB_PASSWORD=***;{pair}=1",
                "snippet": f"def connect():\n    # ***: admin / {comment}\n    if token == {operand}:\n        return {{\"{key}\": \"***\"}}"}
        imported = {**base, "title": f"Hard-coded value {title}", "fingerprint": "e" * 64, "finding_id": "e" * 16, "scanner": "sast",
                    "tool": "Strix", "rule_id": "strix/x", "path": "app.py", "line": 3, "snippet": "run()",
                    "reason": {"$t": "scanning.sarif.reason", "params": {"tool": "Strix", "message": "found"}}}
        stored = [code, imported]
        before = {item["fingerprint"]: (canonical.identity_of(item), canonical.anywhere(item)) for item in stored}
        record = {"schema_version": "0.3.0", "id": "e" * 32, "created_at": datetime.now(timezone.utc).isoformat(), "type": "repository_scan",
                  "status": "completed", "target": "org/api", "source": {"id": "github:org/api", "uid": "github#2", "name": "org/api", "provider": "github"},
                  "findings": stored, "steps": [{"id": "x", "name": "x", "status": "completed", "detail": f"engine said: spring.datasource.password=***;{pair}=1"}],
                  "owasp_coverage": [], "limitations": [], "context": "",
                  "summary": {"files": 1, "dependencies": 0, "candidates": 2, "severities": {}, "priorities": {}, "kev": 0, "fixable": 0, "tools": []}}
        _persist(self.data_dir, record, render_repository_report(record), render_repository_sarif(record))
        registry._save(self.data_dir, {"asset": "github#2", "name": "org/api", "applied": [], "findings": {
            item["fingerprint"]: {"status": "open", "finding": item} for item in stored}})

        self.assertEqual(self.migrations.upgrade(self.data_dir), ["render_stored_texts_lexicon", "web_location_keys", "drop_stored_code"])
        run = load_run(self.data_dir, "e" * 32)
        entries = registry.load(self.data_dir, "github#2")["findings"]
        texts = [json.dumps(run), json.dumps(entries), artifact(self.data_dir, "e" * 32, "report.md").decode(),
                 artifact(self.data_dir, "e" * 32, "findings.sarif").decode(), _rows(self.data_dir)]
        for text in texts:
            for value in (comment, operand, pair, key, title):
                self.assertEqual(leaked(value, text), [], value)
        for item in [*run["findings"], *(entry["finding"] for entry in entries.values())]:
            self.assertEqual((canonical.identity_of(item), canonical.anywhere(item)), before[item["fingerprint"]], item["fingerprint"])
        self.assertNotIn("snippet", next(item for item in run["findings"] if item["tool"] == "opengrep"))   # no code since 0.14.1
        self.assertEqual(self.migrations._render_stored_texts(self.data_dir), 0)  # idempotent


if __name__ == "__main__":
    unittest.main()
