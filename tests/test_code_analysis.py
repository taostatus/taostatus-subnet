"""Static analyzer (secqurityVali/code_analysis): it must flag the real sinks a
white-box auditor would attack, tie them to the route + parameter, and leave safe
(parameterized / constant) code alone -- deterministically, with no network."""

from secqurityVali import code_analysis as ca


def _one(src, tmp_path):
    p = tmp_path / "app.py"
    p.write_text(src)
    return ca.analyze_file(str(p), "app.py")


# --- SQL injection ------------------------------------------------------

def test_sqli_fstring_is_flagged_with_route_and_param(tmp_path):
    src = (
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/search')\n"
        "def search():\n"
        "    q = request.args.get('q')\n"
        "    cur.execute(f\"SELECT * FROM products WHERE name = '{q}'\")\n"
    )
    cands = _one(src, tmp_path)
    sqli = [c for c in cands if c.category == 'sqli']
    assert len(sqli) == 1
    c = sqli[0]
    assert c.endpoint == '/search' and c.parameter == 'q' and c.confidence == 'high'
    assert c.line == 6


def test_sqli_query_built_into_variable_then_executed(tmp_path):
    # the common shape: build the query in a var, then execute the var
    src = (
        "from flask import request\n"
        "@app.get('/s')\n"
        "def s():\n"
        "    value = request.args.get('q')\n"
        "    query = f\"SELECT * FROM products WHERE name LIKE '%{value}%'\"\n"
        "    rows = db.execute(query).fetchall()\n"
    )
    sqli = [c for c in _one(src, tmp_path) if c.category == 'sqli']
    assert len(sqli) == 1 and sqli[0].parameter == 'q' and sqli[0].confidence == 'high'


def test_parameterized_query_is_safe(tmp_path):
    src = (
        "def q(cur, name):\n"
        "    cur.execute('SELECT * FROM products WHERE name = ?', (name,))\n"
    )
    assert [c for c in _one(src, tmp_path) if c.category == 'sqli'] == []


def test_sqli_string_concat_flagged(tmp_path):
    src = (
        "def q(cur, name):\n"
        "    cur.execute('SELECT * FROM t WHERE n = ' + name)\n"
    )
    assert any(c.category == 'sqli' for c in _one(src, tmp_path))


# --- command injection --------------------------------------------------

def test_cmdi_os_system_fstring(tmp_path):
    src = (
        "import os\n"
        "from flask import request\n"
        "@app.get('/ping')\n"
        "def ping():\n"
        "    host = request.args.get('host')\n"
        "    os.system(f'ping -c1 {host}')\n"
    )
    cmdi = [c for c in _one(src, tmp_path) if c.category == 'cmdi']
    assert len(cmdi) == 1 and cmdi[0].parameter == 'host' and cmdi[0].confidence == 'high'


def test_cmdi_subprocess_shell_true(tmp_path):
    src = (
        "import subprocess\n"
        "def run(x):\n"
        "    subprocess.run('echo ' + x, shell=True)\n"
    )
    assert any(c.category == 'cmdi' for c in _one(src, tmp_path))


def test_subprocess_without_shell_is_safe(tmp_path):
    src = (
        "import subprocess\n"
        "def run(x):\n"
        "    subprocess.run(['echo', x])\n"
    )
    assert [c for c in _one(src, tmp_path) if c.category == 'cmdi'] == []


# --- path traversal / LFI ----------------------------------------------

def test_lfi_open_from_request(tmp_path):
    src = (
        "from flask import request\n"
        "@app.get('/download')\n"
        "def download():\n"
        "    name = request.args.get('file')\n"
        "    return open('/srv/files/' + name).read()\n"
    )
    lfi = [c for c in _one(src, tmp_path) if c.category == 'lfi']
    assert len(lfi) == 1 and lfi[0].endpoint == '/download' and lfi[0].parameter == 'file'


def test_open_constant_path_is_safe(tmp_path):
    src = "def cfg():\n    return open('/etc/app/config.ini').read()\n"
    assert [c for c in _one(src, tmp_path) if c.category == 'lfi'] == []


# --- fastapi handler args as taint -------------------------------------

def test_fastapi_query_param_tainted(tmp_path):
    src = (
        "@app.get('/items')\n"
        "async def items(q: str):\n"
        "    cur.execute(f'SELECT * FROM items WHERE n = {q}')\n"
    )
    c = [x for x in _one(src, tmp_path) if x.category == 'sqli']
    assert len(c) == 1 and c[0].parameter == 'q' and c[0].confidence == 'high'


# --- hygiene ------------------------------------------------------------

def test_fully_safe_module_has_no_candidates(tmp_path):
    src = (
        "import os\n"
        "def f(cur):\n"
        "    cur.execute('SELECT 1')\n"
        "    return open('/etc/hostname').read()\n"
    )
    assert _one(src, tmp_path) == []


def test_syntax_error_file_is_ignored(tmp_path):
    p = tmp_path / "bad.py"
    p.write_text("def (:\n")
    assert ca.analyze_file(str(p), "bad.py") == []


def test_analyze_source_walks_tree_and_skips_vendored(tmp_path):
    (tmp_path / "app.py").write_text(
        "def q(cur, x):\n    cur.execute('SELECT * FROM t WHERE n=' + x)\n"
    )
    vendor = tmp_path / ".venv" / "pkg"
    vendor.mkdir(parents=True)
    (vendor / "lib.py").write_text(
        "def q(cur, x):\n    cur.execute('SELECT * FROM t WHERE n=' + x)\n"
    )
    cands = ca.analyze_source(str(tmp_path))
    files = {c.file for c in cands}
    assert "app.py" in files
    assert not any(".venv" in f for f in files)          # vendored tree skipped


def test_candidates_sorted_high_confidence_first(tmp_path):
    src = (
        "from flask import request\n"
        "@app.get('/a')\n"
        "def a():\n"
        "    x = request.args.get('x')\n"
        "    cur.execute(f'SELECT {x}')\n"            # high
        "def b(y):\n"
        "    cur.execute('SELECT ' + y)\n"            # medium
    )
    cands = _one(src, tmp_path)
    assert cands[0].confidence == 'high'
