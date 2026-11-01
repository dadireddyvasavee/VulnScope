"""Sources, sinks and sanitizers (Python / Flask / Django / stdlib)."""

# Attribute/call prefixes whose values are attacker-controlled
SOURCE_PREFIXES = ("flask.request.", "request.args", "request.form", "request.values", "request.json",
                   "request.get_json", "request.cookies", "request.headers", "request.data", "request.files",
                   "request.GET", "request.POST", "request.body", "sys.argv")
SOURCE_CALLS = {"input", "builtins.input"}

SANITIZERS = {"int", "float", "bool", "shlex.quote", "os.path.basename", "werkzeug.utils.secure_filename",
              "secure_filename", "html.escape", "markupsafe.escape", "re.escape", "uuid.UUID"}

# sink name -> (cwe, title, index of dangerous positional arg, keyword name or None)
SINKS = {
    "os.system": ("CWE-78", "OS command injection", 0, None),
    "os.popen": ("CWE-78", "OS command injection", 0, None),
    "subprocess.getoutput": ("CWE-78", "OS command injection", 0, None),
    "subprocess.getstatusoutput": ("CWE-78", "OS command injection", 0, None),
    "eval": ("CWE-95", "Code injection via eval", 0, None),
    "exec": ("CWE-95", "Code injection via exec", 0, None),
    "pickle.loads": ("CWE-502", "Insecure deserialization (pickle)", 0, None),
    "pickle.load": ("CWE-502", "Insecure deserialization (pickle)", 0, None),
    "marshal.loads": ("CWE-502", "Insecure deserialization (marshal)", 0, None),
    "dill.loads": ("CWE-502", "Insecure deserialization (dill)", 0, None),
    "open": ("CWE-22", "Path traversal", 0, "file"),
    "builtins.open": ("CWE-22", "Path traversal", 0, "file"),
    "flask.send_file": ("CWE-22", "Path traversal", 0, None),
    "os.remove": ("CWE-22", "Path traversal", 0, None),
    "shutil.rmtree": ("CWE-22", "Path traversal", 0, None),
    "requests.get": ("CWE-918", "Server-side request forgery", 0, "url"),
    "requests.post": ("CWE-918", "Server-side request forgery", 0, "url"),
    "urllib.request.urlopen": ("CWE-918", "Server-side request forgery", 0, "url"),
}
SUBPROCESS_SHELL = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
                    "subprocess.Popen"}
SQL_METHODS = {"execute", "executemany", "executescript", "raw", "extra"}
ALWAYS_UNSAFE_DESERIALIZERS = {"pickle.loads", "pickle.load", "marshal.loads", "dill.loads"}
