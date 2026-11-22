# JEB headless MCP (5.47)

`jeb_linux.sh -c --script=x.py` and `-c --mcp` both answer
`Disregarding unknown argument` on 5.47 builds: `Launcher.main` only parses
`--license`, `--infile=`, `--interface=`, `--port=`, `--endpoint=`,
`--protocol=`, `--ks-*`, `--generate-key`, `--check-update`, `--logfile=`,
`--makeapkdebug`, `--`, `-h`. The command dispatch handshake (`gj`) is set by a
`Ve(int)` helper that main calls only with 2 (license key), 3 (update) and 7
(makeapkdebug) — script (4) and interface (9) branches are unreachable. So the
documented CLI flags are dead code, not user error.

Run `-c --help` to confirm the same list before assuming a wrong flag name.

## Working recipe

The MCP server is `com.pnfsoftware.jeb.client.mcp.JebMcpServerInstance.start(host,
port, endpoint, IClientContext)`. `com.pnfsoftware.jeb.da` is the headless MCP
client class (extends `HeadlessClientContext`), and its constructor is
`(boolean, host, int port, String endpoint, String protocol, String[] args)`.
Bootstrap it with a two-line Java main, compile against `bin/app/jeb.jar`, run
with `-cp "$JEB/bin/app/jeb.jar:$JEB/bin/app/*:<workdir>"` and cwd = `$JEB`:

```java
com.pnfsoftware.jeb.da d = new com.pnfsoftware.jeb.da(false, "127.0.0.1", 8425, "/mcp", null, new String[0]);
d.initialize(a); d.start();
```

- JEB needs JDK 21 here: Java 25 aborts with `A command line option has attempted
  to allow or enable the Security Manager`. Set `JAVA_HOME=java-21-openjdk-amd64`.
- The input file is the **first positional argument** (`AbstractClientContext`
  copies `args[0]` into `inputpath`); `--infile=` reaches a different branch and
  leaves `get_project_information` answering `There is no opened project`.
- The headless tool list has **no `open_project` / `run_script`** (they are
  graphical-client-only), so the project must exist from startup.
- Talk JSON-RPC over HTTP: `initialize` returns `Mcp-Session-Id`; echo it on later
  calls, then `notifications/initialized` before `tools/list`. Responses are SSE
  (`id:` then `data:` lines) even with `Accept: application/json` — concatenate
  the `data:` payloads and parse that, not the raw body.
- Useful tools: `get_project_information`, `list_units`, `list_code_items`,
  `get_type_information`, `list_cross_references`, `decompile_code_item`
  (`item_kind: type|method`, `item_address` like `Lud/l;`). `Lud/l;` style
  signatures are required; a dot-separated name silently finds nothing.
