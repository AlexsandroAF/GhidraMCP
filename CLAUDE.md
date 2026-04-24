# CLAUDE.md

Orientações para Claude trabalhar eficientemente neste repositório.

## O que é

GhidraMCP = **dois plugins Java** empacotados num mesmo JAR + bridge MCP em Python. Cada plugin sobe um HTTP server separado num tool diferente do Ghidra; o bridge traduz chamadas MCP stdio/SSE em requisições HTTP para qualquer um dos dois. Clientes MCP (Claude Desktop, Claude Code CLI, Cline, 5ire) consomem as tools através do bridge.

```
                              ┌─ http://127.0.0.1:8080  ─ GhidraMCPPlugin         (CodeBrowser tool, análise estática)
[MCP client] ⇄ bridge_mcp_ghidra.py ⇄                                  (ambos dentro do Ghidra)
                              └─ http://127.0.0.1:18081 ─ GhidraMCPDebuggerPlugin (Debugger tool, runtime control)
```

O user pode ter só o CodeBrowser tool aberto, só o Debugger, ou os dois. As tools `mcp__ghidra__*` sem prefixo batem no CodeBrowser; as com prefixo `dbg_` batem no Debugger.

## Layout

- `src/main/java/com/lauriewired/GhidraMCPPlugin.java` — plugin do CodeBrowser (~2.3k linhas). Handlers estáticos: listagens, renomes, decompile, tipos, comentários, xrefs, labels, bookmarks, read_bytes, P-code markup.
- `src/main/java/com/lauriewired/GhidraMCPDebuggerPlugin.java` — plugin do Debugger tool (~320 linhas). 16 endpoints `/dbg/*` sobre `FlatDebuggerAPI`: state/threads/frames, read/write memory e registers, step/resume/interrupt/kill, breakpoints.
- `src/main/java/com/lauriewired/Util.java` — helpers HTTP/JSON compartilhados (parseQueryParams, parsePostParams, readBody, sendResponse, paginateList, parseLimitOrDefault, escapeNonAscii, MiniJson). Ambos plugins consomem.
- `bridge_mcp_ghidra.py` — wrapper FastMCP. Cada `@mcp.tool()` faz GET/POST para um endpoint do plugin. Metadata PEP 723 inline no topo — roda com `uv run bridge_mcp_ghidra.py` sem venv. Duas URLs configuráveis: `--ghidra-server` (CodeBrowser, 8080) e `--ghidra-debugger-server` (Debugger, 18081).
- `src/main/resources/extension.properties` — versão + versão mínima do Ghidra (ambas devem bater).
- `src/main/resources/META-INF/MANIFEST.MF` — `Plugin-Class`, `Plugin-Name`, etc. Usado pelo jar plugin.
- `src/main/resources/Module.manifest` — exigido pelo Ghidra para reconhecer o módulo.
- `src/assembly/ghidra-extension.xml` — descriptor Maven que monta o ZIP final.
- `lib/*.jar` — **não versionado** (`.gitignore: lib/*.jar`). Precisa copiar manualmente dos JARs do Ghidra antes de compilar. Lista completa abaixo.

## Versão alvo do Ghidra

**12.0.1** (data de build `20260114`). Três pontos sempre mudam juntos ao bumping:

1. `pom.xml` — 12 `<version>` nas dependências do Ghidra (8 base + 4 debugger)
2. `src/main/resources/extension.properties` — `version` + `ghidraVersion`
3. `.github/workflows/build.yml` — `GHIDRA_VERSION` + `GHIDRA_DATE`

Data de release de uma versão: `curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases | grep -A1 "Ghidra_<VER>_build"`.

## Como buildar

### Opção A — Maven (ambiente com `mvn` instalado, usado pelo CI)

```bash
mvn clean package assembly:single
```

Saída: `target/GhidraMCP-1.0-SNAPSHOT.zip`.

### Opção B — `build-local.sh` (Windows git-bash sem Maven)

Feito quando Maven não está disponível. Usa `javac` + `jar` do JDK. Mesma saída.

```bash
./build-local.sh
```

Três detalhes que esse script resolve e que **quebram silenciosamente** se alguém adaptar:

1. **Paths**: `javac.exe` do Windows não aceita paths Unix-style do git-bash (`/c/Users/...`). Usa `cygpath -w` para converter tanto o classpath quanto o argfile.
2. **ZIP separator**: `Compress-Archive` do PowerShell grava caminhos com `\` (viola a spec ZIP); o `ExtensionUtils.unzipToInstallationFolder` do Ghidra então falha com "caminho não encontrado". Usamos `jar.exe --create --no-manifest -C <dir> <entry>` que sempre grava com `/`.
3. **JDK detection**: o `javapath` da Oracle em `C:\Program Files\Common Files\Oracle\Java\javapath` só tem symlinks para `java.exe`, `javac.exe`, `javaw.exe`, `jshell.exe` — **não tem `jar.exe`**. O script procura um JDK completo (`jdk-25.0.2`, `jdk-21`, etc.) antes de cair para `$PATH`.

## JARs do Ghidra (pré-requisito de build)

Copiar de `<ghidra_dir>/Ghidra/` para `lib/`:

**Base (8, usados por ambos plugins):**

| JAR | Origem |
|---|---|
| `Base.jar` | `Features/Base/lib/` |
| `Decompiler.jar` | `Features/Decompiler/lib/` |
| `Docking.jar` | `Framework/Docking/lib/` |
| `Generic.jar` | `Framework/Generic/lib/` |
| `Project.jar` | `Framework/Project/lib/` |
| `SoftwareModeling.jar` | `Framework/SoftwareModeling/lib/` |
| `Utility.jar` | `Framework/Utility/lib/` |
| `Gui.jar` | `Framework/Gui/lib/` |

**Debugger (4, necessários para `GhidraMCPDebuggerPlugin`):**

| JAR | Origem |
|---|---|
| `Debugger-api.jar` | `Debug/Debugger-api/lib/` |
| `Framework-TraceModeling.jar` | `Debug/Framework-TraceModeling/lib/` |
| `Debugger.jar` | `Debug/Debugger/lib/` |
| `ProposedUtils.jar` | `Debug/ProposedUtils/lib/` |

O CI (`build.yml`) baixa o ZIP do Ghidra e copia esses JARs automaticamente. `build-local.sh` tem um sanity check que verifica os 12 jars em `lib/`.

## Estrutura do ZIP final

O Ghidra exige exatamente:

```
GhidraMCP/
├── extension.properties
├── Module.manifest
└── lib/
    └── GhidraMCP.jar      # com META-INF/MANIFEST.MF + com/lauriewired/*.class
```

## Compatibilidade de API do Ghidra

**Ghidra 12.0 depreciou** (GP-5742) `Listing.getComment(int,Address)` / `setComment(Address,int,String)` e os `int` constants `CodeUnit.EOL_COMMENT / PRE_COMMENT / PLATE_COMMENT`. Substitutos oficiais vivem em `ghidra.program.model.listing.CommentType` (enum: `EOL`, `PRE`, `POST`, `PLATE`, `REPEATABLE`).

Este repo **já migrou** para a nova API. Não reintroduzir os `int` constants — a compilação ainda aceita (métodos `default`), mas eles estão marcados `[removal]` e devem sumir em versão futura (provavelmente 13.0). Se vier um PR revertendo isso, rejeitar.

Conveniência disponível: `CommentType.valueOf(int)` converte o int legado → enum.

## Testar sem Ghidra aberto é impossível

- `GhidraMCPPlugin` só serve requisições quando o **CodeBrowser** está aberto **com um programa carregado**. Senão: `connection refused` ou endpoint retorna vazio.
- `GhidraMCPDebuggerPlugin` só serve quando o **tool Debugger** está aberto; `/dbg/*` com target ativo (launched via GDB/dbgeng/LLDB) responde com estado real, sem target responde `No active debug session`.
- Smoke test do CodeBrowser:
  ```bash
  curl http://localhost:8080/methods
  curl http://localhost:8080/get_current_function
  ```
- Smoke test do Debugger (não precisa de target pra o ping):
  ```bash
  curl http://localhost:18081/dbg/ping
  curl http://localhost:18081/dbg/state      # precisa de trace ativo
  ```
- Smoke test via MCP: o bridge expõe tools `mcp__ghidra__*` (CodeBrowser) e `mcp__ghidra__dbg_*` (Debugger). Cliente precisa estar configurado. Rodando via Claude Code:
  ```bash
  claude mcp add --scope user ghidra -- uv run <path>/bridge_mcp_ghidra.py
  ```
  (Reiniciar o Claude Code depois pra carregar.)

## Ordem canônica para validar mudanças na API de Ghidra

Quando alterar algo que toca a API nativa do Ghidra, validar em runtime **além** da compilação:

1. `mcp__ghidra__list_functions` / `get_current_function` — sanity check
2. `mcp__ghidra__disassemble_function` — exercita `Listing.getComment(CommentType.EOL, …)` no loop
3. `mcp__ghidra__set_disassembly_comment` — exercita `setComment(…, CommentType.EOL, …)`
4. `mcp__ghidra__set_decompiler_comment` — exercita `setComment(…, CommentType.PRE, …)`
5. `mcp__ghidra__set_function_prototype` — exercita `setComment(…, CommentType.PLATE, …)` via `addPrototypeComment`

Se os 5 passam, a migração está funcional em runtime (não só no compilador).

## Convenções do código Java

- Transações Ghidra: sempre `startTransaction` + try/finally com `endTransaction(tx, success)`. Nunca commitar transação em caminho de erro.
- Operações que tocam o AST/listing devem rodar na Swing EDT: `SwingUtilities.invokeAndWait(() -> { … })`.
- Logs: `Msg.error(this, msg, e)` (import `ghidra.util.Msg`). Não usar `System.err`.
- Plugin é stateful **por tool**: `getCurrentProgram()` vem do `PluginTool`. Bridge é stateless — passa tudo por query/body.

## Portas HTTP configuráveis

Dois plugins, duas portas, cada uma configurável via Tool Options do respectivo tool:

| Plugin | Tool | Default | Tool Options category |
|---|---|---|---|
| `GhidraMCPPlugin` | CodeBrowser | 8080 | `GhidraMCP HTTP Server → Server Port` |
| `GhidraMCPDebuggerPlugin` | Debugger | 18081 | `GhidraMCP Debugger HTTP Server → Server Port` |

Porta 18081 foi escolhida fora do range típico de dev (8xxx/3xxx/5xxx) porque 8081 frequentemente está ocupada (Jenkins, Tomcat, etc.). Ao precisar adicionar mais servers no futuro, ficar em 18xxx / 48xxx. Bridge flags: `--ghidra-server http://host:porta/` e `--ghidra-debugger-server http://host:porta/`.

## Pitfalls conhecidos

- **`list_functions` é gigante** em binários grandes — estoura limite de token do cliente MCP. Use `search_functions_by_name` ou paginação quando possível.
- **`mcp==1.5.0` em `requirements.txt`** é pin conservador; a metadata inline PEP 723 do script usa range `>=1.2.0,<2`. `uv run` pega a inline, `pip install -r` pega o pin — divergência real. Se algo quebrar entre versões do SDK MCP, checar qual das duas foi instalada.
- **Assembly descriptor** está no caminho atípico `src/assembly/ghidra-extension.xml` (não `src/main/assembly/`). Não mover — o `maven-assembly-plugin` referencia esse path no `pom.xml`.
- O script `build-local.sh` tem um warning cosmético `line 45: /c/Program: No such file or directory` no banner — é o `echo "$JAVAC -version"` sem quoting adequado em path com espaço. Inofensivo; ignorar.
