# GhidraMCP — Catálogo de Tools

Referência completa das 93 tools MCP expostas pelo bridge (`bridge_mcp_ghidra.py`). Cada tool corresponde a um endpoint HTTP num dos dois plugins Java rodando dentro do Ghidra.

```
[MCP client]  ⇄  bridge_mcp_ghidra.py  ⇄  http://127.0.0.1:8080   — GhidraMCPPlugin (CodeBrowser tool, análise estática)
                                      ⇄  http://127.0.0.1:18081  — GhidraMCPDebuggerPlugin (Debugger tool, runtime)
```

Convenções nesta referência:
- **Prefixo `dbg_`** — fala com o plugin Debugger (porta 18081). Requer o tool Debugger aberto; a maioria requer trace ativo (target lançado).
- **Sem prefixo** — fala com o plugin CodeBrowser (porta 8080). Requer program carregado.
- **Retorno `str` com JSON** — parsear com `json.loads()`. Endpoints JSON retornam HTTP 4xx/5xx em erro; demais retornam 200 com string de erro embutida.
- **Retorno `list`** — lista de linhas (output já split em `\n`).

---

## 📋 Índice

**Análise estática** (CodeBrowser, 67 tools)
1. [Observabilidade & sessão](#observabilidade--sessão)
2. [Multi-program](#multi-program)
3. [Agent workspace (notes)](#agent-workspace-notes)
4. [Navegação](#navegação)
5. [Listagens](#listagens)
6. [Busca](#busca)
7. [Função — metadata estruturada](#função--metadata-estruturada)
8. [Instrução — metadata estruturada](#instrução--metadata-estruturada)
9. [Call graph & CFG](#call-graph--cfg)
10. [Decompilação & P-code](#decompilação--p-code)
11. [Renomeação](#renomeação)
12. [Comentários](#comentários)
13. [Tipos (structs, enums, typedefs)](#tipos-structs-enums-typedefs)
14. [Labels & bookmarks](#labels--bookmarks)
15. [Equates (operando → enum)](#equates-operando--enum)
16. [Memória raw](#memória-raw)
17. [Xrefs](#xrefs)
18. [Undo/redo](#undoredo)

**Debugger runtime** (Debugger, 26 tools)
19. [Sessão & autonomia de launch](#sessão--autonomia-de-launch)
20. [Estado runtime](#estado-runtime)
21. [Controle de execução](#controle-de-execução)
22. [Memória & registradores runtime](#memória--registradores-runtime)
23. [Breakpoints & watchpoints](#breakpoints--watchpoints)
24. [Backend passthrough](#backend-passthrough)

---

## Análise estática (CodeBrowser, porta 8080)

### Observabilidade & sessão

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `health()` | — | JSON | Plugin version, Ghidra version, tool, uptime, programas abertos, programa atual e path. Primeiro call sanity. |
| `version()` | — | str | Versão resumida em texto plain. |
| `stats()` | — | JSON | Contador total de requests, rps, bytes, `by_endpoint: {path: count}`. |

### Multi-program

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `list_programs()` | — | list | Todos os programas abertos no CodeBrowser; `*` prefixa o current. |
| `switch_program(path)` | `path` | str | Muda o current program por pathname ou short name. |

### Agent workspace (notes)

Notes persistem em `Program.getOptions("GhidraMCP.AgentNotes")` — sobrevivem save/reopen do program.

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `note_set(key, value)` | `key`, `value` | str | Salva nota (ambas strings; encode JSON se precisar estrutura). |
| `note_get(key)` | `key` | str | Lê nota raw ou `Not found: <key>`. |
| `note_list()` | — | list | Todas as notas como `key: value` (value truncado a 120 chars). |
| `note_delete(key)` | `key` | str | Remove. |

### Navegação

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `get_current_address()` | — | str | Endereço onde o cursor do CodeBrowser está. |
| `get_current_function()` | — | str | Função contendo o cursor atual. |
| `get_function_by_address(address)` | `address` | str | Info textual de uma função. |

### Listagens

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `list_methods(offset, limit)` | offset=0, limit=100 | list | Nomes de funções paginados. |
| `list_functions()` | — | list | Nome + endereço. **Pode estourar em binários grandes — prefira `list_functions_filtered`.** |
| `list_functions_filtered(offset, limit, segment, complexity_min, has_xrefs, filter)` | vários | list | Paginado + filtros: segmento (`.text`), mínimo de instruções, bool de xrefs, substring no nome. |
| `list_classes(offset, limit)` | offset, limit | list | Namespaces/classes. |
| `list_namespaces(offset, limit)` | offset, limit | list | Namespaces não-globais. |
| `list_segments(offset, limit)` | offset, limit | list | Memory blocks. |
| `list_imports(offset, limit)` | offset, limit | list | Símbolos importados. |
| `list_exports(offset, limit)` | offset, limit | list | Símbolos exportados. |
| `list_data_items(offset, limit)` | offset, limit | list | Data labels + valores. |
| `list_strings(offset, limit, filter)` | vários | list | Strings definidas, filter opcional. |
| `list_labels(offset, limit, filter)` | vários | list | Labels user + funções, filter substring. |
| `list_bookmarks(offset, limit, category)` | vários | list | Bookmarks Note, category opcional. |
| `list_data_types(offset, limit, category, filter)` | vários | list | Data types no DTM. |
| `list_comments(offset, limit, type)` | type=all\|EOL\|PRE\|POST\|PLATE\|REPEATABLE | list | Todos comentários do program, `ADDR [TYPE] text`. |

### Busca

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `search_functions_by_name(query, offset, limit)` | substring | list | Matches no nome. |
| `search_bytes(pattern, segment, limit)` | pattern com `??` wildcard | list | Padrão hex em memória, segment opcional. Ex: `"48 8b ?? c3"`. |

### Função — metadata estruturada

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `get_function_info(address)` | `address` | JSON str | **Preferir** isso ao `decompile_function`. Retorna `{name, entry, signature, size, is_thunk, is_inline, is_external, calling_convention, params:[{name,type,storage}], locals, callees, callers, tags}`. |

### Instrução — metadata estruturada

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `get_instruction_info(address)` | `address` | JSON str | `{address, mnemonic, length, bytes_hex, flow_type, fall_through, operands, inputs, outputs, pcode}`. |

### Call graph & CFG

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `get_callees_recursive(address, depth, limit)` | depth=2 max=6, limit=200 | JSON | BFS down do call graph. Flat list `{name, entry, depth, parent}`. |
| `get_callers_recursive(address, depth, limit)` | depth=2, limit=200 | JSON | BFS up ("quem pode chegar nessa função"). |
| `get_function_cfg(address)` | `address` | JSON | Basic blocks + edges com `flow_type` (FALL_THROUGH, CONDITIONAL_JUMP, UNCONDITIONAL_CALL, ...). |

### Decompilação & P-code

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `decompile_function(name)` | nome | str | C decompilado por nome. |
| `decompile_function_by_address(address)` | `address` | str | C decompilado por endereço. |
| `decompile_with_map(address, name)` | um dos dois | list | Cada linha prefixada pelo endereço do token mínimo: `"0x401000 | int main(...)"`. |
| `disassemble_function(address)` | `address` | list | Disasm linha-a-linha com comentários. |
| `get_high_pcode(address)` | `address` | list | HighFunction pcode (IR pós-decompile). |
| `get_pcode(address, length)` | length=0 (função inteira) | list | P-code raw por instrução. |

### Renomeação

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `rename_function(old_name, new_name)` | nomes | str | Rename por nome. |
| `rename_function_by_address(function_address, new_name)` | addr + name | str | Rename por endereço (prefira esse). |
| `rename_data(address, new_name)` | addr + name | str | Renomeia data label. |
| `rename_variable(function_name, old_name, new_name)` | vários | str | Renomeia var local. |
| `create_label(address, name)` | addr + name | str | Cria label USER_DEFINED em endereço arbitrário. |
| `remove_label(address, name="")` | addr, name opcional | str | Remove label. |

### Comentários

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `set_decompiler_comment(address, comment)` | addr + text | str | PRE comment (decompile). |
| `set_disassembly_comment(address, comment)` | addr + text | str | EOL comment (disasm). |

### Tipos (structs, enums, typedefs)

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `get_data_type(name)` | nome | str | Dump textual de struct/enum/typedef. |
| `create_struct(name, fields, category, packed)` | `fields:[{name,type,offset?}]` | str | Cria struct via JSON. Tipos aceitam C-style: `int`, `char*`, `T **`. |
| `create_enum(name, size, values, category)` | `values:[{name,value}]` | str | Cria enum, size em bytes (1/2/4/8). |
| `create_typedef(name, target_type, category)` | alias | str | Cria typedef. |
| `apply_data_type(address, type_name, clear_existing)` | vários | str | Aplica tipo a endereço. `clear_existing=True` sobrescreve. |
| `delete_data_type(name)` | nome | str | Remove do DTM. |
| `set_function_prototype(function_address, prototype)` | texto C | str | Aplica signature. |
| `set_local_variable_type(function_address, variable_name, new_type)` | vários | str | Muda tipo de local var. |

### Labels & bookmarks

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `set_bookmark(address, category, comment)` | vários | str | Cria/sobrescreve bookmark Note. |
| `remove_bookmark(address, category)` | addr + cat | str | Remove bookmark. |

### Equates (operando → enum)

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `apply_enum_value(address, operand_index, enum_name, value)` | vários | str | Transforma `push 0x42` em `push MY_FLAGS::FOO` sem mudar bytes. Enum precisa existir (criar via `create_enum`). |

### Memória raw

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `read_bytes(address, length, format)` | format=hex\|base64 | str | Lê bytes do arquivo estático. Max 4096 bytes. |

### Xrefs

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `get_xrefs_to(address, offset, limit)` | addr + paginação | list | Quem referencia `address`. |
| `get_xrefs_from(address, offset, limit)` | addr + paginação | list | Pra onde `address` aponta. |
| `get_function_xrefs(name, offset, limit)` | nome | list | Referências à entry da função. |

### Undo/redo

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `undo(count=1)` | count | str | Desfaz N transações. Retorna contagem + `canUndo`/`canRedo`. |
| `redo(count=1)` | count | str | Refaz N desfeitas. |

---

## Debugger runtime (porta 18081)

### Sessão & autonomia de launch

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `dbg_ping()` | — | str | Confirma plugin Debugger up + nome do tool. |
| `dbg_health()` | — | JSON | Status, trace_active, execution_state, target_alive. |
| `dbg_version()` | — | str | Versão Debugger plugin. |
| `dbg_stats()` | — | JSON | Counters do plugin Debugger. |
| `dbg_list_launchers()` | — | list | Launchers TraceRmi disponíveis pro program atual (GDB/dbgeng/LLDB/Java + variantes). Inclui schema de params. |
| `dbg_launch(launcher_id, args)` | config_name + args{} | JSON | Genérico: lança via config_name (de `list_launchers`). |
| `dbg_launch_gdb(binary_path, args)` | vários | str | Wrapper pra GDB local. |
| `dbg_launch_dbgeng(binary_path, args)` | vários | str | Wrapper pra dbgeng (Windows). Prefere `local-dbgeng.bat`. |
| `dbg_disconnect()` | — | str | Termina sessão (kill + closeTrace). |

### Estado runtime

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `dbg_state()` | — | str | `execution_state`, trace, thread, PC, frame, snap, target_alive. |
| `dbg_list_threads()` | — | list | `id | name | alive=bool` por thread. |
| `dbg_list_frames()` | — | str | Frame atual (multi-frame é roadmap). |

### Controle de execução

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `dbg_resume()` | — | str | Continua execução. |
| `dbg_step_into()` | — | JSON | **Diff**: `{action, success, before_pc, after_pc, instruction, changed_registers}`. |
| `dbg_step_over()` | — | JSON | Idem, sem descer em calls. |
| `dbg_step_out()` | — | JSON | Roda até retornar do frame atual. |
| `dbg_interrupt()` | — | str | Pausa target. |
| `dbg_kill()` | — | str | **Destrutivo**: termina processo. |

### Memória & registradores runtime

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `dbg_read_memory(address, length, format)` | vários | str | Lê bytes runtime. Cap 4096. hex ou base64. |
| `dbg_write_memory(address, bytes_hex)` | vários | str | **Destrutivo**: escreve bytes no target vivo. Requer control mode writeable. |
| `dbg_read_registers(filter)` | filter=general\|float\|vector\|all | list | Registradores filtrados. Default `general` = ~24 GP regs; `all` = 1400+. |
| `dbg_write_register(name, value)` | vários | str | Escreve reg (hex `0x..` ou decimal). |

### Breakpoints & watchpoints

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `dbg_set_breakpoint(address)` | addr | str | Software execute breakpoint. |
| `dbg_set_watchpoint(address, length, kind)` | length=4, kind=read\|write\|access | str | Data breakpoint (watchpoint). |
| `dbg_remove_breakpoint(address)` | addr | str | Remove qualquer bp/watchpoint no endereço. |
| `dbg_list_breakpoints()` | — | list | Todos breakpoints lógicos. |

### Backend passthrough

| Tool | Args | Retorna | Propósito |
|---|---|---|---|
| `dbg_execute(command)` | string | str | Python REPL raw (dbgeng target) ou cmd syntax (GDB/LLDB). Sem pré-imports. |
| `dbg_execute_backend(command)` | string | str | **Preferir** no dbgeng. Wrap `pybag.dbgeng.util.dbg.cmd(...)`. Ex: `"r rax"`, `"u rip L4"`, `"k"`. |

---

## Fluxos típicos

### Investigação rápida de uma função
```python
info = json.loads(get_function_info("0x401000"))
cfg  = json.loads(get_function_cfg("0x401000"))
# Se info["callees"] é grande: deep BFS
graph = json.loads(get_callees_recursive("0x401000", depth=3, limit=50))
```

### Encontrar padrão + classificar
```python
hits = search_bytes("55 8b ec", segment=".text", limit=20)
for line in hits:
    addr = line.split()[0]
    info = json.loads(get_function_info(addr))
    note_set(f"fn_{addr}_summary", f"{info['name']} cc={info['calling_convention']}")
```

### Debug session autônoma (dbgeng)
```python
launchers = dbg_list_launchers()
# scolher BATCH_FILE:local-dbgeng.bat
result = dbg_launch("BATCH_FILE:local-dbgeng.bat", {
    "env:OPT_PYTHON_EXE": "C:/Python312/python.exe"
})
state = dbg_state()
# Set watchpoint numa variável global
dbg_set_watchpoint("0x403000", length=4, kind="write")
dbg_resume()
# Quando pausar no watchpoint:
regs = dbg_read_registers()
bt = dbg_execute_backend("k")
```

### Memória de sessão
```python
# Fim de uma sessão de análise:
note_set("aika_entry_analysis", json.dumps({
    "entry": "0x6a0437",
    "crt_init": True,
    "main_candidate": "FUR_006a8025",
    "findings": [...]
}))
# Próxima sessão:
prev = json.loads(note_get("aika_entry_analysis"))
```

---

## Arquivos relacionados

- `src/main/java/com/lauriewired/GhidraMCPPlugin.java` — plugin CodeBrowser
- `src/main/java/com/lauriewired/GhidraMCPDebuggerPlugin.java` — plugin Debugger
- `src/main/java/com/lauriewired/Util.java` — helpers HTTP/JSON compartilhados (incluindo `MiniJson` parser)
- `bridge_mcp_ghidra.py` — bridge FastMCP
- `CLAUDE.md` — orientações para manutenção

## Portas configuráveis

- **8080** CodeBrowser plugin → Tool Options `GhidraMCP HTTP Server → Server Port`
- **18081** Debugger plugin → Tool Options `GhidraMCP Debugger HTTP Server → Server Port`

Bridge flags: `--ghidra-server http://host:porta/`, `--ghidra-debugger-server http://host:porta/`.
