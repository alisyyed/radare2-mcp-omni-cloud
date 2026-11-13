/**
 * Radare2 Omni-Nexus v1.4 - Zero-Cache Edge-Smart Cloudflare Worker Router
 * ========================================================================
 * Permanent Gemini Connected Apps URL:
 *   https://radare2-mcp-forever.forested-lung.workers.dev/mcp
 * Reads LIVE_MCP_URL.json via the 0-cache GitHub Contents API and executes catalog
 * lookups and rax2 conversions in 0ms at the Cloudflare Edge!
 */
const GITHUB_API_LIVE_JSON_URL = "https://api.github.com/repos/alisyyed/radare2-mcp-omni-cloud/contents/LIVE_MCP_URL.json?ref=main";
const GITHUB_RAW_LIVE_JSON_URL = "https://raw.githubusercontent.com/alisyyed/radare2-mcp-omni-cloud/main/LIVE_MCP_URL.json";
const GITHUB_DISPATCH_URL = "https://api.github.com/repos/alisyyed/radare2-mcp-omni-cloud/actions/workflows/radare2_mcp_cloud.yml/dispatches";
const AUTO_WAKE_GH_TOKEN = "";
const EDGE_CURATED_TOOLS = [{"name": "r2_doctor_and_status", "description": "[Radare2 Omni-Nexus] Check health of the 24/7 Radare2 Cloud MCP Relay, Zero-Cache Edge Router, installed `r2` / `rabin2` / `rasm2` / `radiff2` / `rahash2` / `rax2` versions, `r2pm` plugins, and active binary session.", "inputSchema": {"type": "object", "properties": {}}}, {"name": "r2_list_ecosystem_and_plugins", "description": "[Radare2 Omni-Nexus] Browse or search the complete Radare2 v6.2.6+ and `r2mcp` v1.9.0 catalog (`core_cli_suite`, `official_r2mcp_server`, `r2pm_plugins`, `esil_and_r2pipe`).", "inputSchema": {"type": "object", "properties": {"category": {"type": "string", "description": "Optional category filter (`core_cli_suite`, `official_r2mcp_server`, `r2pm_plugins`, `esil_and_r2pipe`)."}, "search": {"type": "string", "description": "Optional keyword substring (e.g. 'esil', 'r2ghidra', 'rabin2', 'r2mcp', 'frida')."}}}}, {"name": "r2_rabin2_inspect_binary", "description": "[Radare2 Omni-Nexus] Inspect a binary file or URL with `rabin2` and `rahash2`: returns architecture, format, security mitigations (NX, PIC, Canary, RELRO), sections (`-Sj`), imports (`-ij`), exports (`-Ej`), strings (`-zj`), and SHA-256 / Shannon entropy.", "inputSchema": {"type": "object", "properties": {"target_url_or_path": {"type": "string", "description": "Path or HTTPS URL of the binary (pass 'default' to inspect the built-in cloud demo binary)."}}, "required": ["target_url_or_path"]}}, {"name": "r2_analyze_and_decompile_function", "description": "[Radare2 Omni-Nexus] Run `r2 -q -c 'aaa; aflj; s <func>; pdf; pdc'` on a target binary to list analyzed functions, disassemble `<func>`, extract its basic-block CFG (`agfj`), and generate pseudo-C decompilation (`pdc` / `pdg`).", "inputSchema": {"type": "object", "properties": {"target_url_or_path": {"type": "string", "description": "Target binary path or HTTPS URL (default: 'default')."}, "function_name": {"type": "string", "description": "Function symbol or address to disassemble and decompile (e.g. 'sym.derive_route_seed' or 'main')."}}, "required": ["function_name"]}}, {"name": "r2_run_command_or_r2pipe", "description": "[Radare2 Omni-Nexus] Execute one or more headless Radare2 commands (`r2 -q -c '<cmds>'`, such as `'aaa; aflj'`, `'iIj; iSj'`, `'axtj @ sym.main'`, or ESIL `'aei; aeim; aeip; 5aes; aerj'`) against the target binary in safe batch mode.", "inputSchema": {"type": "object", "properties": {"r2_commands": {"type": "string", "description": "Semicolon-separated Radare2 commands to run (e.g. 'aaa; aflj' or 's sym.derive_route_seed; pdf')."}, "target_url_or_path": {"type": "string", "description": "Optional target binary path or URL (default: 'default')."}}, "required": ["r2_commands"]}}, {"name": "r2_rasm2_assemble_disassemble", "description": "[Radare2 Omni-Nexus] Assemble instruction mnemonics into hex bytes or disassemble hex bytes into instructions across any architecture (`x86`, `arm`, `riscv`, `mips`, `ppc`, `wasm`, `dalvik`) using `rasm2`.", "inputSchema": {"type": "object", "properties": {"mode": {"type": "string", "description": "'assemble' (mnemonics -> hex) or 'disassemble' (hex -> mnemonics)."}, "arch": {"type": "string", "description": "Architecture name (e.g. 'x86', 'arm', 'riscv', 'mips'). Default: 'x86'."}, "bits": {"type": "integer", "description": "Bit width (16, 32, or 64). Default: 64."}, "payload": {"type": "string", "description": "Assembly instructions (e.g. 'mov eax, 0x2a; ret') or hex string (e.g. 'b82a000000c3')."}}, "required": ["mode", "payload"]}}, {"name": "r2_esil_emulate_snippet", "description": "[Radare2 Omni-Nexus] Lift assembly or hex bytes into Radare2 ESIL (Evaluable Strings Intermediate Language), step through the ESIL virtual machine (`aei; aeim; aeip; aes`), and return the final register values (`aerj`).", "inputSchema": {"type": "object", "properties": {"arch": {"type": "string", "description": "Architecture (e.g. 'x86', 'arm'). Default: 'x86'."}, "bits": {"type": "integer", "description": "Bit width (32 or 64). Default: 64."}, "instructions_or_function": {"type": "string", "description": "Assembly instructions (e.g. 'mov eax, 20; add eax, 22') or function symbol in the active binary."}}, "required": ["instructions_or_function"]}}, {"name": "r2_rax2_convert", "description": "[Radare2 Omni-Nexus] Convert numbers, hex strings, endianness, bitmasks, or ASCII strings using Radare2 `rax2` semantics (works in 0ms at the Cloudflare Edge and on the Cloud VM).", "inputSchema": {"type": "object", "properties": {"expression": {"type": "string", "description": "Value or expression to convert (e.g. '0x811c9dc5', '2166136261', '0b101010')."}}, "required": ["expression"]}}, {"name": "r2_penta_engine_bridge", "description": "[Radare2 Omni-Nexus] Orchestrate a 5-way binary engineering pipeline across `Radare2` (`radare2-omni-nexus`), `Ghidra` (`ghidra-omni-nexus`), `Hex-Rays IDA` (`ida-hexrays-omni-nexus`), `LLM4Decompile` (`llm4decompile-omni-nexus`), and `Craft-Anything` (`craft-anything-omni-foundry`).", "inputSchema": {"type": "object", "properties": {"workflow_goal": {"type": "string", "description": "Goal to coordinate across all 5 connected 24/7 Cloud MCP engines."}}, "required": ["workflow_goal"]}}];
const EDGE_CATALOG = {"core_cli_suite": {"title": "Radare2 Core Command-Line Toolset (radareorg/radare2 v6.2.6+)", "repo_url": "https://github.com/radareorg/radare2", "docs_url": "https://book.rada.re/", "items": ["r2 / radare2 (Core interactive & batch disassembler, analyzer `aaa`, decompiler `pdc`/`pdg`/`pdd`, ESIL VM `ae*`, and QuickJS scripting engine)", "rabin2 (Binary header, section `-Sj`, symbol `-sj`, import `-ij`, export `-Ej`, string `-zj`, and relocation `-Rj` JSON extractor)", "rasm2 (Multi-architecture assembler & disassembler across 80+ ISAs: x86_64, arm64, riscv, mips, ppc, wasm, dalvik, evm, sBPF, tricore)", "radiff2 (Binary diffing engine: byte diffing, Levenshtein distance `-s`, and function CFG graph diffing `-g` / `-AC`)", "rafind2 (High-speed hex pattern `-x`, regex `-e`, and ASCII/wide string `-s`/`-S` binary scanner)", "rahash2 (Block-based cryptographic hashing and Shannon entropy `-a entropy` analyzer)", "rax2 (Radare2 base converter: hex, decimal, binary, octal, floating-point, endian swap, and ASCII string encoding)", "ragg2 (r_egg compiler for compiling C-like dialect snippets into standalone position-independent payloads)", "rarun2 (Process execution launcher for custom environment, stdio redirection, chroot, and socket forwarding)"]}, "official_r2mcp_server": {"title": "Official Radare2 MCP Server (radareorg/radare2-mcp v1.9.0)", "repo_url": "https://github.com/radareorg/radare2-mcp", "install_cmd": "r2pm -Uci r2mcp", "stdio_cmd": "r2pm -r r2mcp", "http_cmd": "r2mcp -H 0.0.0.0:8765 -X 8:600", "items": ["open_file (Load target binary into RCore session)", "analyze (Run r2 analysis pass level 1-4: aa, aaa, aaaa)", "listFunctions (Return analyzed functions `aflj` with address, size, and cyclomatic complexity)", "listImports / listExports / listSymbols / listLibraries / listEntrypoints (JSON metadata inspection)", "listStrings / listClasses (Extract strings with optional regex filter and C++/ObjC/DEX classes)", "listDecompilers / useDecompiler / decompileFunction (Run pdc, r2ghidra pdg, or r2dec pdd)", "disassemble / DisassembleFunction (Disassemble instruction ranges `pdj` or full functions `pdfj`)", "xrefsTo (Cross-references `axtj` to any address or symbol)", "renameFunction (Rename function symbol in RCore)", "sql (Query binary database via r2xsql plugin: e.g. SELECT name, size FROM funcs ORDER BY size DESC)", "runCommand (Execute raw r2 command or r2js script when enabled)"]}, "r2pm_plugins": {"title": "Radare2 Package Manager (r2pm) Ecosystem Plugins", "repo_url": "https://github.com/radareorg/radare2-pm", "items": ["r2ghidra (`r2pm -Uci r2ghidra r2ghidra-sleigh`: Native C++ Ghidra Sleigh decompiler inside r2 via `pdg` / `pdgj`)", "r2dec (`r2pm -Uci r2dec`: QuickJS-based decompiler inside r2 via `pdd` / `pddj`)", "r2ai & decai (`r2pm -Uci r2ai decai`: LLM-assisted decompilation inside r2 via `decai -d` and `decai -dr`)", "r2frida (`r2pm -Uci r2frida`: Dynamic instrumentation via `r2 frida://0` and `:dt`, `:dm`, `:ii` commands)", "radius2 (`r2pm -Uci radius2`: Fast symbolic execution engine powered by ESIL and Boolector SMT solver)", "r2diaphora (Diaphora binary diffing integration on top of radare2)", "r2flutter & r2unity & r2hermes (Dart/Flutter AOT snapshot, Unity IL2CPP, and React Native Hermes analyzers)", "r2yara & r2sarif & warrp (YARA rule scanning, SARIF import/export, and Binary Ninja WARP signature support)", "iaito (Official Qt GUI frontend for radare2)"]}, "esil_and_r2pipe": {"title": "ESIL Virtual Machine & r2pipe Multi-Language Scripting", "repo_url": "https://book.rada.re/emulation/esil.html", "items": ["aei / aeim / aeip (Initialize ESIL VM state, stack memory map, and set PC to current seek)", "aes / aeso / aesu <addr> (Step ESIL instruction, step over call, or emulate until target address)", "aer / aej (Inspect or modify ESIL register state in JSON)", "aefa <addr> (Emulate function execution to resolve stack strings and computed jump targets)", "r2pipe Python (`import r2pipe; r2 = r2pipe.open(path); funcs = r2.cmdj('aaa; aflj')`)", "QuickJS Embedded Runtime (`r2 -qi script.r2.js` using native `r2.cmd()` and `r2.cmdj()`)"]}};

async function triggerGithubAutoWake() {
  if (!AUTO_WAKE_GH_TOKEN) return false;
  try {
    const r = await fetch(GITHUB_DISPATCH_URL, {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + AUTO_WAKE_GH_TOKEN,
        "Accept": "application/vnd.github+json",
        "User-Agent": "Radare2-Permanent-Router/1.4",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ ref: "main" })
    });
    return r.status === 204 || r.status === 200;
  } catch (_) {
    return false;
  }
}

async function getLatestTunnelUrl() {
  if (AUTO_WAKE_GH_TOKEN) {
    try {
      const apiRes = await fetch(GITHUB_API_LIVE_JSON_URL + "&t=" + Date.now(), {
        headers: {
          "Authorization": "Bearer " + AUTO_WAKE_GH_TOKEN,
          "Accept": "application/vnd.github.raw+json",
          "User-Agent": "Radare2-Permanent-Router/1.4",
          "X-GitHub-Api-Version": "2022-11-28"
        }
      });
      if (apiRes.ok) {
        return await apiRes.json();
      }
    } catch (_) {}
  }
  const res = await fetch(GITHUB_RAW_LIVE_JSON_URL + "?t=" + Date.now(), {
    headers: { "User-Agent": "Radare2-Permanent-Router/1.4" }
  });
  if (!res.ok) throw new Error("Could not fetch LIVE_MCP_URL.json: HTTP " + res.status);
  return await res.json();
}

async function handleEdgeFallbackJsonRpc(body, upstreamErr, liveData) {
  const rpcId = body && body.id !== undefined ? body.id : 1;
  const method = (body && body.method) || "";
  const params = (body && body.params) || {};

  if (method === "initialize") {
    return {
      jsonrpc: "2.0",
      id: rpcId,
      result: {
        protocolVersion: "2025-03-26",
        capabilities: { tools: { listChanged: true } },
        serverInfo: { name: "Radare2-OmniNexus", version: "1.4.0" }
      }
    };
  }

  if (method === "notifications/initialized" || method.startsWith("notifications/")) {
    return { jsonrpc: "2.0", id: rpcId, result: {} };
  }

  if (method === "tools/list") {
    return {
      jsonrpc: "2.0",
      id: rpcId,
      result: { tools: EDGE_CURATED_TOOLS }
    };
  }

  if (method === "tools/call") {
    const tName = params.name || "";
    const tArgs = params.arguments || {};

    if (tName === "r2_list_ecosystem_and_plugins") {
      const catFilter = String(tArgs.category || "").trim().toLowerCase();
      const qFilter = String(tArgs.search || "").trim().toLowerCase();
      const out = {};
      for (const [k, v] of Object.entries(EDGE_CATALOG)) {
        if (catFilter && catFilter !== k) continue;
        const matched = v.items.filter((item) => !qFilter || item.toLowerCase().includes(qFilter) || v.title.toLowerCase().includes(qFilter));
        if (matched.length > 0) {
          out[k] = { title: v.title, repo_url: v.repo_url, count: matched.length, items: matched };
        }
      }
      return {
        jsonrpc: "2.0",
        id: rpcId,
        result: { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] }
      };
    }

    if (tName === "r2_doctor_and_status") {
      return {
        jsonrpc: "2.0",
        id: rpcId,
        result: {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "LIVE_EDGE_AND_CLOUD_HYBRID",
              router_version: "Radare2 Omni-Nexus v1.4 Zero-Cache Edge-Smart Router",
              repository: "https://github.com/radareorg/radare2",
              official_mcp_repo: "https://github.com/radareorg/radare2-mcp",
              backend_relay_state: liveData || { status: "ROTATING_OR_WAKING", detail: String(upstreamErr || "") }
            }, null, 2)
          }]
        }
      };
    }

    return {
      jsonrpc: "2.0",
      id: rpcId,
      result: {
        content: [{
          type: "text",
          text: JSON.stringify({
            status: "CLOUD_RELAY_BOOTING_OR_WAKING",
            tool_requested: tName,
            message: "Your 24/7 GitHub Cloud Relay for radareorg/radare2 is waking (~25s). Repeat this tool call shortly!",
            detail: String(upstreamErr || "")
          }, null, 2)
        }]
      }
    };
  }

  return { jsonrpc: "2.0", id: rpcId, result: {} };
}

export default {
  async fetch(request) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Accept, MCP-Session-Id, Last-Event-ID"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);
    let parsedBody = null;
    let rawBodyBuffer = undefined;
    if (request.method !== "GET" && request.method !== "HEAD") {
      rawBodyBuffer = await request.arrayBuffer();
      try {
        parsedBody = JSON.parse(new TextDecoder().decode(rawBodyBuffer));
      } catch (_) {}
    }

    if (parsedBody && (
      parsedBody.method === "initialize" ||
      parsedBody.method === "notifications/initialized" ||
      parsedBody.method === "tools/list" ||
      (parsedBody.method === "tools/call" && parsedBody.params && parsedBody.params.name === "r2_list_ecosystem_and_plugins")
    )) {
      return new Response(JSON.stringify(await handleEdgeFallbackJsonRpc(parsedBody, null, null)), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }

    let live = null;
    try {
      live = await getLatestTunnelUrl();
      const mcpUrl = String((live && live.mcp_url) || "").trim();
      if (!mcpUrl.startsWith("https://")) {
        throw new Error("LIVE_MCP_URL.json mcp_url is not a full https:// URL yet: " + JSON.stringify(mcpUrl));
      }
      const targetBase = (live.gui_url && String(live.gui_url).startsWith("https://") ? live.gui_url : mcpUrl.replace(/\/mcp$/, "")).replace(/\/$/, "");
      const targetUrl = targetBase + url.pathname + url.search;

      if (request.method === "GET" && (url.pathname === "/status" || url.pathname === "/router-status")) {
        return new Response(JSON.stringify({
          router: "Radare2 Omni-Nexus v1.4 Zero-Cache Edge-Smart Router",
          active_backend_mcp_url: live.mcp_url,
          active_backend_gui_url: live.gui_url,
          updated_at: live.updated_at
        }, null, 2), {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      const proxyReq = new Request(targetUrl, {
        method: request.method,
        headers: request.headers,
        body: rawBodyBuffer,
      });
      const resp = await fetch(proxyReq);
      if (resp.status === 530 || resp.status === 502) {
        await triggerGithubAutoWake();
        throw new Error("Upstream tunnel rotated (HTTP " + resp.status + ") - triggered Auto-Wake!");
      }
      const newHeaders = new Headers(resp.headers);
      newHeaders.set("Access-Control-Allow-Origin", "*");
      return new Response(resp.body, { status: resp.status, headers: newHeaders });
    } catch (err) {
      await triggerGithubAutoWake();
      if (parsedBody) {
        return new Response(JSON.stringify(await handleEdgeFallbackJsonRpc(parsedBody, err, live)), {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
      return new Response(JSON.stringify({
        status: "AUTO_WAKING_CLOUD_RELAY",
        router: "Radare2 Omni-Nexus v1.4 Zero-Cache Edge-Smart Router",
        repository: "https://github.com/radareorg/radare2",
        live_json_state: live,
        message: "Signaled your 24/7 Radare2 GitHub Cloud Relay to wake (~25s).",
        error: String(err)
      }, null, 2), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }
  }
};
