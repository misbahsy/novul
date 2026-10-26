// `novul mcp`: minimal MCP server over stdio (newline-delimited JSON-RPC 2.0).
// stdout carries protocol messages only; diagnostics go to stderr.

use crate::cli::{self, Query};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;

const VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

const GUIDANCE: &str = "NoVul reports known vulnerabilities in the dependencies, Homebrew packages and runtimes on this Mac, from local scan results (OSV advisories). \
Findings are local results, not proof of safety: say \"no known vulnerabilities found\", never \"secure\". \
Call list_findings with project set to your working directory. Work in priority order: malicious, exploited (actively exploited), critical, high. \
fix_command is a suggestion: review it, then run it in the project folder. Prefer upgrading direct dependencies; for transitive ones use the package manager's overrides or resolutions. \
For a malicious package, remove it and rotate any secrets it could have read. Never print secret values (NoVul stores none, only fingerprints). \
After fixing and running the project's tests, call rescan with the project path to confirm the findings are gone.";

fn tools() -> Value {
    let project = json!({"type": "string", "description": "Directory (e.g. your working directory) or lockfile path; only findings of lockfiles inside it are returned"});
    json!([
        {
            "name": "list_findings",
            "description": "List open vulnerability findings from NoVul's latest local scan, most urgent first (malicious, exploited, critical, high, ...). Each has id, package, installed and fixed version, direct/transitive, advisory id and fix_command. fix_command is a suggestion: review it, then run it in the project folder. Prefer upgrading direct dependencies. After fixing, call rescan to confirm. Muted findings, dev-only findings and estimated ones (version guessed from requirements.txt, marked estimated: true) are hidden unless include_dev / include_estimated is set; malicious and actively exploited ones always show.",
            "inputSchema": {"type": "object", "properties": {
                "project": project,
                "min_priority": {"type": "string", "enum": ["malicious", "exploited", "critical", "high", "medium", "low"], "description": "Only findings at least this urgent"},
                "include_dev": {"type": "boolean", "description": "Include dev-only dependencies (default false)"},
                "include_estimated": {"type": "boolean", "description": "Include findings whose version is estimated, not read from a lockfile (default false)"},
                "limit": {"type": "number", "description": "Maximum findings returned (default 50)"}
            }},
            "annotations": {"title": "List findings", "readOnlyHint": true, "openWorldHint": false}
        },
        {
            "name": "get_finding",
            "description": "Full detail of one finding by id (from list_findings): summary, aliases, advisory URL, score, EPSS, fix_command (review before running).",
            "inputSchema": {"type": "object", "properties": {"id": {"type": "number"}}, "required": ["id"]},
            "annotations": {"title": "Get finding", "readOnlyHint": true, "openWorldHint": false}
        },
        {
            "name": "list_projects",
            "description": "List scanned projects (lockfiles) with open finding counts by priority, worst first.",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": {"title": "List projects", "readOnlyHint": true, "openWorldHint": false}
        },
        {
            "name": "rescan",
            "description": "Rescan lockfiles with NoVul and return the remaining open findings for them. Call this after fixing dependencies and running the project's tests, to confirm the findings are gone. Takes lockfile paths or project directories; takes seconds to a minute.",
            "inputSchema": {"type": "object", "properties": {"paths": {"type": "array", "items": {"type": "string"}, "description": "Lockfiles or project directories"}}, "required": ["paths"]},
            "annotations": {"title": "Rescan", "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": true}
        }
    ])
}

fn call_tool(db: &Path, name: &str, args: &Value) -> Result<Value, String> {
    let cap = |n: Option<u64>| n.map(|n| n as usize).unwrap_or(50);
    match name {
        "list_findings" => {
            let q = Query {
                projects: args["project"]
                    .as_str()
                    .map(|p| vec![p.to_string()])
                    .unwrap_or_default(),
                min: args["min_priority"]
                    .as_str()
                    .map(cli::parse_min)
                    .transpose()?,
                include_dev: args["include_dev"].as_bool().unwrap_or(false),
                include_estimated: args["include_estimated"].as_bool().unwrap_or(false),
                limit: Some(cap(args["limit"].as_u64())),
                ..Default::default()
            };
            let (total, findings) = cli::findings_json(db, &q)?;
            Ok(json!({"total": total, "returned": findings.len(), "findings": findings}))
        }
        "get_finding" => {
            let id = args["id"].as_i64().ok_or("id (number) is required")?;
            Ok(json!({"finding": cli::finding_json(db, id)?}))
        }
        "list_projects" => Ok(json!({"projects": cli::projects_json(db)?})),
        "rescan" => {
            let paths: Vec<String> = args["paths"]
                .as_array()
                .ok_or("paths (array of strings) is required")?
                .iter()
                .filter_map(|p| p.as_str().map(String::from))
                .collect();
            if paths.is_empty() {
                return Err("paths must not be empty".into());
            }
            let (scanned, warning) = cli::rescan(db, &paths)?;
            let q = Query {
                projects: scanned.clone(),
                limit: Some(cap(None)),
                ..Default::default()
            };
            let (total, findings) = cli::findings_json(db, &q)?;
            Ok(
                json!({"scanned": scanned, "warning": warning, "remaining": total, "findings": findings}),
            )
        }
        _ => Err(format!("unknown tool: {name}")),
    }
}

fn ok(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn err(id: &Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// One incoming line -> the reply to send, if any (notifications get none).
pub fn handle(db: &Path, line: &str) -> Option<Value> {
    let Ok(req) = serde_json::from_str::<Value>(line) else {
        return Some(err(&Value::Null, -32700, "parse error"));
    };
    let Some(method) = req["method"].as_str() else {
        // A response or malformed message; only malformed requests get an answer.
        return req
            .get("id")
            .filter(|_| req.get("result").is_none() && req.get("error").is_none())
            .map(|id| err(id, -32600, "invalid request"));
    };
    let id = req.get("id")?; // notifications (initialized, cancelled, ...) need no reply
    let params = &req["params"];
    Some(match method {
        "initialize" => {
            let asked = params["protocolVersion"].as_str().unwrap_or_default();
            let version = VERSIONS
                .iter()
                .find(|v| **v == asked)
                .unwrap_or(&VERSIONS[0]);
            ok(
                id,
                json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "novul", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": GUIDANCE,
                }),
            )
        }
        "ping" => ok(id, json!({})),
        "tools/list" => ok(id, json!({"tools": tools()})),
        "tools/call" => {
            let name = params["name"].as_str().unwrap_or_default();
            if !tools()
                .as_array()
                .is_some_and(|t| t.iter().any(|t| t["name"] == name))
            {
                return Some(err(id, -32602, &format!("unknown tool: {name}")));
            }
            ok(
                id,
                match call_tool(db, name, &params["arguments"]) {
                    Ok(v) => {
                        json!({"content": [{"type": "text", "text": v.to_string()}], "structuredContent": v})
                    }
                    Err(e) => json!({"content": [{"type": "text", "text": e}], "isError": true}),
                },
            )
        }
        _ => err(id, -32601, &format!("method not found: {method}")),
    })
}

pub fn main() -> i32 {
    let db = cli::db_path();
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        if let Some(reply) = handle(&db, &line) {
            if writeln!(out, "{reply}").and_then(|_| out.flush()).is_err() {
                break;
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests::temp_db;

    fn rpc(db: &Path, req: Value) -> Value {
        handle(db, &req.to_string()).expect("reply")
    }

    #[test]
    fn initialize_list_and_call() {
        let (_d, db) = temp_db();
        let init = rpc(
            &db,
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}),
        );
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(init["result"]["serverInfo"]["name"], "novul");
        assert!(init["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("rescan"));
        let newer = rpc(
            &db,
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2099-01-01"}}),
        );
        assert_eq!(newer["result"]["protocolVersion"], "2025-06-18");

        assert!(handle(
            &db,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        )
        .is_none());

        let list = rpc(
            &db,
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        );
        let names: Vec<_> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            ["list_findings", "get_finding", "list_projects", "rescan"]
        );

        let call = rpc(
            &db,
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "list_findings", "arguments": {"project": "/w/app", "min_priority": "high"}}}),
        );
        let result = &call["result"];
        assert!(result["isError"].is_null());
        let sc = &result["structuredContent"];
        assert_eq!(sc["total"], 1);
        assert_eq!(sc["findings"][0]["name"], "lodash");
        let text: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(&text, sc);

        let id = sc["findings"][0]["id"].clone();
        let one = rpc(
            &db,
            json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "get_finding", "arguments": {"id": id}}}),
        );
        assert_eq!(
            one["result"]["structuredContent"]["finding"]["group_id"],
            "CVE-1"
        );
    }

    #[test]
    fn errors_follow_json_rpc() {
        let (_d, db) = temp_db();
        assert_eq!(
            rpc(&db, json!({"jsonrpc": "2.0", "id": 1, "method": "nope"}))["error"]["code"],
            -32601
        );
        assert_eq!(handle(&db, "{not json").unwrap()["error"]["code"], -32700);
        assert_eq!(
            rpc(
                &db,
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "nope"}})
            )["error"]["code"],
            -32602
        );
        assert_eq!(
            rpc(&db, json!({"jsonrpc": "2.0", "id": 5, "method": "ping"}))["result"],
            json!({})
        );

        let bad = rpc(
            &db,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_findings", "arguments": {"min_priority": "urgent"}}}),
        );
        assert_eq!(bad["result"]["isError"], true);
        let nodb = handle(
            Path::new("/nonexistent/x.db"),
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_projects"}}"#,
        )
        .unwrap();
        assert_eq!(nodb["result"]["isError"], true);
        assert_eq!(nodb["result"]["content"][0]["text"], cli::MISSING_DB);
    }
}
