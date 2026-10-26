// Owner: feeds agent.
use crate::model::PackageKey;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

const URL: &str = "https://api.osv.dev/v1/querybatch";
const CHUNK: usize = 1000;
const MAX_PAGES: usize = 100;

/// Indices into the current chunk still to query, with the page token to continue from.
type Pending = Vec<(usize, Option<String>)>;

/// POST https://api.osv.dev/v1/querybatch in chunks of <= 1000 queries, following
/// `next_page_token`. Returns the sorted vuln ids for every queried package (empty vec if none).
pub async fn querybatch(client: &reqwest::Client, pkgs: &[PackageKey]) -> Result<HashMap<PackageKey, Vec<String>>, String> {
    let mut out = HashMap::new();
    for chunk in unique_chunks(pkgs) {
        let mut ids = vec![Vec::new(); chunk.len()];
        let mut pending: Pending = (0..chunk.len()).map(|i| (i, None)).collect();
        for _ in 0..MAX_PAGES {
            if pending.is_empty() {
                break;
            }
            let resp = post(client, &build_body(&chunk, &pending)).await?;
            pending = apply_response(&resp, &pending, &mut ids)?;
        }
        if !pending.is_empty() {
            return Err("OSV pagination did not terminate".into());
        }
        out.extend(chunk.into_iter().zip(ids));
    }
    Ok(out)
}

fn unique_chunks(pkgs: &[PackageKey]) -> Vec<Vec<PackageKey>> {
    let mut seen = HashSet::new();
    let unique: Vec<PackageKey> = pkgs.iter().filter(|p| seen.insert(*p)).cloned().collect();
    unique.chunks(CHUNK).map(|c| c.to_vec()).collect()
}

fn build_body(chunk: &[PackageKey], pending: &Pending) -> Value {
    let queries: Vec<Value> = pending
        .iter()
        .map(|(i, token)| {
            let k = &chunk[*i];
            let mut q = json!({"package": {"ecosystem": k.ecosystem, "name": k.name}, "version": k.version});
            if let Some(t) = token {
                q["page_token"] = json!(t);
            }
            q
        })
        .collect();
    json!({ "queries": queries })
}

/// Merges one response into `ids` (kept sorted and deduped) and returns the entries that
/// have another page.
fn apply_response(resp: &Value, pending: &Pending, ids: &mut [Vec<String>]) -> Result<Pending, String> {
    let results = resp["results"].as_array().ok_or("OSV response has no results")?;
    if results.len() != pending.len() {
        return Err(format!("OSV returned {} results for {} queries", results.len(), pending.len()));
    }
    let mut next = Vec::new();
    for ((i, _), r) in pending.iter().zip(results) {
        let list = &mut ids[*i];
        list.extend(r["vulns"].as_array().into_iter().flatten().filter_map(|v| v["id"].as_str()).map(String::from));
        list.sort();
        list.dedup();
        if let Some(t) = r["next_page_token"].as_str() {
            next.push((*i, Some(t.to_string())));
        }
    }
    Ok(next)
}

async fn post(client: &reqwest::Client, body: &Value) -> Result<Value, String> {
    let mut last = String::new();
    for _ in 0..2 {
        match client.post(URL).timeout(Duration::from_secs(30)).json(body).send().await {
            Ok(r) if r.status().is_server_error() => last = format!("OSV HTTP {}", r.status()),
            Ok(r) if !r.status().is_success() => return Err(format!("OSV HTTP {}", r.status())),
            Ok(r) => return r.json().await.map_err(|e| format!("OSV response: {e}")),
            Err(e) => last = format!("OSV request: {e}"),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str, version: &str) -> PackageKey {
        PackageKey { ecosystem: "PyPI".into(), name: name.into(), version: version.into() }
    }

    #[test]
    fn chunks_of_1000_after_dedupe() {
        let mut pkgs: Vec<PackageKey> = (0..2500).map(|i| key(&format!("p{i}"), "1.0")).collect();
        pkgs.extend((0..100).map(|i| key(&format!("p{i}"), "1.0")));
        let sizes: Vec<usize> = unique_chunks(&pkgs).iter().map(|c| c.len()).collect();
        assert_eq!(sizes, [1000, 1000, 500]);
    }

    #[test]
    fn request_body_shape_and_page_token() {
        let chunk = [key("requests", "2.19.0"), key("flask", "1.0")];
        let body = build_body(&chunk, &vec![(0, None), (1, Some("tok".into()))]);
        assert_eq!(body["queries"][0], json!({"package": {"ecosystem": "PyPI", "name": "requests"}, "version": "2.19.0"}));
        assert_eq!(body["queries"][1]["page_token"], "tok");
        assert_eq!(body["queries"][1]["package"]["name"], "flask");
    }

    #[test]
    fn real_response_is_sorted_and_missing_vulns_stay_empty() {
        let resp: Value = serde_json::from_str(include_str!("../../tests/fixtures/osv-api/querybatch-response.json")).unwrap();
        let mut resp = resp;
        resp["results"].as_array_mut().unwrap().push(json!({}));
        let pending: Pending = (0..3).map(|i| (i, None)).collect();
        let mut ids = vec![Vec::new(); 3];
        let next = apply_response(&resp, &pending, &mut ids).unwrap();
        assert!(next.is_empty());
        assert_eq!(ids[0].len(), 4);
        assert!(ids[0].windows(2).all(|w| w[0] < w[1]));
        assert_eq!(ids[1].len(), 3);
        assert!(ids[2].is_empty());
    }

    #[test]
    fn next_page_token_requeries_only_that_entry_and_merges() {
        let pending: Pending = vec![(0, None), (1, None), (2, None)];
        let mut ids = vec![Vec::new(); 3];
        let page1 = json!({"results": [
            {"vulns": [{"id": "B"}, {"id": "A"}], "next_page_token": "t1"},
            {"vulns": [{"id": "X"}]},
            {}
        ]});
        let next = apply_response(&page1, &pending, &mut ids).unwrap();
        assert_eq!(next, vec![(0, Some("t1".to_string()))]);
        let chunk = [key("a", "1"), key("b", "1"), key("c", "1")];
        let body = build_body(&chunk, &next);
        assert_eq!(body["queries"].as_array().unwrap().len(), 1);
        assert_eq!(body["queries"][0]["page_token"], "t1");

        let page2 = json!({"results": [{"vulns": [{"id": "C"}, {"id": "A"}]}]});
        assert!(apply_response(&page2, &next, &mut ids).unwrap().is_empty());
        assert_eq!(ids[0], ["A", "B", "C"]);
        assert_eq!(ids[1], ["X"]);
    }

    #[test]
    fn result_count_mismatch_is_an_error() {
        let resp = json!({"results": []});
        assert!(apply_response(&resp, &vec![(0, None)], &mut [Vec::new()]).is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn feeds_live_querybatch() {
        let client = reqwest::Client::new();
        let pkgs = [key("requests", "2.19.0"), key("Requests", "2.19.0"), key("requests", "2.32.4")];
        let got = querybatch(&client, &pkgs).await.unwrap();
        let old = &got[&pkgs[0]];
        assert!(old.contains(&"GHSA-x84v-xcm2-53pg".to_string()), "{old:?}");
        assert_eq!(old, &got[&pkgs[1]], "PyPI names are case-insensitive");
        assert!(got.contains_key(&pkgs[2]));
    }
}
