use colored::Colorize;
use crate::parser::{Package, find_and_parse};
use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub package_name: String,
    pub package_version: String,
    pub fixed_version: Option<String>,
}

pub struct Scanner;

impl Scanner {
    pub fn new() -> Self {
        Scanner
    }
    
    pub fn scan(&self, path: &Path) -> Result<Vec<Vulnerability>> {
        
        let packages = find_and_parse(path)?;
        
        if packages.is_empty() {
            return Ok(Vec::new());
        }
        
        println!("\nQuerying vulnerability database (OSV)...\n");
        
        
        let mut all_vulns = Vec::new();
        
        for (i, pkg) in packages.iter().enumerate() {
            print!("  Checking {}/{}: {}@{}...", 
                i + 1, 
                packages.len(),
                pkg.name.cyan(),
                pkg.version
            );
            
            match query_osv(pkg) {
                Ok(vulns) => {
                    if vulns.is_empty() {
                        println!(" {}", "✓".green());
                    } else {
                        println!(" {} found", format!("{} vulns", vulns.len()).red());
                        all_vulns.extend(vulns);
                    }
                }
                Err(e) => {
                    println!(" {} ({})", "✗".red(), e);
                }
            }
            
            
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        
        Ok(all_vulns)
    }
}


#[derive(Deserialize)]
struct OsvResponse {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    summary: String,
    details: String,
    severity: Vec<OsvSeverity>,
    affected: Vec<OsvAffected>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    score: String,
}

#[derive(Deserialize)]
struct OsvAffected {
    ranges: Vec<OsvRange>,
}

#[derive(Deserialize)]
struct OsvRange {
    fixed: Option<String>,
}

fn query_osv(pkg: &Package) -> Result<Vec<Vulnerability>> {
    
    let url = format!(
        "https://api.osv.dev/v1/query",
    );
    
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    
    
    let body = serde_json::json!({
        "package": {
            "name": pkg.name,
            "ecosystem": "npm"
        },
        "version": pkg.version
    });
    
    let response = client
        .post(&url)
        .json(&body)
        .send()?;
    
    if !response.status().is_success() {
        anyhow::bail!("API error: {}", response.status());
    }
    
    let osv_resp: OsvResponse = response.json()?;
    let mut vulns = Vec::new();
    
    if let Some(osv_vulns) = osv_resp.vulns {
        for v in osv_vulns {
            
            let severity = if !v.severity.is_empty() {
                let score = v.severity[0].score.parse::<f32>().unwrap_or(0.0);
                if score >= 9.0 {
                    "Critical"
                } else if score >= 7.0 {
                    "High"
                } else if score >= 4.0 {
                    "Medium"
                } else {
                    "Low"
                }
            } else {
                "Unknown"
            };
            
            
            let fixed = v.affected.get(0)
                .and_then(|a| a.ranges.get(0))
                .and_then(|r| r.fixed.clone());
            
            vulns.push(Vulnerability {
                id: v.id,
                title: v.summary,
                severity: severity.to_string(),
                description: v.details,
                package_name: pkg.name.clone(),
                package_version: pkg.version.clone(),
                fixed_version: fixed,
            });
        }
    }
    
    Ok(vulns)
}
