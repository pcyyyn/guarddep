use anyhow::Result;
use clap::Parser;
use colored::*;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Clone, Debug)]
struct Package {
    name: String,
    version: String,
    ecosystem: String,
}

#[derive(Clone, Debug)]
struct Vulnerability {
    id: String,
    title: String,
    severity: String,
    description: String,
    package_name: String,
    package_version: String,
    fixed_version: Option<String>,
}

#[derive(Parser)]
#[command(name = "guarddep")]
#[command(about = "A simple dependency security scanner")]
#[command(version = "0.1.0")]
struct Cli {
    #[arg(default_value = ".")]
    path: PathBuf,
    #[arg(short, long)]
    severity: Option<String>,
}

fn find_and_parse(path: &std::path::Path) -> Result<Vec<Package>> {
    let mut packages = Vec::new();
    let package_json = path.join("package.json");
    
    if package_json.exists() {
        println!("[FILE] Found package.json");
        let content = std::fs::read_to_string(&package_json)?;
        let mut pkgs = parse_package_json(&content)?;
        println!("[OK] Parsed {} dependencies", pkgs.len().to_string().green());
        packages.append(&mut pkgs);
    }
    
    if packages.is_empty() {
        println!("{}", "[WARN] No supported manifest files found".yellow());
        println!("   Looking for: package.json");
    }
    
    Ok(packages)
}

fn parse_package_json(content: &str) -> Result<Vec<Package>> {
    #[derive(Deserialize)]
    struct PackageJson {
        dependencies: Option<HashMap<String, String>>,
    }
    
    let package: PackageJson = serde_json::from_str(content)?;
    let mut packages = Vec::new();
    
    if let Some(deps) = package.dependencies {
        for (name, version) in deps {
            let clean_version = version.trim_start_matches(|c: char| !c.is_ascii_digit());
            packages.push(Package {
                name,
                version: clean_version.to_string(),
                ecosystem: "npm".to_string(),
            });
        }
    }
    
    Ok(packages)
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

fn query_osv(client: &Client, pkg: &Package) -> Result<Vec<Vulnerability>> {
    let url = "https://api.osv.dev/v1/query";
    
    let body = serde_json::json!({
        "package": {
            "name": pkg.name,
            "ecosystem": "npm"
        },
        "version": pkg.version
    });
    
    let response = client
        .post(url)
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
                    "Critical".to_string()
                } else if score >= 7.0 {
                    "High".to_string()
                } else if score >= 4.0 {
                    "Medium".to_string()
                } else {
                    "Low".to_string()
                }
            } else {
                "Unknown".to_string()
            };
            
            let fixed = v.affected.get(0)
                .and_then(|a| a.ranges.get(0))
                .and_then(|r| r.fixed.clone());
            
            vulns.push(Vulnerability {
                id: v.id,
                title: v.summary,
                severity,
                description: v.details,
                package_name: pkg.name.clone(),
                package_version: pkg.version.clone(),
                fixed_version: fixed,
            });
        }
    }
    
    Ok(vulns)
}

fn print_report(vulns: &[Vulnerability], min_severity: Option<&str>) {
    let filtered: Vec<&Vulnerability> = vulns.iter()
        .filter(|v| {
            match min_severity {
                Some("Critical") => v.severity == "Critical",
                Some("High") => v.severity == "Critical" || v.severity == "High",
                Some("Medium") => v.severity != "Low" && v.severity != "Unknown",
                _ => true,
            }
        })
        .collect();
    
    println!("\n{}", "=======================================".cyan());
    println!(" Scan Summary\n");
    println!(" Total Vulnerabilities: {}", filtered.len().to_string().red());
    println!("=======================================\n");
    
    if filtered.is_empty() {
        println!("{}", "[PASS] No vulnerabilities found!".green().bold());
        return;
    }
    
    println!("{:<12} {:<20} {:<15} {:<40}", 
        "Severity".bold(),
        "Package".bold(),
        "Version".bold(),
        "Vulnerability ID".bold()
    );
    println!("{}", "-".repeat(90).dimmed());
    
    for vuln in &filtered {
        let sev_color = match vuln.severity.as_str() {
            "Critical" => vuln.severity.red().bold(),
            "High" => vuln.severity.yellow(),
            "Medium" => vuln.severity.cyan(),
            _ => vuln.severity.normal(),
        };
        
        println!("{:<12} {:<20} {:<15} {:<40}",
            sev_color,
            vuln.package_name.cyan(),
            vuln.package_version,
            vuln.id.underline()
        );
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    println!("{}", "[SCAN] GuardDep Security Scanner".cyan().bold());
    println!("Scanning: {}\n", cli.path.display().to_string().yellow());
    
    let packages = find_and_parse(&cli.path)?;
    
    if packages.is_empty() {
        return Ok(());
    }
    
    println!("\n[NET] Querying vulnerability database (OSV)...\n");
    
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    
    let mut all_vulns = Vec::new();
    
    for (i, pkg) in packages.iter().enumerate() {
        print!("  Check {}/{}: {}@{}...", 
            i + 1, 
            packages.len(),
            pkg.name.cyan(),
            pkg.version
        );
        
        match query_osv(&client, pkg) {
            Ok(vulns) => {
                if vulns.is_empty() {
                    println!(" {}", "[OK]".green());
                } else {
                    println!(" {} found", format!("{} vulns", vulns.len()).red());
                    all_vulns.extend(vulns);
                }
            }
            Err(e) => {
                println!(" {} ({})", "[FAIL]".red(), e);
            }
        }
        
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    
    print_report(&all_vulns, cli.severity.as_deref());
    
    let critical_count = all_vulns.iter()
        .filter(|v| v.severity == "Critical")
        .count();
        
    if critical_count > 0 {
        eprintln!("\n[WARN] Found {} critical vulnerabilities!", critical_count);
        std::process::exit(1);
    }
    
    Ok(())
}
