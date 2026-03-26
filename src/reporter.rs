use crate::scanner::Vulnerability;
use colored::*;

pub fn print_report(vulns: &[Vulnerability], min_severity: Option<&str>) {
    println!("\n{}\n", "═".repeat(50).cyan());
    
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
    
    if filtered.is_empty() {
        if vulns.is_empty() {
            println!("{}", "No vulnerabilities found!".green().bold());
        } else {
            println!("{}", "No vulnerabilities match the severity filter.".green());
        }
        return;
    }
    
    
    let critical = filtered.iter().filter(|v| v.severity == "Critical").count();
    let high = filtered.iter().filter(|v| v.severity == "High").count();
    let medium = filtered.iter().filter(|v| v.severity == "Medium").count();
    
    println!("{} Found {} vulnerabilities\n", 
        "!".red(),
        filtered.len().to_string().red().bold()
    );
    
    println!("Summary: {} Critical, {} High, {} Medium\n", 
        critical.to_string().red(),
        high.to_string().yellow(),
        medium.to_string().cyan()
    );
    
    
    println!("{:<12} {:<20} {:<15} {:<30}", 
        "Severity".bold(),
        "Package".bold(),
        "Version".bold(),
        "Vulnerability ID".bold()
    );
    println!("{}", "─".repeat(80).dimmed());
    
    for vuln in &filtered {
        let sev_color = match vuln.severity.as_str() {
            "Critical" => vuln.severity.red().bold(),
            "High" => vuln.severity.yellow(),
            "Medium" => vuln.severity.cyan(),
            _ => vuln.severity.normal(),
        };
        
        println!("{:<12} {:<20} {:<15} {:<30}",
            sev_color,
            vuln.package_name.cyan(),
            vuln.package_version,
            vuln.id.underline()
        );
        
        println!("  Title: {}", vuln.title);
        if let Some(ref fixed) = vuln.fixed_version {
            println!("  Fixed in: {}", fixed.green());
        }
        println!();
    }
    
    println!("{}", "═".repeat(50).cyan());
    println!("{}", "Tip: Update dependencies to fix vulnerabilities".dimmed());
}
