use colored::Colorize;
use anyhow::{Result, Context};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
}

#[derive(Deserialize)]
struct PackageJson {
    dependencies: Option<HashMap<String, String>>,
}

pub fn find_and_parse(path: &Path) -> Result<Vec<Package>> {
    let mut packages = Vec::new();
    
    
    let package_json = path.join("package.json");
    if package_json.exists() {
        println!("Found package.json");
        let content = fs::read_to_string(&package_json)
            .with_context(|| format!("Failed to read {:?}", package_json))?;
        let mut pkgs = parse_package_json(&content)?;
        packages.append(&mut pkgs);
    }
    
   
    let cargo_toml = path.join("Cargo.toml");
    if cargo_toml.exists() {
        println!("Found Cargo.toml");
        println!("   {} (Cargo support coming soon)", "Note:".yellow());
    }
    
    if packages.is_empty() {
        println!("{}", "No supported manifest files found".yellow());
        println!("   Looking for: package.json");
    }
    
    Ok(packages)
}

fn parse_package_json(content: &str) -> Result<Vec<Package>> {
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
    
    println!("Parsed {} dependencies", packages.len().to_string().green());
    Ok(packages)
}
