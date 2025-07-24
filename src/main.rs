mod cli;
mod scanner;
mod output;
mod utils;
mod network;
mod adaptive;
mod config;
mod plugins;

use anyhow::Result;
use clap::Parser;
use colored::*;
use std::io::{self, Write};
use tracing_subscriber;

use crate::cli::Cli;
use crate::scanner::Scanner;
use crate::output::OutputWriter;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    tracing_subscriber::fmt::init();
    
    // No legal BS, just pure scanning action! 🔥
    
    let mut scanner = Scanner::new(
        cli.rate_limit,
        cli.timeout,
        cli.parallel_hosts,
    );
    
    let output_writer = OutputWriter::new(cli.output_format, cli.output_file)?;
    
    let target_spec = cli.target.join(",");
    let ports_spec = cli.ports.join(",");
    let results = scanner.scan(
        &target_spec,
        &ports_spec,
        cli.scan_type,
    ).await?;
    
    output_writer.write(results)?;
    
    Ok(())
}

fn print_disclaimer() -> Result<()> {
    println!("\n{}", 
        "╔═══════════════════════════════════════════════════════════════════════════════╗".truecolor(255, 0, 81));
    println!("{}", 
        "║                              ⚠ LEGAL WARNING ⚠                              ║".truecolor(255, 0, 81).bold());
    println!("{}", 
        "╠═══════════════════════════════════════════════════════════════════════════════╣".truecolor(255, 0, 81));
    println!("{}", 
        "║  This cybernetic intrusion tool is for AUTHORIZED penetration testing only   ║".truecolor(255, 140, 0));
    println!("{}", 
        "║                                                                               ║".truecolor(255, 0, 81));
    println!("{}", 
        "║  Unauthorized network reconnaissance may violate:                             ║".truecolor(255, 140, 0));
    println!("{}", 
        "║  ◦ Computer Fraud and Abuse Act (CFAA)                                       ║".truecolor(255, 255, 255));
    println!("{}", 
        "║  ◦ International cybersecurity regulations                                   ║".truecolor(255, 255, 255));
    println!("{}", 
        "║  ◦ Corporate security policies and ToS                                       ║".truecolor(255, 255, 255));
    println!("{}", 
        "║                                                                               ║".truecolor(255, 0, 81));
    println!("{}", 
        "║  ONLY initiate scans against systems under your direct control or with       ║".truecolor(255, 0, 81).bold());
    println!("{}", 
        "║  explicit written authorization from the target organization.                ║".truecolor(255, 0, 81).bold());
    println!("{}", 
        "╠═══════════════════════════════════════════════════════════════════════════════╣".truecolor(255, 0, 81));
    println!("{}", 
        "║                        ⟨INITIATE SECURITY PROTOCOL⟩                          ║".truecolor(0, 212, 255).bold());
    println!("{}", 
        "╚═══════════════════════════════════════════════════════════════════════════════╝".truecolor(255, 0, 81));
    
    print!("{} {} ", 
        "⟦AUTHORIZATION⟧".truecolor(191, 64, 191).bold(),
        "Acknowledge legal responsibility? [y/N]:".truecolor(255, 255, 255));
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    if !input.trim().eq_ignore_ascii_case("y") {
        println!("{}", 
            "⟦ABORTED⟧ Scan operation terminated by user".truecolor(255, 0, 81).bold());
        std::process::exit(0);
    }
    
    println!("{}", 
        "⟦AUTHORIZED⟧ Initiating network reconnaissance...".truecolor(0, 255, 65).bold());
    println!();
    Ok(())
}
