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
    
    // Check if target is provided
    if cli.target.is_empty() {
        eprintln!("{}", "Error: No target specified. Use -t to specify a target.".red());
        eprintln!("Example: mlscan -t 192.168.1.1");
        eprintln!("Run 'mlscan --help' for more information.");
        std::process::exit(1);
    }
    
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
