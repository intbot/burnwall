//! `burnwall install-service` / `uninstall-service` — register burnwall as a
//! login-time service so the proxy auto-starts on every login. Cross-platform.
//!
//! ## Platforms
//!
//! - **macOS** — launchd LaunchAgent at
//!   `~/Library/LaunchAgents/io.github.intbot.burnwall.plist`. `KeepAlive`
//!   restarts the daemon if it exits; `ThrottleInterval=60` caps the restart
//!   rate so a crash-looping binary can't burn CPU.
//! - **Linux** — systemd user unit at
//!   `~/.config/systemd/user/burnwall.service`. `Restart=on-failure` with
//!   `StartLimitBurst=5` + `StartLimitIntervalSec=60` is the same crash-loop
//!   circuit breaker shape.
//! - **Windows** — a per-user Scheduled Task triggered at logon, registered
//!   via `schtasks.exe`. Task Scheduler restarts on failure (5 attempts at
//!   1-min intervals) — same shape, different incantation.
//!
//! ## No admin required
//!
//! All three install user-scoped services that need no admin / sudo / UAC.
//! Per-user is the right scope because the proxy serves one user's traffic
//! through env vars in their shell.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;

#[cfg(target_os = "macos")]
const SERVICE_ID: &str = "io.github.intbot.burnwall";
#[cfg(target_os = "windows")]
const TASK_NAME: &str = "BurnwallProxy";

#[derive(Args, Debug)]
pub struct InstallServiceArgs {
    /// Skip the start step (just register the service, don't launch it).
    #[arg(long)]
    pub no_start: bool,
}

#[derive(Args, Debug)]
pub struct UninstallServiceArgs {}

pub fn install_cmd(args: InstallServiceArgs) -> Result<()> {
    let exe = std::env::current_exe().context("locating burnwall executable")?;
    install(&exe, !args.no_start)
}

pub fn uninstall_cmd(_args: UninstallServiceArgs) -> Result<()> {
    uninstall()
}

// ─────────────────────────── macOS ───────────────────────────

#[cfg(target_os = "macos")]
fn plist_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("locating $HOME")?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{SERVICE_ID}.plist")))
}

#[cfg(target_os = "macos")]
fn plist_contents(exe: &std::path::Path) -> String {
    let exe = exe.display();
    let home = dirs::home_dir()
        .map(|h| h.display().to_string())
        .unwrap_or_else(|| "/tmp".to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{SERVICE_ID}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/>
    </dict>
    <key>ThrottleInterval</key><integer>60</integer>
    <key>StandardOutPath</key><string>{home}/Library/Logs/burnwall.log</string>
    <key>StandardErrorPath</key><string>{home}/Library/Logs/burnwall.log</string>
</dict>
</plist>
"#
    )
}

#[cfg(target_os = "macos")]
fn install(exe: &std::path::Path, start: bool) -> Result<()> {
    let path = plist_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&path, plist_contents(exe))
        .with_context(|| format!("writing {}", path.display()))?;
    println!("🛡  Installed LaunchAgent: {}", path.display());
    if start {
        let status = std::process::Command::new("launchctl")
            .args(["load", "-w", path.to_str().unwrap_or("")])
            .status()
            .context("running launchctl load")?;
        if !status.success() {
            anyhow::bail!("launchctl load failed (status {})", status);
        }
        println!("   Loaded and started.");
    } else {
        println!("   (not started — run `launchctl load -w {}`)", path.display());
    }
    println!("   Logs:  ~/Library/Logs/burnwall.log");
    println!("   Crash-loop bound: restart no more than once per 60s.");
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall() -> Result<()> {
    let path = plist_path()?;
    if path.exists() {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", "-w", path.to_str().unwrap_or("")])
            .status();
        std::fs::remove_file(&path)
            .with_context(|| format!("removing {}", path.display()))?;
        println!("🛡  Removed LaunchAgent: {}", path.display());
    } else {
        println!("🛡  No LaunchAgent installed.");
    }
    Ok(())
}

// ─────────────────────────── Linux ───────────────────────────

#[cfg(target_os = "linux")]
fn unit_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("locating $HOME")?;
    Ok(home
        .join(".config")
        .join("systemd")
        .join("user")
        .join("burnwall.service"))
}

#[cfg(target_os = "linux")]
fn unit_contents(exe: &std::path::Path) -> String {
    let exe = exe.display();
    format!(
        r#"[Unit]
Description=Burnwall AI firewall + cost-tracking proxy
After=network.target

[Service]
Type=simple
ExecStart={exe} start
Restart=on-failure
RestartSec=5
StartLimitBurst=5
StartLimitIntervalSec=60

[Install]
WantedBy=default.target
"#
    )
}

#[cfg(target_os = "linux")]
fn install(exe: &std::path::Path, start: bool) -> Result<()> {
    let path = unit_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&path, unit_contents(exe))
        .with_context(|| format!("writing {}", path.display()))?;
    println!("🛡  Installed systemd user unit: {}", path.display());
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    let status = std::process::Command::new("systemctl")
        .args(["--user", "enable", "burnwall.service"])
        .status()
        .context("systemctl --user enable")?;
    if !status.success() {
        anyhow::bail!("systemctl enable failed (status {})", status);
    }
    if start {
        let s = std::process::Command::new("systemctl")
            .args(["--user", "start", "burnwall.service"])
            .status()
            .context("systemctl --user start")?;
        if !s.success() {
            anyhow::bail!("systemctl start failed (status {})", s);
        }
        println!("   Enabled and started.");
    } else {
        println!("   Enabled. Start now: systemctl --user start burnwall");
    }
    println!("   Logs:  journalctl --user -u burnwall -f");
    println!("   Crash-loop bound: 5 restarts per 60s, then give up.");
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall() -> Result<()> {
    let path = unit_path()?;
    if path.exists() {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "stop", "burnwall.service"])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "burnwall.service"])
            .status();
        std::fs::remove_file(&path)
            .with_context(|| format!("removing {}", path.display()))?;
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        println!("🛡  Removed systemd unit: {}", path.display());
    } else {
        println!("🛡  No systemd unit installed.");
    }
    Ok(())
}

// ─────────────────────────── Windows ───────────────────────────

#[cfg(target_os = "windows")]
fn task_xml_path() -> Result<PathBuf> {
    let appdata = std::env::var_os("APPDATA")
        .ok_or_else(|| anyhow::anyhow!("APPDATA not set"))?;
    Ok(PathBuf::from(appdata).join("burnwall").join("task.xml"))
}

#[cfg(target_os = "windows")]
fn task_xml(exe: &std::path::Path) -> String {
    let exe = exe.display();
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Burnwall AI firewall + cost-tracking proxy</Description>
    <URI>\{TASK_NAME}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>5</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
      <Arguments>start</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    )
}

#[cfg(target_os = "windows")]
fn install(exe: &std::path::Path, start: bool) -> Result<()> {
    let xml_path = task_xml_path()?;
    if let Some(parent) = xml_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    // Task Scheduler XML import expects UTF-16 LE with BOM.
    let xml = task_xml(exe);
    let utf16: Vec<u16> = std::iter::once(0xFEFFu16)
        .chain(xml.encode_utf16())
        .collect();
    let mut bytes: Vec<u8> = Vec::with_capacity(utf16.len() * 2);
    for w in utf16 {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    std::fs::write(&xml_path, &bytes)
        .with_context(|| format!("writing {}", xml_path.display()))?;

    let status = std::process::Command::new("schtasks.exe")
        .args([
            "/Create",
            "/F",
            "/TN",
            TASK_NAME,
            "/XML",
            xml_path.to_str().unwrap_or(""),
        ])
        .status()
        .context("running schtasks /Create")?;
    if !status.success() {
        anyhow::bail!("schtasks /Create failed (status {})", status);
    }
    println!("🛡  Installed Scheduled Task: \\{TASK_NAME}");
    if start {
        let s = std::process::Command::new("schtasks.exe")
            .args(["/Run", "/TN", TASK_NAME])
            .status()
            .context("running schtasks /Run")?;
        if !s.success() {
            eprintln!("   (Could not start now — will start on next logon)");
        } else {
            println!("   Started.");
        }
    } else {
        println!("   (not started — will start on next logon)");
    }
    println!("   Crash-loop bound: 5 restarts at 1-min intervals.");
    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall() -> Result<()> {
    let status = std::process::Command::new("schtasks.exe")
        .args(["/Delete", "/F", "/TN", TASK_NAME])
        .status()
        .context("running schtasks /Delete")?;
    if status.success() {
        println!("🛡  Removed Scheduled Task: \\{TASK_NAME}");
    } else {
        println!("🛡  No Scheduled Task to remove (or removal failed).");
    }
    // Best-effort cleanup of the staged XML.
    if let Ok(xml_path) = task_xml_path() {
        let _ = std::fs::remove_file(&xml_path);
    }
    Ok(())
}

// ─────────────────────────── unsupported ───────────────────────────

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn install(_exe: &std::path::Path, _start: bool) -> Result<()> {
    anyhow::bail!("install-service is not supported on this OS");
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn uninstall() -> Result<()> {
    anyhow::bail!("uninstall-service is not supported on this OS");
}
