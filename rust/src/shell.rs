// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
pub const TIMEOUT_CODE: i32 = 124;
const NOT_FOUND_CODE: i32 = 127;

#[derive(Debug, Clone)]
pub struct Output {
    pub argv: Vec<String>,
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.code == 0
    }

    /// stdout and stderr together, for a message to a caller.
    pub fn text(&self) -> String {
        let mut joined = self.stdout.clone();
        joined.push_str(&self.stderr);
        joined.trim().to_string()
    }

    pub fn command(&self) -> String {
        self.argv.join(" ")
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{} -> rc={}: {}", .0.command(), .0.code, .0.text())]
pub struct CommandError(pub Output);

/// Run a command to completion, capturing both streams.
///
/// A missing binary and a timeout are reported as exit codes rather than
/// errors, so one match arm handles every failure the caller cares about.
pub async fn command_run(argv: &[String], timeout: Duration, stdin: Option<&str>) -> Output {
    let (program, rest) = match argv.split_first() {
        Some(parts) => parts,
        None => {
            return Output {
                argv: Vec::new(),
                code: NOT_FOUND_CODE,
                stdout: String::new(),
                stderr: "empty command".into(),
            }
        }
    };

    tracing::debug!(command = %argv.join(" "), "run");
    let mut command = Command::new(program);
    command
        .args(rest)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            return Output {
                argv: argv.to_vec(),
                code: NOT_FOUND_CODE,
                stdout: String::new(),
                stderr: err.to_string(),
            }
        }
    };

    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let _ = pipe.write_all(text.as_bytes()).await;
        let _ = pipe.shutdown().await;
    }

    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(out)) => Output {
            argv: argv.to_vec(),
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        },
        Ok(Err(err)) => Output {
            argv: argv.to_vec(),
            code: -1,
            stdout: String::new(),
            stderr: err.to_string(),
        },
        Err(_) => Output {
            argv: argv.to_vec(),
            code: TIMEOUT_CODE,
            stdout: String::new(),
            stderr: format!("timed out after {timeout:?}"),
        },
    }
}

/// Run and fail on a non-zero exit, for the many calls where any failure is fatal.
pub async fn command_check(argv: &[String], timeout: Duration) -> Result<Output, CommandError> {
    let out = command_run(argv, timeout, None).await;
    if out.ok() {
        Ok(out)
    } else {
        Err(CommandError(out))
    }
}

/// Build an argv from string-ish parts, which keeps call sites readable.
#[macro_export]
macro_rules! argv {
    ($($part:expr),* $(,)?) => {
        vec![$(::std::string::ToString::to_string(&$part)),*]
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn captures_stdout_and_exit_code() {
        let out = command_run(&argv!["/bin/sh", "-c", "echo hi; exit 3"], DEFAULT_TIMEOUT, None).await;
        assert_eq!(out.code, 3);
        assert_eq!(out.stdout.trim(), "hi");
        assert!(!out.ok());
    }

    #[tokio::test]
    async fn missing_binary_is_rc_127_not_a_panic() {
        let out = command_run(&argv!["/nonexistent/binary"], DEFAULT_TIMEOUT, None).await;
        assert_eq!(out.code, NOT_FOUND_CODE);
    }

    #[tokio::test]
    async fn timeout_is_rc_124() {
        let out = command_run(
            &argv!["/bin/sh", "-c", "sleep 5"],
            Duration::from_millis(150),
            None,
        )
        .await;
        assert_eq!(out.code, TIMEOUT_CODE);
        assert!(out.stderr.contains("timed out"));
    }

    #[tokio::test]
    async fn stdin_is_delivered() {
        let out = command_run(&argv!["/bin/cat"], DEFAULT_TIMEOUT, Some("payload")).await;
        assert_eq!(out.stdout, "payload");
    }

    #[tokio::test]
    async fn check_surfaces_the_command_and_output() {
        let err = command_check(&argv!["/bin/sh", "-c", "echo boom >&2; exit 1"], DEFAULT_TIMEOUT)
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("rc=1"), "{message}");
        assert!(message.contains("boom"), "{message}");
    }
}
