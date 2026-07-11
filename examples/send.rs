//! Phase 0 test harness: send a file, printing machine-readable lines.
//! Usage: send <file> [code]

use std::io::Write;

fn out(line: String) {
    let mut stdout = std::io::stdout();
    writeln!(stdout, "{line}").unwrap();
    stdout.flush().unwrap();
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: send <file> [code]");
    let code = args.next();

    async_io::block_on(async move {
        let mut last_pct = 0u64;
        wormhole_core::send_file(
            &path,
            code.as_deref(),
            |code| out(format!("CODE:{code}")),
            |transit| out(format!("TRANSIT:{transit}")),
            move |sent, total| {
                let pct = if total == 0 { 100 } else { sent * 100 / total };
                if pct == 100 || pct >= last_pct + 25 {
                    last_pct = pct;
                    out(format!("PROGRESS:{pct}"));
                }
            },
            std::future::pending::<()>(),
        )
        .await
    })?;
    out("SEND-OK".to_string());
    Ok(())
}
