//! Phase 0 test harness: receive a file, printing machine-readable lines.
//! Usage: recv <code> [dest_dir]

use std::io::Write;

fn out(line: String) {
    let mut stdout = std::io::stdout();
    writeln!(stdout, "{line}").unwrap();
    stdout.flush().unwrap();
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let code = args.next().expect("usage: recv <code> [dest_dir]");
    let dest = args.next().unwrap_or_else(|| ".".to_string());

    let path = async_io::block_on(async move {
        let mut last_pct = 0u64;
        wormhole_core::receive_file(
            &code,
            &dest,
            |transit| out(format!("TRANSIT:{transit}")),
            move |received, total| {
                let pct = if total == 0 { 100 } else { received * 100 / total };
                if pct == 100 || pct >= last_pct + 25 {
                    last_pct = pct;
                    out(format!("PROGRESS:{pct}"));
                }
            },
        )
        .await
    })?;
    out(format!("RECV-OK:{}", path.display()));
    Ok(())
}
