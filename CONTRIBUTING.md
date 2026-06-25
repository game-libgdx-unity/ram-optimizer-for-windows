# Contributing to RAM Optimizer

Thanks for being here! RAM Optimizer is a small, focused tool and it gets better with community input. **Ideas, issues, and pull requests are all genuinely welcome** — you don't need to write code to help.

Repo: <https://github.com/game-libgdx-unity/ram-optimizer-for-windows>

## Three ways to contribute

### 💡 Ideas & discussion
Have a thought on detection heuristics, a new platform integration, or a UX improvement? Open an **issue** with the `idea` / `enhancement` label and describe the problem you're trying to solve. Early, rough ideas are fine — that's the point. If Discussions are enabled, that's a great home for open-ended questions too.

### 🐛 Issues
Found a bug or a false positive (e.g. a process flagged that shouldn't be)? Please open an issue with:
- your **OS + version** and how you installed RAM Optimizer,
- what you expected vs. what happened,
- relevant lines from `~/.ram-optimizer/ram-optimizer.log` and, if useful, the offending run from `~/.ram-optimizer/runs.jsonl` (scrub anything private),
- `ram-optimizer --dump` output if it's about detection.

### 🔀 Pull requests
PRs are welcome. For anything beyond a small fix, **open an issue first** so we can agree on the approach before you invest time.

## Development setup

```sh
git clone https://github.com/game-libgdx-unity/ram-optimizer-for-windows
cd ram-optimizer-for-windows
cp config.example.json config.json
cargo build
cargo run -- --print        # one monitoring pass
cargo run -- ui             # the dashboard
```

Linux also needs the GUI dev headers (see the README's Prerequisites).

## Before you push

CI runs the same four checks on Windows, macOS, and Linux. Run them locally first:

```sh
cargo fmt --all
cargo clippy --all-targets
cargo build --release
cargo test
```

- **Keep it format-clean** (`cargo fmt`) and **clippy-clean**.
- **Add a test** when you touch detection/rules logic (see `src/rules.rs` and `src/vectordb.rs` for the pattern).
- **Match the surrounding style** — small modules, doc-comments at the top explaining *why*, no needless dependencies (this is a RAM tool; weight matters).

### Optional: auto-check formatting on commit

The repo ships a pre-commit hook (`.githooks/pre-commit`) that runs
`cargo fmt --all -- --check` — the same gate CI uses — so unformatted code never
reaches a push. Enable it once per clone:

```sh
git config core.hooksPath .githooks
```

If it blocks a commit, run `cargo fmt --all`, re-stage, and commit again
(or `git commit --no-verify` to bypass once).

## Project layout

| File | Responsibility |
|---|---|
| `src/collect.rs` | Cross-platform process/RAM snapshot (`sysinfo`). |
| `src/detect.rs` | Generic anomaly detection (RAM/CPU/duplicates/orphans/leaks/antimalware). |
| `src/rules.rs` | User-rule matching (shared by detection and the optimizer). |
| `src/optimize.rs` | Runs pre-authorized `kill`/`restart` rules. |
| `src/actions.rs` | Confirm-to-act proposal queue (approve/dismiss/execute). |
| `src/ai.rs` | AI escalation + prompt building (claude/OpenAI/Groq). |
| `src/vectordb.rs` | Upstash Vector memory (RAG) + built-in default. |
| `src/pass.rs` | One monitoring pass, shared by the CLI and the dashboard. |
| `src/runlog.rs` | Per-run records + metrics aggregation. |
| `src/scheduler.rs` | Start/stop/retime the OS schedule (Task Scheduler / launchd / cron). |
| `src/ui.rs` | The native egui dashboard. |
| `src/tray.rs` | System-tray icon (Windows/macOS). |

## Design principles

1. **The viewer must stay cheap.** The dashboard reads logs; it must not run continuous monitoring.
2. **Never act without authority.** Only user-written rules act automatically. Heuristic/AI kills are always proposals the user confirms.
3. **Generic over special-casing.** Detectors work on any process; don't hard-code app names into logic (the ignore-list is the user's lever).
4. **No daemon.** The optimizer is a one-shot the OS scheduler runs.

## Code of conduct

Be kind and constructive. Assume good faith. We're all here to make a useful little tool.

By contributing, you agree your contributions are licensed under the project's [MIT License](LICENSE).
