## Summary

Implements four Advancement issues in one PR, plus repairs merge fallout that left `src/main.rs` with duplicate clap variants and a `qpub` typo in `src/utils/mod.rs`.

- **#932 — Watch-only wallets:** `starforge wallet watch` stores public-key-only wallets; list/JSON mark `watch_only: true`; signing is rejected with a clear error; usable as aliases/multisig addresses.
- **#903 — MSRV policy & dependency pins:** Documents N−3 / minor-only MSRV bumps; replaces exact pins on clap/toml/colored/dirs/clap_complete with caret ranges (remaining `=` pins justified); adds scheduled `latest-deps` workflow.
- **#905 — Native Soroban deploy:** `deploy run --execute` uploads WASM + creates the contract via RPC (simulate → assemble → sign → submit → poll); idempotent skip when WASM hash exists; `--print-only` keeps the stellar CLI command path; constructor args supported.
- **#909 — SAC commands:** `starforge asset contract-id` / `asset wrap` for classic assets and native XLM; contract ids match `stellar contract id asset` fixtures; SEP-41 template docs show SAC usage.

closes #932
closes #903
closes #905
closes #909

## Test plan

- [ ] `cargo test --test watch_only_wallet`
- [ ] `cargo test --test sac_contract_id` (vectors vs `stellar contract id asset`)
- [ ] `cargo test -p starforge soroban_native`
- [ ] `starforge wallet watch treasury --address G… && starforge wallet list --json` shows `"watch_only": true`
- [ ] Signing a watch-only wallet fails with a watch-only message
- [ ] `starforge asset contract-id XLM --network testnet` → `CDLZFC3S…`
- [ ] Local quickstart: `starforge deploy run --wasm … --wallet … --execute` returns a contract id (text + `--json`)
- [ ] Re-run deploy with the same WASM reports WASM already uploaded
- [ ] `starforge deploy run … --print-only` still prints a stellar CLI command
- [ ] MSRV job still green on Rust 1.80; `latest-deps` workflow present
