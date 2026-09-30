# Contributing

## Branches

| Branch              | Purpose                                                        |
|---------------------|----------------------------------------------------------------|
| `main`              | Protected. Only integrated, working code. Merges from `staging` only. |
| `staging`           | Integration branch. Every module branch merges here first.     |
| `feature/<module>`  | One per module (e.g. `feature/capture`, `feature/rules`).      |

## Workflow

1. Branch off `staging`:
   ```
   git checkout staging && git pull
   git checkout -b feature/<module-name>
   ```
2. Keep your work inside your module's package. Changes to the shared
   `internal/packet` type should be agreed on first, since every module
   depends on it.
3. Before opening a PR, make sure `make build`, `make test` and `make lint` pass.
4. Open a PR from `feature/<module-name>` into **`staging`** (never into `main`).
5. `staging` -> `main` is merged only after integration testing passes
   (the end-to-end pipeline tests added in the integration step).
