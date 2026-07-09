# Operational Tools — Audit & Reference

Audit baseline for operational adapters (non-scanner tooling). Verified 2026-07-09.

## asset_manager

| Item | Detail |
|------|--------|
| **File** | `src/adapters/asset_manager.py` |
| **Commands** | `add`, `list`, `remove` only |
| **Database** | Shared `DB_PATH` from `src/agent/db.py`; `init_db()` called on connect |
| **Factory** | `create_asset_manager_adapter(config)` |
| **Reports** | **Not supported.** Use `generate_report` tool (`src/agent/tools/report_tool.py`) for assessment reports |

### Parameters

| Command | Required | Optional |
|---------|----------|----------|
| `add` | `name`, `type` (`domain` \| `host` \| `ip`), `value` | — |
| `list` | — | `type` filter |
| `remove` | `name` | — |

### Relationship to findings pipeline

- `asset_manager` manages the `assets` table scope.
- Scanner adapters persist findings via `AdapterToolWrapper` → `FindingsNormalizer` → `DatabaseManager`.
- `public_ip` has no target; wrapper creates/uses session asset `local-agent` (`local`).

## PluginManager adapter config

Per-adapter settings in `config.yaml`:

```yaml
adapters:
  sublist3r:
    threads: 20
  nmap:
    timeout: 300
```

`PluginManager._get_adapter_config(adapter_name)` merges the `adapters.<name>` block before `load_adapter`. For `nmap`, `scan_timeout` is used when no explicit `adapters.nmap.timeout` is set.

## Post-fix status

| Item | Status | Notes |
|------|--------|-------|
| BaseAdapter refactor | Done | `_execute_impl`, `validate_params`, `interpret_result` |
| Shared DB + init_db | Done | Same path as findings pipeline |
| Mock `report` command removed | Done | Agents use `generate_report` tool |
| Smoke harness | Done | `test_all_adapters.py` / `verify_tools_live.py` use `PluginManager.run_adapter` |
| Unit tests | Done | `tests/test_asset_manager_adapter.py` |
