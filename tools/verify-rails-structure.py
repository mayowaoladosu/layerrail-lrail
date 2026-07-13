#!/usr/bin/env python3
"""Restore the Rails SQL schema into a disposable database and verify security objects."""

from __future__ import annotations

import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
STRUCTURE = ROOT / "apps" / "control-plane" / "db" / "structure.sql"
MIGRATIONS = ROOT / "apps" / "control-plane" / "db" / "migrate"
DATABASE = "lrail_structure_verify"
ADMIN = "lrail_local"


def execute(command: list[str], *, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode:
        raise SystemExit(result.stderr or result.stdout)
    return result


def psql(container: str, database: str, sql: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return execute(
        [
            "docker",
            "exec",
            "-i",
            container,
            "psql",
            "--username",
            ADMIN,
            "--dbname",
            database,
            "--set",
            "ON_ERROR_STOP=1",
            "--tuples-only",
            "--no-align",
        ],
        input_text=sql,
        check=check,
    )


def main() -> None:
    container = execute(["docker", "compose", "ps", "-q", "postgres"]).stdout.strip()
    if not container:
        raise SystemExit("Compose PostgreSQL is not running")

    psql(container, "postgres", f'DROP DATABASE IF EXISTS "{DATABASE}" WITH (FORCE);\nCREATE DATABASE "{DATABASE}";')
    try:
        psql(container, DATABASE, STRUCTURE.read_text(encoding="utf-8"))
        counts = psql(
            container,
            DATABASE,
            """
            SELECT
              (SELECT count(*) FROM pg_proc WHERE proname LIKE 'lrail_%'),
              (SELECT count(*) FROM pg_policies WHERE policyname LIKE '%_tenant_policy'),
              (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal),
              (SELECT count(*) FROM schema_migrations);
            """,
        ).stdout.strip()
        function_count, policy_count, trigger_count, migration_count = map(int, counts.split("|"))
        expected_migrations = len(list(MIGRATIONS.glob("*.rb")))
        if function_count < 7 or policy_count < 30 or trigger_count < 4 or migration_count != expected_migrations:
            raise SystemExit(f"unexpected restored object counts: {counts}")

        worker_function = psql(
            container,
            DATABASE,
            "SET ROLE lrail_worker; SELECT count(*) FROM lrail_claim_outbox('restore-check', 1); RESET ROLE;",
        )
        numeric_output = [line.strip() for line in worker_function.stdout.splitlines() if line.strip().isdigit()]
        if not numeric_output or numeric_output[-1] != "0":
            raise SystemExit("restored worker function returned unexpected rows")

        direct_worker_read = psql(
            container,
            DATABASE,
            "SET ROLE lrail_worker; SELECT count(*) FROM outbox_events;",
            check=False,
        )
        if direct_worker_read.returncode == 0 or "permission denied" not in direct_worker_read.stderr:
            raise SystemExit("restored worker role unexpectedly read the outbox table")

        web_metadata_read = psql(
            container,
            DATABASE,
            "SET ROLE lrail_web; SELECT count(*) FROM schema_migrations;",
            check=False,
        )
        if web_metadata_read.returncode == 0 or "permission denied" not in web_metadata_read.stderr:
            raise SystemExit("restored web role unexpectedly read migration metadata")

        source_expiry_grants = psql(
            container,
            DATABASE,
            """
            SELECT
              has_function_privilege('lrail_worker', 'lrail_expire_source_upload_sessions(integer)', 'EXECUTE'),
              has_function_privilege('lrail_web', 'lrail_expire_source_upload_sessions(integer)', 'EXECUTE');
            """,
        ).stdout.strip()
        if source_expiry_grants != "t|f":
            raise SystemExit(f"unexpected restored source expiry grants: {source_expiry_grants}")

        api_key_grants = psql(
            container,
            DATABASE,
            """
            SELECT
              has_function_privilege('lrail_web', 'lrail_find_api_key(text)', 'EXECUTE'),
              has_function_privilege('lrail_worker', 'lrail_find_api_key(text)', 'EXECUTE');
            """,
        ).stdout.strip()
        if api_key_grants != "t|f":
            raise SystemExit(f"unexpected restored API key grants: {api_key_grants}")

        provider_grants = psql(
            container,
            DATABASE,
            """
            SELECT
              has_function_privilege('lrail_web', 'lrail_apply_github_provider_delivery(text,text,text,text,text,text,text,text,text,integer,boolean,boolean,text,text,text,bigint,text,text,jsonb,text,text,text,text)', 'EXECUTE'),
              has_function_privilege('lrail_worker', 'lrail_apply_github_provider_delivery(text,text,text,text,text,text,text,text,text,integer,boolean,boolean,text,text,text,bigint,text,text,jsonb,text,text,text,text)', 'EXECUTE'),
              has_function_privilege('lrail_web', 'lrail_claim_github_provider_delivery(text,text)', 'EXECUTE'),
              has_function_privilege('lrail_worker', 'lrail_claim_github_provider_delivery(text,text)', 'EXECUTE'),
              has_function_privilege('lrail_web', 'lrail_finish_github_provider_delivery(text,text,boolean,text)', 'EXECUTE'),
              has_function_privilege('lrail_worker', 'lrail_finish_github_provider_delivery(text,text,boolean,text)', 'EXECUTE'),
              has_table_privilege('lrail_web', 'source_provider_deliveries', 'SELECT'),
              has_table_privilege('lrail_web', 'source_provider_deliveries', 'INSERT,UPDATE,DELETE'),
              has_sequence_privilege('lrail_web', 'source_provider_deliveries_id_seq', 'USAGE');
            """,
        ).stdout.strip()
        if provider_grants != "t|f|t|f|t|f|t|f|f":
            raise SystemExit(f"unexpected restored provider grants: {provider_grants}")

        provider_rls = psql(
            container,
            DATABASE,
            """
            SELECT string_agg(relname || ':' || relrowsecurity || ':' || relforcerowsecurity, ',' ORDER BY relname)
            FROM pg_class
            WHERE relname IN ('source_provider_deliveries', 'source_fetches', 'project_source_bindings');
            """,
        ).stdout.strip()
        expected_provider_rls = (
            "project_source_bindings:true:true,"
            "source_fetches:true:true,"
            "source_provider_deliveries:true:true"
        )
        if provider_rls != expected_provider_rls:
            raise SystemExit(f"unexpected restored provider RLS: {provider_rls}")

        print(
            "Verified SQL restore: "
            f"{function_count} functions, {policy_count} tenant policies, "
            f"{trigger_count} triggers, {migration_count} migrations"
        )
    finally:
        psql(container, "postgres", f'DROP DATABASE IF EXISTS "{DATABASE}" WITH (FORCE);')


if __name__ == "__main__":
    main()
