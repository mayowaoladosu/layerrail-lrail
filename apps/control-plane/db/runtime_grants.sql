SET search_path TO public, pg_temp;

REVOKE ALL ON FUNCTION rodauth_get_salt(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rodauth_valid_password_hash(bigint, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION rodauth_get_previous_salt(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rodauth_previous_password_hash_match(bigint, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION lrail_account_has_membership(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION lrail_claim_outbox(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION lrail_finish_outbox(bigint, text, boolean, text, timestamptz, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION lrail_claim_email(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION lrail_finish_email(bigint, text, text, text, text, text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION lrail_apply_email_provider_event(text, text, text, text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION lrail_expire_source_upload_sessions(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION lrail_find_api_key(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION lrail_apply_github_provider_delivery(text, text, text, text, text, text, text, text, text, integer, boolean, boolean, text, text, text, bigint, text, text, jsonb, text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION lrail_claim_github_provider_delivery(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION lrail_finish_github_provider_delivery(text, text, boolean, text) FROM PUBLIC;

DO $runtime_grants$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lrail_web') THEN
    GRANT USAGE ON SCHEMA public TO lrail_web;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO lrail_web;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO lrail_web;
    GRANT EXECUTE ON FUNCTION lrail_account_has_membership(bigint) TO lrail_web;
    GRANT EXECUTE ON FUNCTION rodauth_get_salt(bigint) TO lrail_web;
    GRANT EXECUTE ON FUNCTION rodauth_valid_password_hash(bigint, text) TO lrail_web;
    GRANT EXECUTE ON FUNCTION rodauth_get_previous_salt(bigint) TO lrail_web;
    GRANT EXECUTE ON FUNCTION rodauth_previous_password_hash_match(bigint, text) TO lrail_web;
    GRANT EXECUTE ON FUNCTION lrail_apply_email_provider_event(text, text, text, text, timestamptz) TO lrail_web;
    GRANT EXECUTE ON FUNCTION lrail_find_api_key(text) TO lrail_web;
    GRANT EXECUTE ON FUNCTION lrail_apply_github_provider_delivery(text, text, text, text, text, text, text, text, text, integer, boolean, boolean, text, text, text, bigint, text, text, jsonb, text, text, text, text) TO lrail_web;
    GRANT EXECUTE ON FUNCTION lrail_claim_github_provider_delivery(text, text) TO lrail_web;
    GRANT EXECUTE ON FUNCTION lrail_finish_github_provider_delivery(text, text, boolean, text) TO lrail_web;

    REVOKE ALL ON schema_migrations, ar_internal_metadata FROM lrail_web;
    REVOKE ALL ON account_password_hashes FROM lrail_web;
    GRANT INSERT, UPDATE, DELETE ON account_password_hashes TO lrail_web;
    GRANT SELECT (id) ON account_password_hashes TO lrail_web;
    REVOKE ALL ON account_previous_password_hashes FROM lrail_web;
    GRANT INSERT, UPDATE, DELETE ON account_previous_password_hashes TO lrail_web;
    GRANT SELECT (id, account_id) ON account_previous_password_hashes TO lrail_web;
    REVOKE ALL ON email_provider_events FROM lrail_web;
    REVOKE ALL ON SEQUENCE email_provider_events_id_seq FROM lrail_web;
    REVOKE ALL ON source_provider_deliveries FROM lrail_web;
    GRANT SELECT ON source_provider_deliveries TO lrail_web;
    REVOKE ALL ON SEQUENCE source_provider_deliveries_id_seq FROM lrail_web;
    REVOKE UPDATE, DELETE ON outbox_events, email_intents FROM lrail_web;
    REVOKE DELETE ON inbox_messages, dead_letter_messages FROM lrail_web;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lrail_worker') THEN
    GRANT USAGE ON SCHEMA public TO lrail_worker;
    GRANT EXECUTE ON FUNCTION lrail_claim_outbox(text, integer) TO lrail_worker;
    GRANT EXECUTE ON FUNCTION lrail_finish_outbox(bigint, text, boolean, text, timestamptz, boolean) TO lrail_worker;
    GRANT EXECUTE ON FUNCTION lrail_claim_email(text, integer) TO lrail_worker;
    GRANT EXECUTE ON FUNCTION lrail_finish_email(bigint, text, text, text, text, text, timestamptz) TO lrail_worker;
    GRANT EXECUTE ON FUNCTION lrail_expire_source_upload_sessions(integer) TO lrail_worker;
  END IF;
END
$runtime_grants$;
