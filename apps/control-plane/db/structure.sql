SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: citext; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;


--
-- Name: EXTENSION citext; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION citext IS 'data type for case-insensitive character strings';


--
-- Name: lrail_account_has_membership(bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lrail_account_has_membership(target_organization_id bigint) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    AS $$
  SELECT EXISTS (
    SELECT 1 FROM memberships
    WHERE organization_id = target_organization_id
      AND account_id::text = current_setting('lrail.account_id', true)
      AND status = 'active'
  );
$$;


--
-- Name: lrail_apply_email_provider_event(text, text, text, text, timestamp with time zone); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lrail_apply_email_provider_event(delivery_id text, delivery_type text, payload_sha256 text, message_id text, event_time timestamp with time zone) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    SET row_security TO 'off'
    AS $$
DECLARE
  receipt_id bigint;
  intent_id bigint;
  result text;
BEGIN
  IF delivery_type NOT IN (
    'email.sent', 'email.delivered', 'email.delivery_delayed',
    'email.bounced', 'email.complained', 'email.failed', 'email.suppressed'
  ) THEN
    RAISE EXCEPTION 'unsupported email provider event' USING ERRCODE = '22023';
  END IF;

  INSERT INTO email_provider_events(
    provider_event_id, event_type, provider_message_id, payload_digest,
    outcome, received_at, created_at, updated_at
  ) VALUES (
    left(delivery_id, 128), delivery_type, left(message_id, 128), payload_sha256,
    'received', COALESCE(event_time, clock_timestamp()), clock_timestamp(), clock_timestamp()
  )
  ON CONFLICT (provider_event_id) DO NOTHING
  RETURNING id INTO receipt_id;

  IF receipt_id IS NULL THEN
    RETURN 'duplicate';
  END IF;

  SELECT id INTO intent_id
  FROM email_intents
  WHERE provider_message_id = message_id
  LIMIT 1;

  IF intent_id IS NULL THEN
    UPDATE email_provider_events
    SET outcome = 'ignored', processed_at = clock_timestamp(), updated_at = clock_timestamp()
    WHERE id = receipt_id;
    RETURN 'ignored';
  END IF;

  result := CASE delivery_type
    WHEN 'email.sent' THEN 'sent'
    WHEN 'email.delivered' THEN 'delivered'
    WHEN 'email.delivery_delayed' THEN 'sent'
    WHEN 'email.bounced' THEN 'bounced'
    WHEN 'email.complained' THEN 'complained'
    ELSE 'failed'
  END;

  UPDATE email_intents
  SET state = result,
      delivered_at = CASE WHEN result = 'delivered' THEN clock_timestamp() ELSE delivered_at END,
      bounced_at = CASE WHEN result = 'bounced' THEN clock_timestamp() ELSE bounced_at END,
      complained_at = CASE WHEN result = 'complained' THEN clock_timestamp() ELSE complained_at END,
      terminal_at = CASE WHEN result IN ('bounced', 'complained', 'failed') THEN clock_timestamp() ELSE terminal_at END,
      updated_at = clock_timestamp()
  WHERE id = intent_id;

  UPDATE email_provider_events
  SET outcome = 'processed', processed_at = clock_timestamp(), updated_at = clock_timestamp()
  WHERE id = receipt_id;

  RETURN 'processed';
END;
$$;


--
-- Name: lrail_apply_github_provider_delivery(text, text, text, text, text, text, text, text, text, integer, boolean, boolean, text, text, text, bigint, text, text, jsonb, text, text, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lrail_apply_github_provider_delivery(installation_id text, delivery_id text, delivery_event text, delivery_action text, payload_sha256 text, repository_name text, git_ref text, head_commit text, base_commit text, pr_number integer, was_forced boolean, was_deleted boolean, processing_state text, next_connection_status text, account_login text, account_id bigint, repository_selection_value text, repositories_mode text, repository_values jsonb, delivery_public_id text, event_public_id text, audit_public_id text, request_id text) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    SET row_security TO 'off'
    AS $_$
DECLARE
  connection_row source_connections%ROWTYPE;
  existing_digest text;
  existing_delivery_public_id text;
  existing_delivery_state text;
  existing_processing_started_at timestamptz;
  next_repositories jsonb;
  organization_public_id_value text;
  actor_public_id_value text;
BEGIN
  IF delivery_event NOT IN ('push', 'pull_request', 'installation', 'installation_repositories')
     OR processing_state NOT IN ('received', 'processed', 'ignored')
      OR installation_id !~ '^[1-9][0-9]{0,19}$'
     OR delivery_id !~ '^[0-9A-Za-z-]{8,128}$'
     OR payload_sha256 !~ '^sha256:[0-9a-f]{64}$'
     OR delivery_public_id !~ '^[a-z]{2,5}_[0-9a-f-]{36}$'
     OR event_public_id !~ '^[a-z]{2,5}_[0-9a-f-]{36}$'
     OR audit_public_id !~ '^[a-z]{2,5}_[0-9a-f-]{36}$'
     OR request_id !~ '^req_[0-9a-f]{32}$'
     OR char_length(delivery_action) > 64
     OR char_length(account_login) > 255
     OR (account_id IS NOT NULL AND account_id < 1)
     OR (head_commit IS NOT NULL AND head_commit !~ '^[0-9a-f]{40}([0-9a-f]{24})?$')
     OR (base_commit IS NOT NULL AND base_commit !~ '^[0-9a-f]{40}([0-9a-f]{24})?$')
     OR (repository_name <> '' AND repository_name !~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}$')
     OR char_length(git_ref) > 512
     OR (pr_number IS NOT NULL AND pr_number < 1)
     OR next_connection_status NOT IN ('', 'active', 'suspended', 'revoked')
     OR repository_selection_value NOT IN ('', 'all', 'selected')
     OR repositories_mode NOT IN ('none', 'replace', 'add', 'remove')
     OR (repository_values IS NOT NULL AND jsonb_typeof(repository_values) <> 'array')
     OR EXISTS (
       SELECT 1 FROM jsonb_array_elements_text(COALESCE(repository_values, '[]'::jsonb)) AS repository(value)
       WHERE value !~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}$'
     )
     OR (
       delivery_event = 'push' AND (
         COALESCE(repository_name, '') = '' OR COALESCE(git_ref, '') = '' OR
         pr_number IS NOT NULL OR repositories_mode <> 'none' OR
         (was_deleted AND head_commit IS NOT NULL) OR
         (NOT was_deleted AND head_commit IS NULL) OR
         (was_deleted AND processing_state <> 'ignored') OR
         (NOT was_deleted AND processing_state <> 'received')
       )
     )
     OR (
       delivery_event = 'pull_request' AND (
         COALESCE(repository_name, '') = '' OR COALESCE(git_ref, '') = '' OR
         head_commit IS NULL OR base_commit IS NULL OR pr_number IS NULL OR
         was_forced OR repositories_mode <> 'none' OR
         (delivery_action IN ('opened', 'reopened', 'synchronize') AND processing_state <> 'received') OR
         (delivery_action NOT IN ('opened', 'reopened', 'synchronize') AND processing_state <> 'ignored')
       )
     )
     OR (
       delivery_event = 'installation' AND (
         COALESCE(delivery_action, '') = '' OR COALESCE(account_login, '') = '' OR account_id IS NULL OR
         processing_state NOT IN ('processed', 'ignored') OR
         repository_name IS NOT NULL OR git_ref IS NOT NULL OR head_commit IS NOT NULL OR
         base_commit IS NOT NULL OR pr_number IS NOT NULL OR was_forced OR was_deleted
       )
     )
     OR (
       delivery_event = 'installation_repositories' AND (
         delivery_action NOT IN ('added', 'removed') OR
         repository_selection_value NOT IN ('all', 'selected') OR
         repositories_mode NOT IN ('add', 'remove') OR
         processing_state <> 'processed' OR
         repository_name IS NOT NULL OR git_ref IS NOT NULL OR head_commit IS NOT NULL OR
         base_commit IS NOT NULL OR pr_number IS NOT NULL OR was_forced OR was_deleted
       )
     ) THEN
    RAISE EXCEPTION 'invalid GitHub provider delivery' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO connection_row
  FROM source_connections
  WHERE provider = 'github' AND installation_external_id = installation_id
  LIMIT 1;
  IF connection_row.id IS NULL THEN
    RETURN jsonb_build_object('outcome', 'unknown_installation', 'work_pending', false);
  END IF;
  SELECT public_id INTO organization_public_id_value FROM organizations WHERE id = connection_row.organization_id;
  SELECT account.public_id INTO actor_public_id_value
  FROM memberships AS membership
  JOIN accounts AS account ON account.id = membership.account_id
  WHERE membership.organization_id = connection_row.organization_id
    AND membership.status = 'active'
  ORDER BY
    CASE WHEN membership.account_id = connection_row.connected_by_account_id THEN 0 ELSE 1 END,
    CASE membership.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'developer' THEN 2 ELSE 3 END,
    membership.id
  LIMIT 1;
  IF actor_public_id_value IS NULL THEN
    RETURN jsonb_build_object('outcome', 'unknown_installation', 'work_pending', false);
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended('github:' || delivery_id, 0));

  SELECT payload_digest, public_id, state, processing_started_at
  INTO existing_digest, existing_delivery_public_id, existing_delivery_state, existing_processing_started_at
  FROM source_provider_deliveries
  WHERE provider = 'github' AND external_delivery_id = delivery_id;
  IF existing_digest IS NOT NULL THEN
    RETURN jsonb_build_object(
      'outcome', CASE WHEN existing_digest = payload_sha256 THEN 'duplicate' ELSE 'mismatch' END,
      'delivery_public_id', existing_delivery_public_id,
      'organization_public_id', organization_public_id_value,
      'actor_public_id', actor_public_id_value,
      'work_pending', connection_row.status = 'active' AND existing_digest = payload_sha256 AND (
        existing_delivery_state IN ('received', 'failed') OR
        (existing_delivery_state = 'processing' AND existing_processing_started_at < clock_timestamp() - interval '20 minutes')
      )
    );
  END IF;

  IF delivery_event IN ('push', 'pull_request') AND connection_row.status <> 'active' THEN
    processing_state := 'ignored';
  END IF;

  next_repositories := connection_row.selected_repositories;
  IF repositories_mode = 'replace' THEN
    next_repositories := COALESCE(repository_values, '[]'::jsonb);
  ELSIF repositories_mode = 'add' THEN
    SELECT COALESCE(jsonb_agg(value ORDER BY value), '[]'::jsonb) INTO next_repositories
    FROM (
      SELECT DISTINCT value
      FROM jsonb_array_elements_text(connection_row.selected_repositories || COALESCE(repository_values, '[]'::jsonb))
    ) AS values;
  ELSIF repositories_mode = 'remove' THEN
    SELECT COALESCE(jsonb_agg(value ORDER BY value), '[]'::jsonb) INTO next_repositories
    FROM jsonb_array_elements_text(connection_row.selected_repositories) AS values(value)
    WHERE NOT COALESCE(repository_values, '[]'::jsonb) ? value;
  ELSIF repositories_mode <> 'none' THEN
    RAISE EXCEPTION 'invalid GitHub repository update mode' USING ERRCODE = '22023';
  END IF;

  INSERT INTO source_provider_deliveries(
    public_id, organization_id, source_connection_id, provider, external_delivery_id,
    event_type, action, payload_digest, state, repository, ref, commit_sha,
    base_commit_sha, pull_request_number, forced, deleted, processed_at, created_at, updated_at
  ) VALUES (
    delivery_public_id, connection_row.organization_id, connection_row.id, 'github', delivery_id,
    delivery_event, NULLIF(delivery_action, ''), payload_sha256, processing_state,
    NULLIF(repository_name, ''), NULLIF(git_ref, ''), head_commit,
    base_commit, pr_number, was_forced, was_deleted,
    CASE WHEN processing_state IN ('processed', 'ignored') THEN clock_timestamp() END,
    clock_timestamp(), clock_timestamp()
  );

  UPDATE source_connections
  SET status = COALESCE(NULLIF(next_connection_status, ''), status),
      revoked_at = CASE
        WHEN next_connection_status = 'revoked' THEN clock_timestamp()
        WHEN next_connection_status = 'active' THEN NULL
        ELSE revoked_at
      END,
      provider_account_login = COALESCE(NULLIF(account_login, ''), provider_account_login),
      provider_account_id = COALESCE(account_id, provider_account_id),
      repository_selection = COALESCE(NULLIF(repository_selection_value, ''), repository_selection),
      selected_repositories = next_repositories,
      last_webhook_at = clock_timestamp(),
      updated_at = clock_timestamp()
  WHERE id = connection_row.id;

  IF repositories_mode = 'remove' THEN
    UPDATE project_source_bindings
    SET automatic_deployments = false,
        generation = generation + 1,
        updated_at = clock_timestamp()
    WHERE source_connection_id = connection_row.id
      AND repository IN (SELECT jsonb_array_elements_text(COALESCE(repository_values, '[]'::jsonb)));
  END IF;
  IF next_connection_status IN ('suspended', 'revoked') THEN
    UPDATE project_source_bindings
    SET automatic_deployments = false,
        generation = generation + 1,
        updated_at = clock_timestamp()
    WHERE source_connection_id = connection_row.id
      AND automatic_deployments = true;
    UPDATE source_provider_deliveries
    SET state = 'ignored',
        processed_at = clock_timestamp(),
        processing_token = NULL,
        processing_started_at = NULL,
        last_error = NULL,
        updated_at = clock_timestamp()
    WHERE source_connection_id = connection_row.id
      AND state IN ('received', 'failed');
  END IF;

  INSERT INTO outbox_events(
    public_id, organization_id, event_type, schema_version, resource_type,
    resource_public_id, resource_version, actor_type, actor_public_id, correlation_id, data,
    occurred_at, publish_attempts, organization_public_id, created_at, updated_at
  ) VALUES (
    event_public_id, connection_row.organization_id, 'source.provider.' || delivery_event, 1,
    'source_connection', connection_row.public_id, 1, 'system', NULL, request_id,
    jsonb_strip_nulls(jsonb_build_object(
      'delivery_id', delivery_id, 'event_type', delivery_event, 'action', NULLIF(delivery_action, ''),
      'repository', NULLIF(repository_name, ''), 'ref', NULLIF(git_ref, ''),
      'commit_sha', head_commit, 'base_commit_sha', base_commit,
      'pull_request_number', pr_number, 'forced', was_forced, 'deleted', was_deleted
    )),
    clock_timestamp(), 0, organization_public_id_value, clock_timestamp(), clock_timestamp()
  );

  INSERT INTO audit_events(
    public_id, organization_id, actor_type, authentication_method, action,
    resource_type, resource_public_id, request_id, outcome, policy_version,
    metadata, occurred_at
  ) VALUES (
    audit_public_id, connection_row.organization_id, 'system', 'provider_webhook',
    'source.provider.webhook', 'source_connection', connection_row.public_id,
    request_id, 'succeeded', '2026-07-12.v1',
    jsonb_build_object('delivery_id', delivery_id, 'event_type', delivery_event),
    clock_timestamp()
  );

  RETURN jsonb_build_object(
    'outcome', processing_state,
    'delivery_public_id', delivery_public_id,
    'organization_public_id', organization_public_id_value,
    'actor_public_id', actor_public_id_value,
    'work_pending', processing_state = 'received'
  );
END;
$_$;


--
-- Name: lrail_block_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lrail_block_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: email_intents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_intents (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    account_id bigint,
    template character varying NOT NULL,
    template_version integer NOT NULL,
    recipient public.citext NOT NULL,
    locale character varying DEFAULT 'en'::character varying NOT NULL,
    data jsonb DEFAULT '{}'::jsonb NOT NULL,
    tags jsonb DEFAULT '{}'::jsonb NOT NULL,
    idempotency_key character varying NOT NULL,
    state character varying DEFAULT 'pending'::character varying NOT NULL,
    provider_message_id character varying,
    next_attempt_at timestamp(6) without time zone,
    delivered_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    last_error text,
    provider character varying(32),
    locked_at timestamp(6) without time zone,
    locked_by character varying(128),
    bounced_at timestamp(6) without time zone,
    complained_at timestamp(6) without time zone,
    terminal_at timestamp(6) without time zone,
    CONSTRAINT email_intents_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text)),
    CONSTRAINT email_intents_state CHECK (((state)::text = ANY ((ARRAY['pending'::character varying, 'sending'::character varying, 'sent'::character varying, 'delivered'::character varying, 'retryable'::character varying, 'bounced'::character varying, 'complained'::character varying, 'failed'::character varying])::text[])))
);

ALTER TABLE ONLY public.email_intents FORCE ROW LEVEL SECURITY;


--
-- Name: lrail_claim_email(text, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lrail_claim_email(worker_name text, requested_limit integer) RETURNS SETOF public.email_intents
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    SET row_security TO 'off'
    AS $$
  WITH candidates AS (
    SELECT id
    FROM email_intents
    WHERE state IN ('pending', 'retryable')
      AND (next_attempt_at IS NULL OR next_attempt_at <= clock_timestamp())
      AND (locked_at IS NULL OR locked_at < clock_timestamp() - interval '2 minutes')
    ORDER BY created_at, id
    FOR UPDATE SKIP LOCKED
    LIMIT GREATEST(1, LEAST(COALESCE(requested_limit, 1), 100))
  )
  UPDATE email_intents AS intent
  SET state = 'sending',
      locked_at = clock_timestamp(),
      locked_by = left(worker_name, 128),
      attempt_count = attempt_count + 1,
      last_error = NULL
  FROM candidates
  WHERE intent.id = candidates.id
  RETURNING intent.*;
$$;


--
-- Name: lrail_claim_github_provider_delivery(text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lrail_claim_github_provider_delivery(delivery_public_id text, lease_token text) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    SET row_security TO 'off'
    AS $_$
DECLARE
  claimed_state text;
  current_state text;
BEGIN
  IF delivery_public_id !~ '^[a-z]{2,5}_[0-9a-f-]{36}$' OR lease_token !~ '^[0-9A-Za-z-]{8,128}$' THEN
    RAISE EXCEPTION 'invalid provider delivery lease' USING ERRCODE = '22023';
  END IF;

  UPDATE source_provider_deliveries
  SET state = 'processing',
      attempt_count = CASE
        WHEN state = 'processing' AND processing_token = lease_token THEN attempt_count
        ELSE attempt_count + 1
      END,
      processing_token = lease_token,
      processing_started_at = clock_timestamp(),
      last_error = NULL,
      updated_at = clock_timestamp()
  WHERE public_id = delivery_public_id
    AND organization_id::text = current_setting('lrail.organization_id', true)
    AND lrail_account_has_membership(organization_id)
    AND (
      state IN ('received', 'failed') OR
      (state = 'processing' AND (
        processing_token = lease_token OR processing_started_at < clock_timestamp() - interval '20 minutes'
      ))
    )
  RETURNING state INTO claimed_state;
  IF claimed_state IS NOT NULL THEN
    RETURN 'claimed';
  END IF;

  SELECT state INTO current_state
  FROM source_provider_deliveries
  WHERE public_id = delivery_public_id
    AND organization_id::text = current_setting('lrail.organization_id', true)
    AND lrail_account_has_membership(organization_id);
  RETURN CASE
    WHEN current_state IN ('processed', 'ignored') THEN 'complete'
    WHEN current_state = 'processing' THEN 'busy'
    ELSE 'unknown'
  END;
END;
$_$;


--
-- Name: outbox_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.outbox_events (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    event_type character varying NOT NULL,
    schema_version integer DEFAULT 1 NOT NULL,
    resource_type character varying NOT NULL,
    resource_public_id character varying NOT NULL,
    resource_version bigint NOT NULL,
    actor_type character varying NOT NULL,
    actor_public_id character varying,
    correlation_id character varying NOT NULL,
    causation_id character varying,
    traceparent character varying,
    data jsonb DEFAULT '{}'::jsonb NOT NULL,
    occurred_at timestamp(6) without time zone NOT NULL,
    published_at timestamp(6) without time zone,
    publish_attempts integer DEFAULT 0 NOT NULL,
    publish_error text,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    organization_public_id character varying(64) NOT NULL,
    next_attempt_at timestamp(6) without time zone,
    locked_at timestamp(6) without time zone,
    locked_by character varying(128),
    discarded_at timestamp(6) without time zone,
    CONSTRAINT outbox_events_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.outbox_events FORCE ROW LEVEL SECURITY;


--
-- Name: lrail_claim_outbox(text, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lrail_claim_outbox(worker_name text, requested_limit integer) RETURNS SETOF public.outbox_events
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    SET row_security TO 'off'
    AS $$
  WITH candidates AS (
    SELECT id
    FROM outbox_events
    WHERE published_at IS NULL
      AND discarded_at IS NULL
      AND (next_attempt_at IS NULL OR next_attempt_at <= clock_timestamp())
      AND (locked_at IS NULL OR locked_at < clock_timestamp() - interval '2 minutes')
    ORDER BY occurred_at, id
    FOR UPDATE SKIP LOCKED
    LIMIT GREATEST(1, LEAST(COALESCE(requested_limit, 1), 100))
  )
  UPDATE outbox_events AS event
  SET locked_at = clock_timestamp(),
      locked_by = left(worker_name, 128),
      publish_attempts = publish_attempts + 1,
      publish_error = NULL
  FROM candidates
  WHERE event.id = candidates.id
  RETURNING event.*;
$$;


--
-- Name: lrail_expire_source_upload_sessions(integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lrail_expire_source_upload_sessions(requested_limit integer) RETURNS SETOF text
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    SET row_security TO 'off'
    AS $$
  WITH candidates AS (
    SELECT id
    FROM source_upload_sessions
    WHERE state IN ('authorized', 'uploading', 'failed')
      AND expires_at <= clock_timestamp()
    ORDER BY expires_at, id
    FOR UPDATE SKIP LOCKED
    LIMIT GREATEST(1, LEAST(COALESCE(requested_limit, 1), 500))
  )
  UPDATE source_upload_sessions AS session
  SET state = 'expired', updated_at = clock_timestamp()
  FROM candidates
  WHERE session.id = candidates.id
  RETURNING session.public_id;
$$;


--
-- Name: lrail_find_api_key(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lrail_find_api_key(candidate_prefix text) RETURNS TABLE(key_id bigint, key_public_id character varying, organization_id bigint, account_id bigint, secret_digest character varying, scopes jsonb, constraints jsonb, expires_at timestamp with time zone, last_used_at timestamp with time zone)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    SET row_security TO 'off'
    AS $$
  SELECT
    id,
    public_id,
    api_keys.organization_id,
    api_keys.account_id,
    api_keys.secret_digest,
    api_keys.scopes,
    api_keys.constraints,
    api_keys.expires_at,
    api_keys.last_used_at
  FROM api_keys
  WHERE prefix = candidate_prefix
    AND revoked_at IS NULL
    AND (expires_at IS NULL OR expires_at > clock_timestamp())
  LIMIT 1;
$$;


--
-- Name: lrail_finish_email(bigint, text, text, text, text, text, timestamp with time zone); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lrail_finish_email(intent_id bigint, worker_name text, result_state text, provider_name text, message_id text, error_message text, retry_at timestamp with time zone) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    SET row_security TO 'off'
    AS $$
DECLARE
  updated boolean;
BEGIN
  IF result_state NOT IN ('sent', 'delivered', 'retryable', 'failed') THEN
    RAISE EXCEPTION 'invalid email result state' USING ERRCODE = '22023';
  END IF;

  UPDATE email_intents
  SET state = result_state,
      provider = left(provider_name, 32),
      provider_message_id = COALESCE(message_id, provider_message_id),
      next_attempt_at = CASE WHEN result_state = 'retryable' THEN retry_at ELSE NULL END,
      delivered_at = CASE WHEN result_state = 'delivered' THEN clock_timestamp() ELSE delivered_at END,
      terminal_at = CASE WHEN result_state = 'failed' THEN clock_timestamp() ELSE terminal_at END,
      last_error = CASE WHEN result_state IN ('sent', 'delivered') THEN NULL ELSE left(error_message, 2048) END,
      locked_at = NULL,
      locked_by = NULL,
      updated_at = clock_timestamp()
  WHERE id = intent_id AND locked_by = worker_name
  RETURNING true INTO updated;

  RETURN COALESCE(updated, false);
END;
$$;


--
-- Name: lrail_finish_github_provider_delivery(text, text, boolean, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lrail_finish_github_provider_delivery(delivery_public_id text, lease_token text, succeeded boolean, error_code text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    SET row_security TO 'off'
    AS $_$
DECLARE
  updated_id bigint;
BEGIN
  IF delivery_public_id !~ '^[a-z]{2,5}_[0-9a-f-]{36}$' OR lease_token !~ '^[0-9A-Za-z-]{8,128}$'
     OR char_length(error_code) > 128 THEN
    RAISE EXCEPTION 'invalid provider delivery completion' USING ERRCODE = '22023';
  END IF;

  UPDATE source_provider_deliveries
  SET state = CASE WHEN succeeded THEN 'processed' ELSE 'failed' END,
      processed_at = CASE WHEN succeeded THEN clock_timestamp() ELSE NULL END,
      processing_token = NULL,
      processing_started_at = NULL,
      last_error = CASE WHEN succeeded THEN NULL ELSE NULLIF(error_code, '') END,
      updated_at = clock_timestamp()
  WHERE public_id = delivery_public_id
    AND organization_id::text = current_setting('lrail.organization_id', true)
    AND lrail_account_has_membership(organization_id)
    AND state = 'processing'
    AND processing_token = lease_token
  RETURNING id INTO updated_id;
  RETURN updated_id IS NOT NULL;
END;
$_$;


--
-- Name: lrail_finish_outbox(bigint, text, boolean, text, timestamp with time zone, boolean); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lrail_finish_outbox(event_id bigint, worker_name text, was_published boolean, error_message text, retry_at timestamp with time zone, dead_letter boolean) RETURNS boolean
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    SET row_security TO 'off'
    AS $$
  UPDATE outbox_events
  SET published_at = CASE WHEN was_published THEN clock_timestamp() ELSE published_at END,
      discarded_at = CASE WHEN dead_letter THEN clock_timestamp() ELSE discarded_at END,
      next_attempt_at = CASE WHEN was_published OR dead_letter THEN NULL ELSE retry_at END,
      publish_error = CASE WHEN was_published THEN NULL ELSE left(error_message, 2048) END,
      locked_at = NULL,
      locked_by = NULL,
      updated_at = clock_timestamp()
  WHERE id = event_id AND locked_by = worker_name
  RETURNING true;
$$;


--
-- Name: lrail_membership_owner_guard(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.lrail_membership_owner_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF OLD.role = 'owner' AND OLD.status = 'active'
     AND (TG_OP = 'DELETE' OR NEW.role <> 'owner' OR NEW.status <> 'active')
     AND NOT EXISTS (
       SELECT 1 FROM memberships
       WHERE organization_id = OLD.organization_id
         AND role = 'owner' AND status = 'active' AND id <> OLD.id
     ) THEN
    RAISE EXCEPTION 'organization must retain an active owner' USING ERRCODE = '23514';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;


--
-- Name: rodauth_get_previous_salt(bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.rodauth_get_previous_salt(acct_id bigint) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    AS $_$
DECLARE salt text;
BEGIN
SELECT
CASE
    WHEN password_hash ~ '^\$argon2id'
      THEN substring(password_hash from '\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$.+\$')
    ELSE substr(password_hash, 0, 30)
  END INTO salt

FROM "account_previous_password_hashes"
WHERE acct_id = id;
RETURN salt;
END;
$_$;


--
-- Name: rodauth_get_salt(bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.rodauth_get_salt(acct_id bigint) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    AS $_$
DECLARE salt text;
BEGIN
SELECT
CASE
    WHEN password_hash ~ '^\$argon2id'
      THEN substring(password_hash from '\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$.+\$')
    ELSE substr(password_hash, 0, 30)
  END INTO salt

FROM "account_password_hashes"
WHERE acct_id = id;
RETURN salt;
END;
$_$;


--
-- Name: rodauth_previous_password_hash_match(bigint, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.rodauth_previous_password_hash_match(acct_id bigint, hash text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    AS $$
DECLARE valid boolean;
BEGIN
SELECT password_hash = hash INTO valid 
FROM "account_previous_password_hashes"
WHERE acct_id = id;
RETURN valid;
END;
$$;


--
-- Name: rodauth_valid_password_hash(bigint, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.rodauth_valid_password_hash(acct_id bigint, hash text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public', 'pg_temp'
    AS $$
DECLARE valid boolean;
BEGIN
SELECT password_hash = hash INTO valid 
FROM "account_password_hashes"
WHERE acct_id = id;
RETURN valid;
END;
$$;


--
-- Name: account_active_session_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_active_session_keys (
    account_id bigint NOT NULL,
    session_id character varying NOT NULL,
    created_at timestamp(6) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_use timestamp(6) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: account_authentication_audit_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_authentication_audit_logs (
    id bigint NOT NULL,
    account_id bigint NOT NULL,
    at timestamp(6) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    message text NOT NULL,
    metadata jsonb
);


--
-- Name: account_authentication_audit_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.account_authentication_audit_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: account_authentication_audit_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.account_authentication_audit_logs_id_seq OWNED BY public.account_authentication_audit_logs.id;


--
-- Name: account_lockouts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_lockouts (
    id bigint NOT NULL,
    key character varying NOT NULL,
    deadline timestamp(6) without time zone NOT NULL,
    email_last_sent timestamp(6) without time zone
);


--
-- Name: account_lockouts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.account_lockouts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: account_lockouts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.account_lockouts_id_seq OWNED BY public.account_lockouts.id;


--
-- Name: account_login_change_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_login_change_keys (
    id bigint NOT NULL,
    key character varying NOT NULL,
    login character varying NOT NULL,
    deadline timestamp(6) without time zone NOT NULL
);


--
-- Name: account_login_change_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.account_login_change_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: account_login_change_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.account_login_change_keys_id_seq OWNED BY public.account_login_change_keys.id;


--
-- Name: account_login_failures; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_login_failures (
    id bigint NOT NULL,
    number integer DEFAULT 1 NOT NULL
);


--
-- Name: account_login_failures_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.account_login_failures_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: account_login_failures_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.account_login_failures_id_seq OWNED BY public.account_login_failures.id;


--
-- Name: account_otp_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_otp_keys (
    id bigint NOT NULL,
    key character varying NOT NULL,
    num_failures integer DEFAULT 0 NOT NULL,
    last_use timestamp(6) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: account_otp_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.account_otp_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: account_otp_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.account_otp_keys_id_seq OWNED BY public.account_otp_keys.id;


--
-- Name: account_password_hashes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_password_hashes (
    id bigint NOT NULL,
    password_hash character varying NOT NULL
);


--
-- Name: account_password_hashes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.account_password_hashes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: account_password_hashes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.account_password_hashes_id_seq OWNED BY public.account_password_hashes.id;


--
-- Name: account_password_reset_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_password_reset_keys (
    id bigint NOT NULL,
    key character varying NOT NULL,
    deadline timestamp(6) without time zone NOT NULL,
    email_last_sent timestamp(6) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: account_password_reset_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.account_password_reset_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: account_password_reset_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.account_password_reset_keys_id_seq OWNED BY public.account_password_reset_keys.id;


--
-- Name: account_previous_password_hashes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_previous_password_hashes (
    id bigint NOT NULL,
    account_id bigint,
    password_hash character varying NOT NULL
);


--
-- Name: account_previous_password_hashes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.account_previous_password_hashes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: account_previous_password_hashes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.account_previous_password_hashes_id_seq OWNED BY public.account_previous_password_hashes.id;


--
-- Name: account_recovery_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_recovery_codes (
    id bigint NOT NULL,
    code character varying NOT NULL
);


--
-- Name: account_remember_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_remember_keys (
    id bigint NOT NULL,
    key character varying NOT NULL,
    deadline timestamp(6) without time zone NOT NULL
);


--
-- Name: account_remember_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.account_remember_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: account_remember_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.account_remember_keys_id_seq OWNED BY public.account_remember_keys.id;


--
-- Name: account_verification_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_verification_keys (
    id bigint NOT NULL,
    key character varying NOT NULL,
    requested_at timestamp(6) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    email_last_sent timestamp(6) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: account_verification_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.account_verification_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: account_verification_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.account_verification_keys_id_seq OWNED BY public.account_verification_keys.id;


--
-- Name: account_webauthn_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_webauthn_keys (
    account_id bigint NOT NULL,
    webauthn_id character varying NOT NULL,
    public_key character varying NOT NULL,
    sign_count integer NOT NULL,
    last_use timestamp(6) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: account_webauthn_user_ids; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_webauthn_user_ids (
    id bigint NOT NULL,
    webauthn_id character varying NOT NULL
);


--
-- Name: account_webauthn_user_ids_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.account_webauthn_user_ids_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: account_webauthn_user_ids_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.account_webauthn_user_ids_id_seq OWNED BY public.account_webauthn_user_ids.id;


--
-- Name: accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.accounts (
    id bigint NOT NULL,
    status integer DEFAULT 1 NOT NULL,
    email public.citext NOT NULL,
    public_id character varying NOT NULL,
    display_name character varying DEFAULT 'Developer'::character varying NOT NULL,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    CONSTRAINT accounts_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text)),
    CONSTRAINT valid_email CHECK ((email OPERATOR(public.~) '^[^,;@ 
]+@[^,@; 
]+.[^,@; 
]+$'::public.citext))
);


--
-- Name: accounts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.accounts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: accounts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.accounts_id_seq OWNED BY public.accounts.id;


--
-- Name: addon_backups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.addon_backups (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    addon_id bigint NOT NULL,
    kind character varying NOT NULL,
    state character varying DEFAULT 'pending'::character varying NOT NULL,
    started_at timestamp(6) without time zone,
    completed_at timestamp(6) without time zone,
    restorable_from timestamp(6) without time zone,
    restorable_until timestamp(6) without time zone,
    encryption_key_id character varying,
    digest character varying,
    size_bytes bigint,
    object_locations jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT addon_backups_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.addon_backups FORCE ROW LEVEL SECURITY;


--
-- Name: addon_backups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.addon_backups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: addon_backups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.addon_backups_id_seq OWNED BY public.addon_backups.id;


--
-- Name: addons; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.addons (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    project_id bigint NOT NULL,
    environment_id bigint NOT NULL,
    name character varying NOT NULL,
    engine character varying NOT NULL,
    version_channel character varying NOT NULL,
    topology character varying NOT NULL,
    size_profile character varying NOT NULL,
    storage_profile character varying NOT NULL,
    region character varying NOT NULL,
    state character varying DEFAULT 'requested'::character varying NOT NULL,
    deletion_protection boolean DEFAULT true NOT NULL,
    conditions jsonb DEFAULT '[]'::jsonb NOT NULL,
    provider_resource_id character varying,
    lock_version integer DEFAULT 0 NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT addons_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.addons FORCE ROW LEVEL SECURITY;


--
-- Name: addons_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.addons_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: addons_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.addons_id_seq OWNED BY public.addons.id;


--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_keys (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    account_id bigint NOT NULL,
    name character varying NOT NULL,
    prefix character varying NOT NULL,
    secret_digest character varying NOT NULL,
    scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
    constraints jsonb DEFAULT '{}'::jsonb NOT NULL,
    expires_at timestamp(6) without time zone,
    last_used_at timestamp(6) without time zone,
    revoked_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT api_keys_argon_digest CHECK (((secret_digest)::text ~~ '$argon2id$%'::text)),
    CONSTRAINT api_keys_constraints_object CHECK ((jsonb_typeof(constraints) = 'object'::text)),
    CONSTRAINT api_keys_prefix_format CHECK (((prefix)::text ~ '^[A-Za-z0-9]{12}$'::text)),
    CONSTRAINT api_keys_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text)),
    CONSTRAINT api_keys_scopes_array CHECK ((jsonb_typeof(scopes) = 'array'::text))
);

ALTER TABLE ONLY public.api_keys FORCE ROW LEVEL SECURITY;


--
-- Name: api_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.api_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: api_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.api_keys_id_seq OWNED BY public.api_keys.id;


--
-- Name: ar_internal_metadata; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ar_internal_metadata (
    key character varying NOT NULL,
    value character varying,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);


--
-- Name: attachments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attachments (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    addon_id bigint NOT NULL,
    service_id bigint NOT NULL,
    environment_id bigint NOT NULL,
    name character varying NOT NULL,
    credential_version bigint NOT NULL,
    state character varying DEFAULT 'pending'::character varying NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT attachments_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.attachments FORCE ROW LEVEL SECURITY;


--
-- Name: attachments_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.attachments_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: attachments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.attachments_id_seq OWNED BY public.attachments.id;


--
-- Name: attestations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attestations (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    revision_id bigint NOT NULL,
    kind character varying NOT NULL,
    digest character varying NOT NULL,
    object_ref character varying NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);

ALTER TABLE ONLY public.attestations FORCE ROW LEVEL SECURITY;


--
-- Name: attestations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.attestations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: attestations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.attestations_id_seq OWNED BY public.attestations.id;


--
-- Name: audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_events (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    actor_type character varying NOT NULL,
    actor_public_id character varying,
    authentication_method character varying,
    action character varying NOT NULL,
    reason character varying,
    resource_type character varying NOT NULL,
    resource_public_id character varying NOT NULL,
    before_fingerprint character varying,
    after_fingerprint character varying,
    request_id character varying NOT NULL,
    trace_id character varying,
    workflow_id character varying,
    incident_public_id character varying,
    ip_prefix character varying,
    device_summary character varying,
    outcome character varying NOT NULL,
    policy_version character varying NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    occurred_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT audit_events_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.audit_events FORCE ROW LEVEL SECURITY;


--
-- Name: audit_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_events_id_seq OWNED BY public.audit_events.id;


--
-- Name: build_steps; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.build_steps (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    build_id bigint NOT NULL,
    "position" integer NOT NULL,
    name character varying NOT NULL,
    state character varying NOT NULL,
    failure_code character varying,
    started_at timestamp(6) without time zone,
    completed_at timestamp(6) without time zone
);

ALTER TABLE ONLY public.build_steps FORCE ROW LEVEL SECURITY;


--
-- Name: build_steps_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.build_steps_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: build_steps_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.build_steps_id_seq OWNED BY public.build_steps.id;


--
-- Name: builds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.builds (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    source_snapshot_id bigint NOT NULL,
    definition_digest character varying NOT NULL,
    state character varying DEFAULT 'accepted'::character varying NOT NULL,
    network_profile character varying DEFAULT 'none'::character varying NOT NULL,
    artifact_digest character varying,
    started_at timestamp(6) without time zone,
    completed_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT builds_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.builds FORCE ROW LEVEL SECURITY;


--
-- Name: builds_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.builds_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: builds_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.builds_id_seq OWNED BY public.builds.id;


--
-- Name: certificates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.certificates (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    domain_id bigint NOT NULL,
    state character varying DEFAULT 'pending'::character varying NOT NULL,
    key_id character varying,
    fingerprint character varying,
    sans jsonb DEFAULT '[]'::jsonb NOT NULL,
    not_before timestamp(6) without time zone,
    not_after timestamp(6) without time zone,
    renewal_due_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT certificates_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.certificates FORCE ROW LEVEL SECURITY;


--
-- Name: certificates_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.certificates_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: certificates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.certificates_id_seq OWNED BY public.certificates.id;


--
-- Name: credential_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.credential_versions (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    addon_id bigint NOT NULL,
    version bigint NOT NULL,
    secret_public_id character varying NOT NULL,
    state character varying DEFAULT 'next'::character varying NOT NULL,
    issued_at timestamp(6) without time zone NOT NULL,
    revoked_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);

ALTER TABLE ONLY public.credential_versions FORCE ROW LEVEL SECURITY;


--
-- Name: credential_versions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.credential_versions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: credential_versions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.credential_versions_id_seq OWNED BY public.credential_versions.id;


--
-- Name: dead_letter_messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dead_letter_messages (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    consumer character varying(128) NOT NULL,
    event_public_id character varying(64) NOT NULL,
    event_type character varying(128) NOT NULL,
    subject character varying(256) NOT NULL,
    reason character varying(256) NOT NULL,
    event_payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    message_headers jsonb DEFAULT '{}'::jsonb NOT NULL,
    attempt_count integer NOT NULL,
    first_failed_at timestamp(6) without time zone NOT NULL,
    last_failed_at timestamp(6) without time zone NOT NULL,
    replayed_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT dead_letter_messages_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.dead_letter_messages FORCE ROW LEVEL SECURITY;


--
-- Name: dead_letter_messages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dead_letter_messages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dead_letter_messages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dead_letter_messages_id_seq OWNED BY public.dead_letter_messages.id;


--
-- Name: deployment_transitions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.deployment_transitions (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    deployment_id bigint NOT NULL,
    from_state character varying,
    to_state character varying NOT NULL,
    reason character varying NOT NULL,
    actor_type character varying NOT NULL,
    actor_public_id character varying,
    correlation_id character varying NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp(6) without time zone NOT NULL
);

ALTER TABLE ONLY public.deployment_transitions FORCE ROW LEVEL SECURITY;


--
-- Name: deployment_transitions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.deployment_transitions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: deployment_transitions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.deployment_transitions_id_seq OWNED BY public.deployment_transitions.id;


--
-- Name: deployments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.deployments (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    project_id bigint NOT NULL,
    environment_id bigint NOT NULL,
    source_snapshot_id bigint,
    revision_id bigint,
    operation_id bigint NOT NULL,
    state character varying DEFAULT 'created'::character varying NOT NULL,
    source jsonb DEFAULT '{}'::jsonb NOT NULL,
    manifest_revision integer NOT NULL,
    reason text NOT NULL,
    lock_version integer DEFAULT 0 NOT NULL,
    ready_at timestamp(6) without time zone,
    promoted_at timestamp(6) without time zone,
    canceled_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT deployments_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text)),
    CONSTRAINT deployments_source_object CHECK ((jsonb_typeof(source) = 'object'::text)),
    CONSTRAINT deployments_state CHECK (((state)::text = ANY ((ARRAY['created'::character varying, 'sourcing'::character varying, 'detecting'::character varying, 'queued'::character varying, 'building'::character varying, 'scanning'::character varying, 'publishing'::character varying, 'scheduling'::character varying, 'starting'::character varying, 'verifying'::character varying, 'ready'::character varying, 'promoted'::character varying, 'canceling'::character varying, 'canceled'::character varying, 'failed'::character varying, 'retrying'::character varying])::text[])))
);

ALTER TABLE ONLY public.deployments FORCE ROW LEVEL SECURITY;


--
-- Name: deployments_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.deployments_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: deployments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.deployments_id_seq OWNED BY public.deployments.id;


--
-- Name: dns_changes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dns_changes (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    domain_id bigint NOT NULL,
    operation_id character varying NOT NULL,
    generation bigint NOT NULL,
    previous_fingerprint character varying,
    records jsonb NOT NULL,
    state character varying DEFAULT 'pending'::character varying NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);

ALTER TABLE ONLY public.dns_changes FORCE ROW LEVEL SECURITY;


--
-- Name: dns_changes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dns_changes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dns_changes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dns_changes_id_seq OWNED BY public.dns_changes.id;


--
-- Name: domains; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.domains (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    project_id bigint NOT NULL,
    environment_id bigint NOT NULL,
    service_id bigint NOT NULL,
    hostname public.citext NOT NULL,
    mode character varying NOT NULL,
    state character varying DEFAULT 'requested'::character varying NOT NULL,
    verified_at timestamp(6) without time zone,
    revalidation_due_at timestamp(6) without time zone,
    lock_version integer DEFAULT 0 NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT domains_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.domains FORCE ROW LEVEL SECURITY;


--
-- Name: domains_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.domains_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: domains_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.domains_id_seq OWNED BY public.domains.id;


--
-- Name: edge_route_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.edge_route_versions (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    domain_id bigint NOT NULL,
    release_id bigint NOT NULL,
    edge_generation_public_id character varying NOT NULL,
    canonical_digest character varying NOT NULL,
    state character varying DEFAULT 'staged'::character varying NOT NULL,
    conditions jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);

ALTER TABLE ONLY public.edge_route_versions FORCE ROW LEVEL SECURITY;


--
-- Name: edge_route_versions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.edge_route_versions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: edge_route_versions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.edge_route_versions_id_seq OWNED BY public.edge_route_versions.id;


--
-- Name: email_intents_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.email_intents_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: email_intents_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.email_intents_id_seq OWNED BY public.email_intents.id;


--
-- Name: email_provider_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_provider_events (
    id bigint NOT NULL,
    provider_event_id character varying(128) NOT NULL,
    event_type character varying(64) NOT NULL,
    provider_message_id character varying(128),
    payload_digest character varying(71) NOT NULL,
    outcome character varying(32) DEFAULT 'received'::character varying NOT NULL,
    received_at timestamp(6) without time zone NOT NULL,
    processed_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);


--
-- Name: email_provider_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.email_provider_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: email_provider_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.email_provider_events_id_seq OWNED BY public.email_provider_events.id;


--
-- Name: environments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environments (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    project_id bigint NOT NULL,
    slug character varying(63) NOT NULL,
    name character varying(100) NOT NULL,
    protected boolean DEFAULT false NOT NULL,
    generation bigint DEFAULT 1 NOT NULL,
    health character varying DEFAULT 'unknown'::character varying NOT NULL,
    lock_version integer DEFAULT 0 NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT environments_generation CHECK ((generation > 0)),
    CONSTRAINT environments_health CHECK (((health)::text = ANY ((ARRAY['healthy'::character varying, 'degraded'::character varying, 'deploying'::character varying, 'paused'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT environments_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.environments FORCE ROW LEVEL SECURITY;


--
-- Name: environments_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.environments_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: environments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.environments_id_seq OWNED BY public.environments.id;


--
-- Name: idempotency_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.idempotency_keys (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    principal_public_id character varying NOT NULL,
    http_method character varying NOT NULL,
    normalized_route character varying NOT NULL,
    key_digest character varying NOT NULL,
    request_fingerprint character varying NOT NULL,
    command_public_id character varying,
    response_status integer,
    response_body jsonb,
    expires_at timestamp(6) without time zone NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);

ALTER TABLE ONLY public.idempotency_keys FORCE ROW LEVEL SECURITY;


--
-- Name: idempotency_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.idempotency_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: idempotency_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.idempotency_keys_id_seq OWNED BY public.idempotency_keys.id;


--
-- Name: inbox_messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.inbox_messages (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    consumer character varying(128) NOT NULL,
    event_public_id character varying(64) NOT NULL,
    event_type character varying(128) NOT NULL,
    schema_version integer NOT NULL,
    subject character varying(256) NOT NULL,
    payload_digest character varying(71) NOT NULL,
    state character varying DEFAULT 'processing'::character varying NOT NULL,
    attempt_count integer DEFAULT 1 NOT NULL,
    first_received_at timestamp(6) without time zone NOT NULL,
    processed_at timestamp(6) without time zone,
    last_error text,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT inbox_messages_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text)),
    CONSTRAINT inbox_messages_state CHECK (((state)::text = ANY ((ARRAY['processing'::character varying, 'completed'::character varying, 'dead_lettered'::character varying])::text[])))
);

ALTER TABLE ONLY public.inbox_messages FORCE ROW LEVEL SECURITY;


--
-- Name: inbox_messages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.inbox_messages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: inbox_messages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.inbox_messages_id_seq OWNED BY public.inbox_messages.id;


--
-- Name: invitations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.invitations (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    inviter_id bigint NOT NULL,
    email public.citext NOT NULL,
    role character varying NOT NULL,
    token_digest character varying NOT NULL,
    expires_at timestamp(6) without time zone NOT NULL,
    accepted_at timestamp(6) without time zone,
    revoked_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT invitations_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.invitations FORCE ROW LEVEL SECURITY;


--
-- Name: invitations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.invitations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: invitations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.invitations_id_seq OWNED BY public.invitations.id;


--
-- Name: memberships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.memberships (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    account_id bigint NOT NULL,
    organization_id bigint NOT NULL,
    role character varying NOT NULL,
    status character varying DEFAULT 'active'::character varying NOT NULL,
    revoked_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT memberships_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text)),
    CONSTRAINT memberships_role CHECK (((role)::text = ANY ((ARRAY['owner'::character varying, 'admin'::character varying, 'developer'::character varying, 'operator'::character varying, 'billing'::character varying, 'auditor'::character varying])::text[]))),
    CONSTRAINT memberships_status CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'suspended'::character varying, 'revoked'::character varying])::text[])))
);

ALTER TABLE ONLY public.memberships FORCE ROW LEVEL SECURITY;


--
-- Name: memberships_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.memberships_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: memberships_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.memberships_id_seq OWNED BY public.memberships.id;


--
-- Name: oauth_clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_clients (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    name character varying NOT NULL,
    client_digest character varying NOT NULL,
    redirect_uris jsonb DEFAULT '[]'::jsonb NOT NULL,
    scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
    revoked_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT oauth_clients_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.oauth_clients FORCE ROW LEVEL SECURITY;


--
-- Name: oauth_clients_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.oauth_clients_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: oauth_clients_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.oauth_clients_id_seq OWNED BY public.oauth_clients.id;


--
-- Name: operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.operations (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    resource_type character varying NOT NULL,
    resource_public_id character varying NOT NULL,
    state character varying DEFAULT 'accepted'::character varying NOT NULL,
    stage character varying DEFAULT 'accepted'::character varying NOT NULL,
    completed_steps integer DEFAULT 0 NOT NULL,
    total_steps integer DEFAULT 0 NOT NULL,
    waiting_reason text,
    error_code character varying,
    error_message text,
    conditions jsonb DEFAULT '[]'::jsonb NOT NULL,
    workflow_id character varying,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT operations_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text)),
    CONSTRAINT operations_state CHECK (((state)::text = ANY ((ARRAY['accepted'::character varying, 'running'::character varying, 'waiting'::character varying, 'retrying'::character varying, 'succeeded'::character varying, 'failed'::character varying, 'canceling'::character varying, 'canceled'::character varying])::text[])))
);

ALTER TABLE ONLY public.operations FORCE ROW LEVEL SECURITY;


--
-- Name: operations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.operations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: operations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.operations_id_seq OWNED BY public.operations.id;


--
-- Name: organizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organizations (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    created_by_account_id bigint NOT NULL,
    slug character varying(63) NOT NULL,
    name character varying(100) NOT NULL,
    plan character varying DEFAULT 'free'::character varying NOT NULL,
    personal boolean DEFAULT false NOT NULL,
    lock_version integer DEFAULT 0 NOT NULL,
    deletion_requested_at timestamp(6) without time zone,
    retention_until timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT organizations_plan CHECK (((plan)::text = ANY ((ARRAY['free'::character varying, 'pro'::character varying, 'enterprise'::character varying])::text[]))),
    CONSTRAINT organizations_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text)),
    CONSTRAINT organizations_slug_format CHECK (((slug)::text ~ '^[a-z][a-z0-9-]{0,62}$'::text))
);

ALTER TABLE ONLY public.organizations FORCE ROW LEVEL SECURITY;


--
-- Name: organizations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.organizations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: organizations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.organizations_id_seq OWNED BY public.organizations.id;


--
-- Name: outbox_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.outbox_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: outbox_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.outbox_events_id_seq OWNED BY public.outbox_events.id;


--
-- Name: ownership_challenges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ownership_challenges (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    domain_id bigint NOT NULL,
    record_name character varying NOT NULL,
    verifier bytea NOT NULL,
    expires_at timestamp(6) without time zone NOT NULL,
    consumed_at timestamp(6) without time zone,
    evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);

ALTER TABLE ONLY public.ownership_challenges FORCE ROW LEVEL SECURITY;


--
-- Name: ownership_challenges_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ownership_challenges_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ownership_challenges_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ownership_challenges_id_seq OWNED BY public.ownership_challenges.id;


--
-- Name: project_source_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.project_source_bindings (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    project_id bigint NOT NULL,
    source_connection_id bigint NOT NULL,
    created_by_account_id bigint NOT NULL,
    current_source_fetch_id bigint,
    last_provider_delivery_id bigint,
    repository character varying(201) NOT NULL,
    production_branch character varying(255) DEFAULT 'main'::character varying NOT NULL,
    root_directory character varying(512) DEFAULT ''::character varying NOT NULL,
    automatic_deployments boolean DEFAULT true NOT NULL,
    current_ref character varying(512),
    requested_commit_sha character varying(64),
    generation bigint DEFAULT 1 NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT project_source_bindings_commit CHECK (((requested_commit_sha IS NULL) OR ((requested_commit_sha)::text ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'::text))),
    CONSTRAINT project_source_bindings_generation CHECK ((generation > 0)),
    CONSTRAINT project_source_bindings_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text)),
    CONSTRAINT project_source_bindings_repository CHECK (((repository)::text ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}$'::text))
);

ALTER TABLE ONLY public.project_source_bindings FORCE ROW LEVEL SECURITY;


--
-- Name: project_source_bindings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.project_source_bindings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: project_source_bindings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.project_source_bindings_id_seq OWNED BY public.project_source_bindings.id;


--
-- Name: projects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.projects (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    slug character varying(63) NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    status character varying DEFAULT 'healthy'::character varying NOT NULL,
    manifest_revision integer DEFAULT 1 NOT NULL,
    manifest jsonb DEFAULT '{}'::jsonb NOT NULL,
    lock_version integer DEFAULT 0 NOT NULL,
    deletion_requested_at timestamp(6) without time zone,
    retention_until timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT projects_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text)),
    CONSTRAINT projects_status CHECK (((status)::text = ANY ((ARRAY['healthy'::character varying, 'degraded'::character varying, 'deploying'::character varying, 'paused'::character varying])::text[])))
);

ALTER TABLE ONLY public.projects FORCE ROW LEVEL SECURITY;


--
-- Name: projects_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.projects_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: projects_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.projects_id_seq OWNED BY public.projects.id;


--
-- Name: release_targets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.release_targets (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    release_id bigint NOT NULL,
    cell_public_id character varying NOT NULL,
    region character varying NOT NULL,
    desired_generation bigint NOT NULL,
    observed_generation bigint,
    state character varying DEFAULT 'pending'::character varying NOT NULL,
    conditions jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);

ALTER TABLE ONLY public.release_targets FORCE ROW LEVEL SECURITY;


--
-- Name: release_targets_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.release_targets_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: release_targets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.release_targets_id_seq OWNED BY public.release_targets.id;


--
-- Name: releases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.releases (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    service_id bigint NOT NULL,
    environment_id bigint NOT NULL,
    revision_id bigint NOT NULL,
    deployment_id bigint,
    generation bigint NOT NULL,
    state character varying DEFAULT 'draft'::character varying NOT NULL,
    rollout_policy character varying DEFAULT 'default_canary'::character varying NOT NULL,
    traffic_weight integer DEFAULT 0 NOT NULL,
    activated_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT releases_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text)),
    CONSTRAINT releases_state CHECK (((state)::text = ANY ((ARRAY['draft'::character varying, 'policy_check'::character varying, 'provisioning'::character varying, 'previewing'::character varying, 'shifting'::character varying, 'verifying'::character varying, 'active'::character varying, 'paused'::character varying, 'aborting'::character varying, 'rolled_back'::character varying, 'superseded'::character varying, 'retired'::character varying])::text[]))),
    CONSTRAINT releases_traffic_weight CHECK (((traffic_weight >= 0) AND (traffic_weight <= 100)))
);

ALTER TABLE ONLY public.releases FORCE ROW LEVEL SECURITY;


--
-- Name: releases_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.releases_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: releases_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.releases_id_seq OWNED BY public.releases.id;


--
-- Name: revisions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.revisions (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    service_id bigint NOT NULL,
    build_id bigint NOT NULL,
    image_digest character varying NOT NULL,
    manifest_digest character varying NOT NULL,
    sbom_ref character varying NOT NULL,
    provenance_ref character varying NOT NULL,
    signature_ref character varying NOT NULL,
    scan_state character varying NOT NULL,
    policy_state character varying NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT revisions_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.revisions FORCE ROW LEVEL SECURITY;


--
-- Name: revisions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.revisions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: revisions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.revisions_id_seq OWNED BY public.revisions.id;


--
-- Name: rollout_steps; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rollout_steps (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    release_id bigint NOT NULL,
    "position" integer NOT NULL,
    traffic_weight integer NOT NULL,
    duration_seconds integer NOT NULL,
    state character varying DEFAULT 'pending'::character varying NOT NULL,
    analysis jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);

ALTER TABLE ONLY public.rollout_steps FORCE ROW LEVEL SECURITY;


--
-- Name: rollout_steps_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.rollout_steps_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: rollout_steps_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.rollout_steps_id_seq OWNED BY public.rollout_steps.id;


--
-- Name: schedules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schedules (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    project_id bigint NOT NULL,
    environment_id bigint NOT NULL,
    name character varying NOT NULL,
    expression character varying NOT NULL,
    timezone character varying NOT NULL,
    overlap_policy character varying NOT NULL,
    target jsonb NOT NULL,
    retry_policy jsonb DEFAULT '{}'::jsonb NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    next_run_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT schedules_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.schedules FORCE ROW LEVEL SECURITY;


--
-- Name: schedules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.schedules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: schedules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.schedules_id_seq OWNED BY public.schedules.id;


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version character varying NOT NULL
);


--
-- Name: service_routes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.service_routes (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    service_id bigint NOT NULL,
    environment_id bigint NOT NULL,
    hostname character varying,
    path_prefix character varying DEFAULT '/'::character varying NOT NULL,
    protocol character varying DEFAULT 'https'::character varying NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT service_routes_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.service_routes FORCE ROW LEVEL SECURITY;


--
-- Name: service_routes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.service_routes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: service_routes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.service_routes_id_seq OWNED BY public.service_routes.id;


--
-- Name: services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.services (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    project_id bigint NOT NULL,
    slug character varying(63) NOT NULL,
    name character varying(100) NOT NULL,
    kind character varying NOT NULL,
    framework character varying,
    health character varying DEFAULT 'unknown'::character varying NOT NULL,
    build_specification jsonb DEFAULT '{}'::jsonb NOT NULL,
    runtime_specification jsonb DEFAULT '{}'::jsonb NOT NULL,
    lock_version integer DEFAULT 0 NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    current_release_id bigint,
    CONSTRAINT services_health CHECK (((health)::text = ANY ((ARRAY['healthy'::character varying, 'degraded'::character varying, 'deploying'::character varying, 'paused'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT services_kind CHECK (((kind)::text = ANY ((ARRAY['web'::character varying, 'worker'::character varying, 'private_service'::character varying, 'static'::character varying])::text[]))),
    CONSTRAINT services_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.services FORCE ROW LEVEL SECURITY;


--
-- Name: services_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.services_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: services_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.services_id_seq OWNED BY public.services.id;


--
-- Name: source_connections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.source_connections (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    provider character varying NOT NULL,
    installation_external_id character varying NOT NULL,
    status character varying DEFAULT 'active'::character varying NOT NULL,
    scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
    last_webhook_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    provider_account_login character varying(255) NOT NULL,
    provider_account_id bigint,
    repository_selection character varying(16) DEFAULT 'selected'::character varying NOT NULL,
    selected_repositories jsonb DEFAULT '[]'::jsonb NOT NULL,
    token_expires_at timestamp(6) without time zone,
    revoked_at timestamp(6) without time zone,
    connected_by_account_id bigint NOT NULL,
    CONSTRAINT source_connections_installation CHECK (((installation_external_id)::text ~ '^[1-9][0-9]{0,19}$'::text)),
    CONSTRAINT source_connections_provider CHECK (((provider)::text = 'github'::text)),
    CONSTRAINT source_connections_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text)),
    CONSTRAINT source_connections_repositories_array CHECK ((jsonb_typeof(selected_repositories) = 'array'::text)),
    CONSTRAINT source_connections_repository_selection CHECK (((repository_selection)::text = ANY ((ARRAY['all'::character varying, 'selected'::character varying])::text[]))),
    CONSTRAINT source_connections_scopes_array CHECK ((jsonb_typeof(scopes) = 'array'::text)),
    CONSTRAINT source_connections_status CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'suspended'::character varying, 'revoked'::character varying])::text[])))
);

ALTER TABLE ONLY public.source_connections FORCE ROW LEVEL SECURITY;


--
-- Name: source_connections_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.source_connections_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: source_connections_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.source_connections_id_seq OWNED BY public.source_connections.id;


--
-- Name: source_fetches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.source_fetches (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    project_id bigint NOT NULL,
    source_connection_id bigint NOT NULL,
    created_by_account_id bigint NOT NULL,
    source_snapshot_id bigint,
    state character varying(32) DEFAULT 'authorized'::character varying NOT NULL,
    repository character varying(201) NOT NULL,
    requested_commit_sha character varying(64) NOT NULL,
    resolved_commit_sha character varying(64),
    tree_sha character varying(64),
    root_directory character varying(512) DEFAULT ''::character varying NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    snapshot_sha256 character varying(71),
    manifest_sha256 character varying(71),
    archive_sha256 character varying(71),
    manifest_ref character varying,
    archive_ref character varying,
    signing_key_id character varying(128),
    author character varying(512),
    authored_at timestamp(6) without time zone,
    policy_version character varying(128),
    warnings jsonb DEFAULT '[]'::jsonb NOT NULL,
    submodules jsonb DEFAULT '[]'::jsonb NOT NULL,
    lfs_digests jsonb DEFAULT '[]'::jsonb NOT NULL,
    token_expires_at timestamp(6) without time zone,
    expires_at timestamp(6) without time zone NOT NULL,
    finalized_at timestamp(6) without time zone,
    last_error text,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    project_source_binding_id bigint,
    source_provider_delivery_id bigint,
    superseded_by_source_fetch_id bigint,
    superseded_at timestamp(6) without time zone,
    CONSTRAINT source_fetches_attempts CHECK ((attempt_count >= 0)),
    CONSTRAINT source_fetches_lfs_array CHECK ((jsonb_typeof(lfs_digests) = 'array'::text)),
    CONSTRAINT source_fetches_policy_version CHECK (((policy_version IS NULL) OR ((char_length((policy_version)::text) >= 1) AND (char_length((policy_version)::text) <= 128)))),
    CONSTRAINT source_fetches_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text)),
    CONSTRAINT source_fetches_requested_commit CHECK (((requested_commit_sha)::text ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'::text)),
    CONSTRAINT source_fetches_resolved_commit CHECK (((resolved_commit_sha IS NULL) OR ((resolved_commit_sha)::text ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'::text))),
    CONSTRAINT source_fetches_snapshot_digest CHECK (((snapshot_sha256 IS NULL) OR ((snapshot_sha256)::text ~ '^sha256:[0-9a-f]{64}$'::text))),
    CONSTRAINT source_fetches_state CHECK (((state)::text = ANY ((ARRAY['authorized'::character varying, 'fetching'::character varying, 'complete'::character varying, 'failed'::character varying, 'expired'::character varying, 'canceled'::character varying])::text[]))),
    CONSTRAINT source_fetches_submodules_array CHECK ((jsonb_typeof(submodules) = 'array'::text)),
    CONSTRAINT source_fetches_tree CHECK (((tree_sha IS NULL) OR ((tree_sha)::text ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'::text))),
    CONSTRAINT source_fetches_warnings_array CHECK ((jsonb_typeof(warnings) = 'array'::text))
);

ALTER TABLE ONLY public.source_fetches FORCE ROW LEVEL SECURITY;


--
-- Name: source_fetches_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.source_fetches_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: source_fetches_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.source_fetches_id_seq OWNED BY public.source_fetches.id;


--
-- Name: source_provider_deliveries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.source_provider_deliveries (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    source_connection_id bigint NOT NULL,
    provider character varying(32) NOT NULL,
    external_delivery_id character varying(128) NOT NULL,
    event_type character varying(64) NOT NULL,
    action character varying(64),
    payload_digest character varying(71) NOT NULL,
    state character varying(32) DEFAULT 'received'::character varying NOT NULL,
    repository character varying(201),
    ref character varying(512),
    commit_sha character varying(64),
    base_commit_sha character varying(64),
    pull_request_number integer,
    forced boolean DEFAULT false NOT NULL,
    deleted boolean DEFAULT false NOT NULL,
    processed_at timestamp(6) without time zone,
    attempt_count integer DEFAULT 0 NOT NULL,
    processing_token character varying(128),
    processing_started_at timestamp(6) without time zone,
    last_error text,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT source_provider_deliveries_attempts CHECK ((attempt_count >= 0)),
    CONSTRAINT source_provider_deliveries_base_commit CHECK (((base_commit_sha IS NULL) OR ((base_commit_sha)::text ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'::text))),
    CONSTRAINT source_provider_deliveries_commit CHECK (((commit_sha IS NULL) OR ((commit_sha)::text ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'::text))),
    CONSTRAINT source_provider_deliveries_digest CHECK (((payload_digest)::text ~ '^sha256:[0-9a-f]{64}$'::text)),
    CONSTRAINT source_provider_deliveries_provider CHECK (((provider)::text = 'github'::text)),
    CONSTRAINT source_provider_deliveries_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text)),
    CONSTRAINT source_provider_deliveries_state CHECK (((state)::text = ANY ((ARRAY['received'::character varying, 'processing'::character varying, 'processed'::character varying, 'ignored'::character varying, 'failed'::character varying])::text[])))
);

ALTER TABLE ONLY public.source_provider_deliveries FORCE ROW LEVEL SECURITY;


--
-- Name: source_provider_deliveries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.source_provider_deliveries_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: source_provider_deliveries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.source_provider_deliveries_id_seq OWNED BY public.source_provider_deliveries.id;


--
-- Name: source_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.source_snapshots (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    project_id bigint NOT NULL,
    source_connection_id bigint,
    kind character varying NOT NULL,
    repository character varying,
    commit_sha character varying,
    digest character varying NOT NULL,
    object_ref character varying NOT NULL,
    size_bytes bigint NOT NULL,
    retention_until timestamp(6) without time zone NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT source_snapshots_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text)),
    CONSTRAINT source_snapshots_size CHECK ((size_bytes >= 0))
);

ALTER TABLE ONLY public.source_snapshots FORCE ROW LEVEL SECURITY;


--
-- Name: source_snapshots_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.source_snapshots_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: source_snapshots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.source_snapshots_id_seq OWNED BY public.source_snapshots.id;


--
-- Name: source_upload_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.source_upload_sessions (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    project_id bigint NOT NULL,
    created_by_account_id bigint NOT NULL,
    source_snapshot_id bigint,
    state character varying(32) DEFAULT 'authorized'::character varying NOT NULL,
    expected_archive_bytes bigint NOT NULL,
    expected_archive_sha256 character varying(71) NOT NULL,
    expected_parts integer NOT NULL,
    root_directory character varying(512) DEFAULT ''::character varying NOT NULL,
    excluded_count integer DEFAULT 0 NOT NULL,
    uploaded_parts jsonb DEFAULT '[]'::jsonb NOT NULL,
    finalize_attempts integer DEFAULT 0 NOT NULL,
    snapshot_sha256 character varying(71),
    manifest_sha256 character varying(71),
    archive_sha256 character varying(71),
    manifest_ref character varying,
    archive_ref character varying,
    signing_key_id character varying(128),
    last_error text,
    expires_at timestamp(6) without time zone NOT NULL,
    finalized_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT source_upload_sessions_archive_digest CHECK (((expected_archive_sha256)::text ~ '^sha256:[0-9a-f]{64}$'::text)),
    CONSTRAINT source_upload_sessions_bytes CHECK (((expected_archive_bytes >= 1) AND (expected_archive_bytes <= 1073741824))),
    CONSTRAINT source_upload_sessions_excluded CHECK ((excluded_count >= 0)),
    CONSTRAINT source_upload_sessions_part_capacity CHECK ((expected_archive_bytes <= ((expected_parts)::bigint * 16777216))),
    CONSTRAINT source_upload_sessions_parts CHECK (((expected_parts >= 1) AND (expected_parts <= 256))),
    CONSTRAINT source_upload_sessions_public_id_format CHECK (((public_id)::text ~ '^upl_[0-9a-f-]{36}$'::text)),
    CONSTRAINT source_upload_sessions_state CHECK (((state)::text = ANY ((ARRAY['authorized'::character varying, 'uploading'::character varying, 'finalizing'::character varying, 'complete'::character varying, 'failed'::character varying, 'expired'::character varying, 'canceled'::character varying])::text[]))),
    CONSTRAINT source_upload_sessions_uploaded_parts CHECK ((jsonb_typeof(uploaded_parts) = 'array'::text))
);

ALTER TABLE ONLY public.source_upload_sessions FORCE ROW LEVEL SECURITY;


--
-- Name: source_upload_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.source_upload_sessions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: source_upload_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.source_upload_sessions_id_seq OWNED BY public.source_upload_sessions.id;


--
-- Name: usage_ledger; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usage_ledger (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    meter_type character varying NOT NULL,
    quantity bigint NOT NULL,
    unit character varying NOT NULL,
    period_start timestamp(6) without time zone NOT NULL,
    period_end timestamp(6) without time zone NOT NULL,
    resource_public_id character varying NOT NULL,
    source_id character varying NOT NULL,
    source_epoch character varying NOT NULL,
    sequence bigint NOT NULL,
    correlation_id character varying NOT NULL,
    correction_of_public_id character varying,
    meter_attributes jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT usage_ledger_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text)),
    CONSTRAINT usage_nonzero CHECK ((quantity <> 0)),
    CONSTRAINT usage_period_order CHECK ((period_end > period_start))
);

ALTER TABLE ONLY public.usage_ledger FORCE ROW LEVEL SECURITY;


--
-- Name: usage_ledger_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.usage_ledger_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: usage_ledger_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.usage_ledger_id_seq OWNED BY public.usage_ledger.id;


--
-- Name: webhook_deliveries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_deliveries (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    webhook_id bigint NOT NULL,
    event_public_id character varying NOT NULL,
    attempt integer DEFAULT 1 NOT NULL,
    state character varying DEFAULT 'pending'::character varying NOT NULL,
    response_status integer,
    next_attempt_at timestamp(6) without time zone,
    completed_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT webhook_deliveries_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.webhook_deliveries FORCE ROW LEVEL SECURITY;


--
-- Name: webhook_deliveries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.webhook_deliveries_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: webhook_deliveries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.webhook_deliveries_id_seq OWNED BY public.webhook_deliveries.id;


--
-- Name: webhooks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhooks (
    id bigint NOT NULL,
    public_id character varying(64) NOT NULL,
    organization_id bigint NOT NULL,
    project_id bigint,
    url character varying NOT NULL,
    state character varying DEFAULT 'verification_pending'::character varying NOT NULL,
    event_types jsonb DEFAULT '[]'::jsonb NOT NULL,
    secret_digest character varying NOT NULL,
    signature_version integer DEFAULT 1 NOT NULL,
    verified_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL,
    CONSTRAINT webhooks_public_id_format CHECK (((public_id)::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text))
);

ALTER TABLE ONLY public.webhooks FORCE ROW LEVEL SECURITY;


--
-- Name: webhooks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.webhooks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: webhooks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.webhooks_id_seq OWNED BY public.webhooks.id;


--
-- Name: workflow_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_runs (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    workflow_id character varying NOT NULL,
    workflow_type character varying NOT NULL,
    resource_public_id character varying NOT NULL,
    state character varying DEFAULT 'accepted'::character varying NOT NULL,
    run_id character varying,
    conditions jsonb DEFAULT '[]'::jsonb NOT NULL,
    started_at timestamp(6) without time zone,
    completed_at timestamp(6) without time zone,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);

ALTER TABLE ONLY public.workflow_runs FORCE ROW LEVEL SECURITY;


--
-- Name: workflow_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.workflow_runs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: workflow_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.workflow_runs_id_seq OWNED BY public.workflow_runs.id;


--
-- Name: account_authentication_audit_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_authentication_audit_logs ALTER COLUMN id SET DEFAULT nextval('public.account_authentication_audit_logs_id_seq'::regclass);


--
-- Name: account_lockouts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_lockouts ALTER COLUMN id SET DEFAULT nextval('public.account_lockouts_id_seq'::regclass);


--
-- Name: account_login_change_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_login_change_keys ALTER COLUMN id SET DEFAULT nextval('public.account_login_change_keys_id_seq'::regclass);


--
-- Name: account_login_failures id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_login_failures ALTER COLUMN id SET DEFAULT nextval('public.account_login_failures_id_seq'::regclass);


--
-- Name: account_otp_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_otp_keys ALTER COLUMN id SET DEFAULT nextval('public.account_otp_keys_id_seq'::regclass);


--
-- Name: account_password_hashes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_password_hashes ALTER COLUMN id SET DEFAULT nextval('public.account_password_hashes_id_seq'::regclass);


--
-- Name: account_password_reset_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_password_reset_keys ALTER COLUMN id SET DEFAULT nextval('public.account_password_reset_keys_id_seq'::regclass);


--
-- Name: account_previous_password_hashes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_previous_password_hashes ALTER COLUMN id SET DEFAULT nextval('public.account_previous_password_hashes_id_seq'::regclass);


--
-- Name: account_remember_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_remember_keys ALTER COLUMN id SET DEFAULT nextval('public.account_remember_keys_id_seq'::regclass);


--
-- Name: account_verification_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_verification_keys ALTER COLUMN id SET DEFAULT nextval('public.account_verification_keys_id_seq'::regclass);


--
-- Name: account_webauthn_user_ids id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_webauthn_user_ids ALTER COLUMN id SET DEFAULT nextval('public.account_webauthn_user_ids_id_seq'::regclass);


--
-- Name: accounts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.accounts ALTER COLUMN id SET DEFAULT nextval('public.accounts_id_seq'::regclass);


--
-- Name: addon_backups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.addon_backups ALTER COLUMN id SET DEFAULT nextval('public.addon_backups_id_seq'::regclass);


--
-- Name: addons id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.addons ALTER COLUMN id SET DEFAULT nextval('public.addons_id_seq'::regclass);


--
-- Name: api_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys ALTER COLUMN id SET DEFAULT nextval('public.api_keys_id_seq'::regclass);


--
-- Name: attachments id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attachments ALTER COLUMN id SET DEFAULT nextval('public.attachments_id_seq'::regclass);


--
-- Name: attestations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attestations ALTER COLUMN id SET DEFAULT nextval('public.attestations_id_seq'::regclass);


--
-- Name: audit_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events ALTER COLUMN id SET DEFAULT nextval('public.audit_events_id_seq'::regclass);


--
-- Name: build_steps id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.build_steps ALTER COLUMN id SET DEFAULT nextval('public.build_steps_id_seq'::regclass);


--
-- Name: builds id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.builds ALTER COLUMN id SET DEFAULT nextval('public.builds_id_seq'::regclass);


--
-- Name: certificates id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificates ALTER COLUMN id SET DEFAULT nextval('public.certificates_id_seq'::regclass);


--
-- Name: credential_versions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credential_versions ALTER COLUMN id SET DEFAULT nextval('public.credential_versions_id_seq'::regclass);


--
-- Name: dead_letter_messages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dead_letter_messages ALTER COLUMN id SET DEFAULT nextval('public.dead_letter_messages_id_seq'::regclass);


--
-- Name: deployment_transitions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_transitions ALTER COLUMN id SET DEFAULT nextval('public.deployment_transitions_id_seq'::regclass);


--
-- Name: deployments id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployments ALTER COLUMN id SET DEFAULT nextval('public.deployments_id_seq'::regclass);


--
-- Name: dns_changes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dns_changes ALTER COLUMN id SET DEFAULT nextval('public.dns_changes_id_seq'::regclass);


--
-- Name: domains id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domains ALTER COLUMN id SET DEFAULT nextval('public.domains_id_seq'::regclass);


--
-- Name: edge_route_versions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edge_route_versions ALTER COLUMN id SET DEFAULT nextval('public.edge_route_versions_id_seq'::regclass);


--
-- Name: email_intents id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_intents ALTER COLUMN id SET DEFAULT nextval('public.email_intents_id_seq'::regclass);


--
-- Name: email_provider_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_provider_events ALTER COLUMN id SET DEFAULT nextval('public.email_provider_events_id_seq'::regclass);


--
-- Name: environments id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environments ALTER COLUMN id SET DEFAULT nextval('public.environments_id_seq'::regclass);


--
-- Name: idempotency_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idempotency_keys ALTER COLUMN id SET DEFAULT nextval('public.idempotency_keys_id_seq'::regclass);


--
-- Name: inbox_messages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inbox_messages ALTER COLUMN id SET DEFAULT nextval('public.inbox_messages_id_seq'::regclass);


--
-- Name: invitations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations ALTER COLUMN id SET DEFAULT nextval('public.invitations_id_seq'::regclass);


--
-- Name: memberships id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memberships ALTER COLUMN id SET DEFAULT nextval('public.memberships_id_seq'::regclass);


--
-- Name: oauth_clients id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_clients ALTER COLUMN id SET DEFAULT nextval('public.oauth_clients_id_seq'::regclass);


--
-- Name: operations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.operations ALTER COLUMN id SET DEFAULT nextval('public.operations_id_seq'::regclass);


--
-- Name: organizations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations ALTER COLUMN id SET DEFAULT nextval('public.organizations_id_seq'::regclass);


--
-- Name: outbox_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.outbox_events ALTER COLUMN id SET DEFAULT nextval('public.outbox_events_id_seq'::regclass);


--
-- Name: ownership_challenges id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ownership_challenges ALTER COLUMN id SET DEFAULT nextval('public.ownership_challenges_id_seq'::regclass);


--
-- Name: project_source_bindings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_source_bindings ALTER COLUMN id SET DEFAULT nextval('public.project_source_bindings_id_seq'::regclass);


--
-- Name: projects id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects ALTER COLUMN id SET DEFAULT nextval('public.projects_id_seq'::regclass);


--
-- Name: release_targets id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.release_targets ALTER COLUMN id SET DEFAULT nextval('public.release_targets_id_seq'::regclass);


--
-- Name: releases id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.releases ALTER COLUMN id SET DEFAULT nextval('public.releases_id_seq'::regclass);


--
-- Name: revisions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.revisions ALTER COLUMN id SET DEFAULT nextval('public.revisions_id_seq'::regclass);


--
-- Name: rollout_steps id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rollout_steps ALTER COLUMN id SET DEFAULT nextval('public.rollout_steps_id_seq'::regclass);


--
-- Name: schedules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schedules ALTER COLUMN id SET DEFAULT nextval('public.schedules_id_seq'::regclass);


--
-- Name: service_routes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_routes ALTER COLUMN id SET DEFAULT nextval('public.service_routes_id_seq'::regclass);


--
-- Name: services id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.services ALTER COLUMN id SET DEFAULT nextval('public.services_id_seq'::regclass);


--
-- Name: source_connections id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_connections ALTER COLUMN id SET DEFAULT nextval('public.source_connections_id_seq'::regclass);


--
-- Name: source_fetches id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_fetches ALTER COLUMN id SET DEFAULT nextval('public.source_fetches_id_seq'::regclass);


--
-- Name: source_provider_deliveries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_provider_deliveries ALTER COLUMN id SET DEFAULT nextval('public.source_provider_deliveries_id_seq'::regclass);


--
-- Name: source_snapshots id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_snapshots ALTER COLUMN id SET DEFAULT nextval('public.source_snapshots_id_seq'::regclass);


--
-- Name: source_upload_sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_upload_sessions ALTER COLUMN id SET DEFAULT nextval('public.source_upload_sessions_id_seq'::regclass);


--
-- Name: usage_ledger id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_ledger ALTER COLUMN id SET DEFAULT nextval('public.usage_ledger_id_seq'::regclass);


--
-- Name: webhook_deliveries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries ALTER COLUMN id SET DEFAULT nextval('public.webhook_deliveries_id_seq'::regclass);


--
-- Name: webhooks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhooks ALTER COLUMN id SET DEFAULT nextval('public.webhooks_id_seq'::regclass);


--
-- Name: workflow_runs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_runs ALTER COLUMN id SET DEFAULT nextval('public.workflow_runs_id_seq'::regclass);


--
-- Name: account_active_session_keys account_active_session_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_active_session_keys
    ADD CONSTRAINT account_active_session_keys_pkey PRIMARY KEY (account_id, session_id);


--
-- Name: account_authentication_audit_logs account_authentication_audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_authentication_audit_logs
    ADD CONSTRAINT account_authentication_audit_logs_pkey PRIMARY KEY (id);


--
-- Name: account_lockouts account_lockouts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_lockouts
    ADD CONSTRAINT account_lockouts_pkey PRIMARY KEY (id);


--
-- Name: account_login_change_keys account_login_change_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_login_change_keys
    ADD CONSTRAINT account_login_change_keys_pkey PRIMARY KEY (id);


--
-- Name: account_login_failures account_login_failures_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_login_failures
    ADD CONSTRAINT account_login_failures_pkey PRIMARY KEY (id);


--
-- Name: account_otp_keys account_otp_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_otp_keys
    ADD CONSTRAINT account_otp_keys_pkey PRIMARY KEY (id);


--
-- Name: account_password_hashes account_password_hashes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_password_hashes
    ADD CONSTRAINT account_password_hashes_pkey PRIMARY KEY (id);


--
-- Name: account_password_reset_keys account_password_reset_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_password_reset_keys
    ADD CONSTRAINT account_password_reset_keys_pkey PRIMARY KEY (id);


--
-- Name: account_previous_password_hashes account_previous_password_hashes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_previous_password_hashes
    ADD CONSTRAINT account_previous_password_hashes_pkey PRIMARY KEY (id);


--
-- Name: account_recovery_codes account_recovery_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_recovery_codes
    ADD CONSTRAINT account_recovery_codes_pkey PRIMARY KEY (id, code);


--
-- Name: account_remember_keys account_remember_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_remember_keys
    ADD CONSTRAINT account_remember_keys_pkey PRIMARY KEY (id);


--
-- Name: account_verification_keys account_verification_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_verification_keys
    ADD CONSTRAINT account_verification_keys_pkey PRIMARY KEY (id);


--
-- Name: account_webauthn_keys account_webauthn_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_webauthn_keys
    ADD CONSTRAINT account_webauthn_keys_pkey PRIMARY KEY (account_id, webauthn_id);


--
-- Name: account_webauthn_user_ids account_webauthn_user_ids_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_webauthn_user_ids
    ADD CONSTRAINT account_webauthn_user_ids_pkey PRIMARY KEY (id);


--
-- Name: accounts accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (id);


--
-- Name: addon_backups addon_backups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.addon_backups
    ADD CONSTRAINT addon_backups_pkey PRIMARY KEY (id);


--
-- Name: addons addons_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.addons
    ADD CONSTRAINT addons_pkey PRIMARY KEY (id);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: ar_internal_metadata ar_internal_metadata_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ar_internal_metadata
    ADD CONSTRAINT ar_internal_metadata_pkey PRIMARY KEY (key);


--
-- Name: attachments attachments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT attachments_pkey PRIMARY KEY (id);


--
-- Name: attestations attestations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attestations
    ADD CONSTRAINT attestations_pkey PRIMARY KEY (id);


--
-- Name: audit_events audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);


--
-- Name: build_steps build_steps_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.build_steps
    ADD CONSTRAINT build_steps_pkey PRIMARY KEY (id);


--
-- Name: builds builds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.builds
    ADD CONSTRAINT builds_pkey PRIMARY KEY (id);


--
-- Name: certificates certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_pkey PRIMARY KEY (id);


--
-- Name: credential_versions credential_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credential_versions
    ADD CONSTRAINT credential_versions_pkey PRIMARY KEY (id);


--
-- Name: dead_letter_messages dead_letter_messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dead_letter_messages
    ADD CONSTRAINT dead_letter_messages_pkey PRIMARY KEY (id);


--
-- Name: deployment_transitions deployment_transitions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_transitions
    ADD CONSTRAINT deployment_transitions_pkey PRIMARY KEY (id);


--
-- Name: deployments deployments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployments
    ADD CONSTRAINT deployments_pkey PRIMARY KEY (id);


--
-- Name: dns_changes dns_changes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dns_changes
    ADD CONSTRAINT dns_changes_pkey PRIMARY KEY (id);


--
-- Name: domains domains_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_pkey PRIMARY KEY (id);


--
-- Name: edge_route_versions edge_route_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edge_route_versions
    ADD CONSTRAINT edge_route_versions_pkey PRIMARY KEY (id);


--
-- Name: email_intents email_intents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_intents
    ADD CONSTRAINT email_intents_pkey PRIMARY KEY (id);


--
-- Name: email_provider_events email_provider_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_provider_events
    ADD CONSTRAINT email_provider_events_pkey PRIMARY KEY (id);


--
-- Name: environments environments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environments
    ADD CONSTRAINT environments_pkey PRIMARY KEY (id);


--
-- Name: idempotency_keys idempotency_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idempotency_keys
    ADD CONSTRAINT idempotency_keys_pkey PRIMARY KEY (id);


--
-- Name: inbox_messages inbox_messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inbox_messages
    ADD CONSTRAINT inbox_messages_pkey PRIMARY KEY (id);


--
-- Name: invitations invitations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT invitations_pkey PRIMARY KEY (id);


--
-- Name: memberships memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memberships
    ADD CONSTRAINT memberships_pkey PRIMARY KEY (id);


--
-- Name: oauth_clients oauth_clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT oauth_clients_pkey PRIMARY KEY (id);


--
-- Name: operations operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: outbox_events outbox_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.outbox_events
    ADD CONSTRAINT outbox_events_pkey PRIMARY KEY (id);


--
-- Name: ownership_challenges ownership_challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ownership_challenges
    ADD CONSTRAINT ownership_challenges_pkey PRIMARY KEY (id);


--
-- Name: project_source_bindings project_source_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_source_bindings
    ADD CONSTRAINT project_source_bindings_pkey PRIMARY KEY (id);


--
-- Name: projects projects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_pkey PRIMARY KEY (id);


--
-- Name: release_targets release_targets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.release_targets
    ADD CONSTRAINT release_targets_pkey PRIMARY KEY (id);


--
-- Name: releases releases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.releases
    ADD CONSTRAINT releases_pkey PRIMARY KEY (id);


--
-- Name: revisions revisions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.revisions
    ADD CONSTRAINT revisions_pkey PRIMARY KEY (id);


--
-- Name: rollout_steps rollout_steps_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rollout_steps
    ADD CONSTRAINT rollout_steps_pkey PRIMARY KEY (id);


--
-- Name: schedules schedules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schedules
    ADD CONSTRAINT schedules_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: service_routes service_routes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_routes
    ADD CONSTRAINT service_routes_pkey PRIMARY KEY (id);


--
-- Name: services services_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_pkey PRIMARY KEY (id);


--
-- Name: source_connections source_connections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_connections
    ADD CONSTRAINT source_connections_pkey PRIMARY KEY (id);


--
-- Name: source_fetches source_fetches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_fetches
    ADD CONSTRAINT source_fetches_pkey PRIMARY KEY (id);


--
-- Name: source_provider_deliveries source_provider_deliveries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_provider_deliveries
    ADD CONSTRAINT source_provider_deliveries_pkey PRIMARY KEY (id);


--
-- Name: source_snapshots source_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_snapshots
    ADD CONSTRAINT source_snapshots_pkey PRIMARY KEY (id);


--
-- Name: source_upload_sessions source_upload_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_upload_sessions
    ADD CONSTRAINT source_upload_sessions_pkey PRIMARY KEY (id);


--
-- Name: usage_ledger usage_ledger_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_ledger
    ADD CONSTRAINT usage_ledger_pkey PRIMARY KEY (id);


--
-- Name: webhook_deliveries webhook_deliveries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (id);


--
-- Name: webhooks webhooks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhooks
    ADD CONSTRAINT webhooks_pkey PRIMARY KEY (id);


--
-- Name: workflow_runs workflow_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_runs
    ADD CONSTRAINT workflow_runs_pkey PRIMARY KEY (id);


--
-- Name: audit_resource_timeline; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_resource_timeline ON public.audit_events USING btree (resource_type, resource_public_id, occurred_at);


--
-- Name: dead_letter_consumer_event; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX dead_letter_consumer_event ON public.dead_letter_messages USING btree (consumer, event_public_id);


--
-- Name: email_intent_delivery_queue; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX email_intent_delivery_queue ON public.email_intents USING btree (state, next_attempt_at, locked_at);


--
-- Name: idempotency_scope_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idempotency_scope_unique ON public.idempotency_keys USING btree (organization_id, principal_public_id, http_method, normalized_route, key_digest);


--
-- Name: idx_on_organization_id_resource_type_resource_publi_d374b329c8; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_on_organization_id_resource_type_resource_publi_d374b329c8 ON public.operations USING btree (organization_id, resource_type, resource_public_id);


--
-- Name: inbox_consumer_event; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX inbox_consumer_event ON public.inbox_messages USING btree (consumer, event_public_id);


--
-- Name: index_account_active_session_keys_on_account_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_account_active_session_keys_on_account_id ON public.account_active_session_keys USING btree (account_id);


--
-- Name: index_account_authentication_audit_logs_on_account_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_account_authentication_audit_logs_on_account_id ON public.account_authentication_audit_logs USING btree (account_id);


--
-- Name: index_account_authentication_audit_logs_on_account_id_and_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_account_authentication_audit_logs_on_account_id_and_at ON public.account_authentication_audit_logs USING btree (account_id, at);


--
-- Name: index_account_authentication_audit_logs_on_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_account_authentication_audit_logs_on_at ON public.account_authentication_audit_logs USING btree (at);


--
-- Name: index_account_previous_password_hashes_on_account_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_account_previous_password_hashes_on_account_id ON public.account_previous_password_hashes USING btree (account_id);


--
-- Name: index_account_webauthn_keys_on_account_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_account_webauthn_keys_on_account_id ON public.account_webauthn_keys USING btree (account_id);


--
-- Name: index_accounts_on_email; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_accounts_on_email ON public.accounts USING btree (email) WHERE (status = ANY (ARRAY[1, 2]));


--
-- Name: index_accounts_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_accounts_on_public_id ON public.accounts USING btree (public_id);


--
-- Name: index_addon_backups_on_addon_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_addon_backups_on_addon_id ON public.addon_backups USING btree (addon_id);


--
-- Name: index_addon_backups_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_addon_backups_on_organization_id ON public.addon_backups USING btree (organization_id);


--
-- Name: index_addon_backups_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_addon_backups_on_public_id ON public.addon_backups USING btree (public_id);


--
-- Name: index_addons_on_engine_and_provider_resource_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_addons_on_engine_and_provider_resource_id ON public.addons USING btree (engine, provider_resource_id) WHERE (provider_resource_id IS NOT NULL);


--
-- Name: index_addons_on_environment_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_addons_on_environment_id ON public.addons USING btree (environment_id);


--
-- Name: index_addons_on_environment_id_and_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_addons_on_environment_id_and_name ON public.addons USING btree (environment_id, name);


--
-- Name: index_addons_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_addons_on_organization_id ON public.addons USING btree (organization_id);


--
-- Name: index_addons_on_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_addons_on_project_id ON public.addons USING btree (project_id);


--
-- Name: index_addons_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_addons_on_public_id ON public.addons USING btree (public_id);


--
-- Name: index_api_keys_on_account_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_api_keys_on_account_id ON public.api_keys USING btree (account_id);


--
-- Name: index_api_keys_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_api_keys_on_organization_id ON public.api_keys USING btree (organization_id);


--
-- Name: index_api_keys_on_prefix; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_api_keys_on_prefix ON public.api_keys USING btree (prefix);


--
-- Name: index_api_keys_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_api_keys_on_public_id ON public.api_keys USING btree (public_id);


--
-- Name: index_api_keys_on_secret_digest; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_api_keys_on_secret_digest ON public.api_keys USING btree (secret_digest);


--
-- Name: index_attachments_on_addon_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_attachments_on_addon_id ON public.attachments USING btree (addon_id);


--
-- Name: index_attachments_on_environment_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_attachments_on_environment_id ON public.attachments USING btree (environment_id);


--
-- Name: index_attachments_on_environment_id_and_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_attachments_on_environment_id_and_name ON public.attachments USING btree (environment_id, name);


--
-- Name: index_attachments_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_attachments_on_organization_id ON public.attachments USING btree (organization_id);


--
-- Name: index_attachments_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_attachments_on_public_id ON public.attachments USING btree (public_id);


--
-- Name: index_attachments_on_service_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_attachments_on_service_id ON public.attachments USING btree (service_id);


--
-- Name: index_attestations_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_attestations_on_organization_id ON public.attestations USING btree (organization_id);


--
-- Name: index_attestations_on_revision_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_attestations_on_revision_id ON public.attestations USING btree (revision_id);


--
-- Name: index_attestations_on_revision_id_and_kind; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_attestations_on_revision_id_and_kind ON public.attestations USING btree (revision_id, kind);


--
-- Name: index_audit_events_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_audit_events_on_organization_id ON public.audit_events USING btree (organization_id);


--
-- Name: index_audit_events_on_organization_id_and_occurred_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_audit_events_on_organization_id_and_occurred_at ON public.audit_events USING btree (organization_id, occurred_at);


--
-- Name: index_audit_events_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_audit_events_on_public_id ON public.audit_events USING btree (public_id);


--
-- Name: index_build_steps_on_build_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_build_steps_on_build_id ON public.build_steps USING btree (build_id);


--
-- Name: index_build_steps_on_build_id_and_position; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_build_steps_on_build_id_and_position ON public.build_steps USING btree (build_id, "position");


--
-- Name: index_build_steps_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_build_steps_on_organization_id ON public.build_steps USING btree (organization_id);


--
-- Name: index_builds_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_builds_on_organization_id ON public.builds USING btree (organization_id);


--
-- Name: index_builds_on_organization_id_and_definition_digest; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_builds_on_organization_id_and_definition_digest ON public.builds USING btree (organization_id, definition_digest);


--
-- Name: index_builds_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_builds_on_public_id ON public.builds USING btree (public_id);


--
-- Name: index_builds_on_source_snapshot_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_builds_on_source_snapshot_id ON public.builds USING btree (source_snapshot_id);


--
-- Name: index_certificates_on_domain_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_certificates_on_domain_id ON public.certificates USING btree (domain_id);


--
-- Name: index_certificates_on_fingerprint; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_certificates_on_fingerprint ON public.certificates USING btree (fingerprint) WHERE (fingerprint IS NOT NULL);


--
-- Name: index_certificates_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_certificates_on_organization_id ON public.certificates USING btree (organization_id);


--
-- Name: index_certificates_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_certificates_on_public_id ON public.certificates USING btree (public_id);


--
-- Name: index_credential_versions_on_addon_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_credential_versions_on_addon_id ON public.credential_versions USING btree (addon_id);


--
-- Name: index_credential_versions_on_addon_id_and_version; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_credential_versions_on_addon_id_and_version ON public.credential_versions USING btree (addon_id, version);


--
-- Name: index_credential_versions_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_credential_versions_on_organization_id ON public.credential_versions USING btree (organization_id);


--
-- Name: index_dead_letter_messages_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_dead_letter_messages_on_organization_id ON public.dead_letter_messages USING btree (organization_id);


--
-- Name: index_dead_letter_messages_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_dead_letter_messages_on_public_id ON public.dead_letter_messages USING btree (public_id);


--
-- Name: index_deployment_transitions_on_deployment_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_deployment_transitions_on_deployment_id ON public.deployment_transitions USING btree (deployment_id);


--
-- Name: index_deployment_transitions_on_deployment_id_and_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_deployment_transitions_on_deployment_id_and_created_at ON public.deployment_transitions USING btree (deployment_id, created_at);


--
-- Name: index_deployment_transitions_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_deployment_transitions_on_organization_id ON public.deployment_transitions USING btree (organization_id);


--
-- Name: index_deployments_on_environment_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_deployments_on_environment_id ON public.deployments USING btree (environment_id);


--
-- Name: index_deployments_on_operation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_deployments_on_operation_id ON public.deployments USING btree (operation_id);


--
-- Name: index_deployments_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_deployments_on_organization_id ON public.deployments USING btree (organization_id);


--
-- Name: index_deployments_on_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_deployments_on_project_id ON public.deployments USING btree (project_id);


--
-- Name: index_deployments_on_project_id_and_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_deployments_on_project_id_and_created_at ON public.deployments USING btree (project_id, created_at);


--
-- Name: index_deployments_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_deployments_on_public_id ON public.deployments USING btree (public_id);


--
-- Name: index_deployments_on_revision_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_deployments_on_revision_id ON public.deployments USING btree (revision_id);


--
-- Name: index_deployments_on_source_snapshot_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_deployments_on_source_snapshot_id ON public.deployments USING btree (source_snapshot_id);


--
-- Name: index_dns_changes_on_domain_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_dns_changes_on_domain_id ON public.dns_changes USING btree (domain_id);


--
-- Name: index_dns_changes_on_operation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_dns_changes_on_operation_id ON public.dns_changes USING btree (operation_id);


--
-- Name: index_dns_changes_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_dns_changes_on_organization_id ON public.dns_changes USING btree (organization_id);


--
-- Name: index_domains_on_environment_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_domains_on_environment_id ON public.domains USING btree (environment_id);


--
-- Name: index_domains_on_hostname; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_domains_on_hostname ON public.domains USING btree (hostname) WHERE ((state)::text <> ALL ((ARRAY['released'::character varying, 'expired'::character varying])::text[]));


--
-- Name: index_domains_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_domains_on_organization_id ON public.domains USING btree (organization_id);


--
-- Name: index_domains_on_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_domains_on_project_id ON public.domains USING btree (project_id);


--
-- Name: index_domains_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_domains_on_public_id ON public.domains USING btree (public_id);


--
-- Name: index_domains_on_service_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_domains_on_service_id ON public.domains USING btree (service_id);


--
-- Name: index_edge_route_versions_on_domain_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_edge_route_versions_on_domain_id ON public.edge_route_versions USING btree (domain_id);


--
-- Name: index_edge_route_versions_on_edge_generation_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_edge_route_versions_on_edge_generation_public_id ON public.edge_route_versions USING btree (edge_generation_public_id);


--
-- Name: index_edge_route_versions_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_edge_route_versions_on_organization_id ON public.edge_route_versions USING btree (organization_id);


--
-- Name: index_edge_route_versions_on_release_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_edge_route_versions_on_release_id ON public.edge_route_versions USING btree (release_id);


--
-- Name: index_email_intents_on_account_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_email_intents_on_account_id ON public.email_intents USING btree (account_id);


--
-- Name: index_email_intents_on_idempotency_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_email_intents_on_idempotency_key ON public.email_intents USING btree (idempotency_key);


--
-- Name: index_email_intents_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_email_intents_on_organization_id ON public.email_intents USING btree (organization_id);


--
-- Name: index_email_intents_on_provider_message_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_email_intents_on_provider_message_id ON public.email_intents USING btree (provider_message_id) WHERE (provider_message_id IS NOT NULL);


--
-- Name: index_email_intents_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_email_intents_on_public_id ON public.email_intents USING btree (public_id);


--
-- Name: index_email_intents_on_state_and_next_attempt_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_email_intents_on_state_and_next_attempt_at ON public.email_intents USING btree (state, next_attempt_at);


--
-- Name: index_email_provider_events_on_provider_event_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_email_provider_events_on_provider_event_id ON public.email_provider_events USING btree (provider_event_id);


--
-- Name: index_email_provider_events_on_provider_message_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_email_provider_events_on_provider_message_id ON public.email_provider_events USING btree (provider_message_id);


--
-- Name: index_environments_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_environments_on_organization_id ON public.environments USING btree (organization_id);


--
-- Name: index_environments_on_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_environments_on_project_id ON public.environments USING btree (project_id);


--
-- Name: index_environments_on_project_id_and_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_environments_on_project_id_and_slug ON public.environments USING btree (project_id, slug);


--
-- Name: index_environments_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_environments_on_public_id ON public.environments USING btree (public_id);


--
-- Name: index_idempotency_keys_on_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_idempotency_keys_on_expires_at ON public.idempotency_keys USING btree (expires_at);


--
-- Name: index_idempotency_keys_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_idempotency_keys_on_organization_id ON public.idempotency_keys USING btree (organization_id);


--
-- Name: index_inbox_messages_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_inbox_messages_on_organization_id ON public.inbox_messages USING btree (organization_id);


--
-- Name: index_inbox_messages_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_inbox_messages_on_public_id ON public.inbox_messages USING btree (public_id);


--
-- Name: index_inbox_messages_on_state_and_first_received_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_inbox_messages_on_state_and_first_received_at ON public.inbox_messages USING btree (state, first_received_at);


--
-- Name: index_invitations_on_inviter_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_invitations_on_inviter_id ON public.invitations USING btree (inviter_id);


--
-- Name: index_invitations_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_invitations_on_organization_id ON public.invitations USING btree (organization_id);


--
-- Name: index_invitations_on_organization_id_and_email; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_invitations_on_organization_id_and_email ON public.invitations USING btree (organization_id, email) WHERE ((accepted_at IS NULL) AND (revoked_at IS NULL));


--
-- Name: index_invitations_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_invitations_on_public_id ON public.invitations USING btree (public_id);


--
-- Name: index_invitations_on_token_digest; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_invitations_on_token_digest ON public.invitations USING btree (token_digest);


--
-- Name: index_memberships_on_account_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_memberships_on_account_id ON public.memberships USING btree (account_id);


--
-- Name: index_memberships_on_account_id_and_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_memberships_on_account_id_and_organization_id ON public.memberships USING btree (account_id, organization_id);


--
-- Name: index_memberships_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_memberships_on_organization_id ON public.memberships USING btree (organization_id);


--
-- Name: index_memberships_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_memberships_on_public_id ON public.memberships USING btree (public_id);


--
-- Name: index_oauth_clients_on_client_digest; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_oauth_clients_on_client_digest ON public.oauth_clients USING btree (client_digest);


--
-- Name: index_oauth_clients_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_oauth_clients_on_organization_id ON public.oauth_clients USING btree (organization_id);


--
-- Name: index_oauth_clients_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_oauth_clients_on_public_id ON public.oauth_clients USING btree (public_id);


--
-- Name: index_operations_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_operations_on_organization_id ON public.operations USING btree (organization_id);


--
-- Name: index_operations_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_operations_on_public_id ON public.operations USING btree (public_id);


--
-- Name: index_operations_on_workflow_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_operations_on_workflow_id ON public.operations USING btree (workflow_id) WHERE (workflow_id IS NOT NULL);


--
-- Name: index_organizations_on_created_by_account_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_organizations_on_created_by_account_id ON public.organizations USING btree (created_by_account_id);


--
-- Name: index_organizations_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_organizations_on_public_id ON public.organizations USING btree (public_id);


--
-- Name: index_organizations_on_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_organizations_on_slug ON public.organizations USING btree (slug);


--
-- Name: index_outbox_events_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_outbox_events_on_organization_id ON public.outbox_events USING btree (organization_id);


--
-- Name: index_outbox_events_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_outbox_events_on_public_id ON public.outbox_events USING btree (public_id);


--
-- Name: index_ownership_challenges_on_domain_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ownership_challenges_on_domain_id ON public.ownership_challenges USING btree (domain_id);


--
-- Name: index_ownership_challenges_on_domain_id_and_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ownership_challenges_on_domain_id_and_expires_at ON public.ownership_challenges USING btree (domain_id, expires_at);


--
-- Name: index_ownership_challenges_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_ownership_challenges_on_organization_id ON public.ownership_challenges USING btree (organization_id);


--
-- Name: index_project_source_bindings_on_created_by_account_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_project_source_bindings_on_created_by_account_id ON public.project_source_bindings USING btree (created_by_account_id);


--
-- Name: index_project_source_bindings_on_current_source_fetch_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_project_source_bindings_on_current_source_fetch_id ON public.project_source_bindings USING btree (current_source_fetch_id);


--
-- Name: index_project_source_bindings_on_last_provider_delivery_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_project_source_bindings_on_last_provider_delivery_id ON public.project_source_bindings USING btree (last_provider_delivery_id);


--
-- Name: index_project_source_bindings_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_project_source_bindings_on_organization_id ON public.project_source_bindings USING btree (organization_id);


--
-- Name: index_project_source_bindings_on_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_project_source_bindings_on_project_id ON public.project_source_bindings USING btree (project_id);


--
-- Name: index_project_source_bindings_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_project_source_bindings_on_public_id ON public.project_source_bindings USING btree (public_id);


--
-- Name: index_project_source_bindings_on_source_connection_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_project_source_bindings_on_source_connection_id ON public.project_source_bindings USING btree (source_connection_id);


--
-- Name: index_projects_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_projects_on_organization_id ON public.projects USING btree (organization_id);


--
-- Name: index_projects_on_organization_id_and_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_projects_on_organization_id_and_slug ON public.projects USING btree (organization_id, slug);


--
-- Name: index_projects_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_projects_on_public_id ON public.projects USING btree (public_id);


--
-- Name: index_release_targets_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_release_targets_on_organization_id ON public.release_targets USING btree (organization_id);


--
-- Name: index_release_targets_on_release_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_release_targets_on_release_id ON public.release_targets USING btree (release_id);


--
-- Name: index_release_targets_on_release_id_and_cell_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_release_targets_on_release_id_and_cell_public_id ON public.release_targets USING btree (release_id, cell_public_id);


--
-- Name: index_releases_on_deployment_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_releases_on_deployment_id ON public.releases USING btree (deployment_id);


--
-- Name: index_releases_on_environment_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_releases_on_environment_id ON public.releases USING btree (environment_id);


--
-- Name: index_releases_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_releases_on_organization_id ON public.releases USING btree (organization_id);


--
-- Name: index_releases_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_releases_on_public_id ON public.releases USING btree (public_id);


--
-- Name: index_releases_on_revision_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_releases_on_revision_id ON public.releases USING btree (revision_id);


--
-- Name: index_releases_on_service_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_releases_on_service_id ON public.releases USING btree (service_id);


--
-- Name: index_revisions_on_build_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_revisions_on_build_id ON public.revisions USING btree (build_id);


--
-- Name: index_revisions_on_image_digest; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_revisions_on_image_digest ON public.revisions USING btree (image_digest);


--
-- Name: index_revisions_on_manifest_digest; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_revisions_on_manifest_digest ON public.revisions USING btree (manifest_digest);


--
-- Name: index_revisions_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_revisions_on_organization_id ON public.revisions USING btree (organization_id);


--
-- Name: index_revisions_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_revisions_on_public_id ON public.revisions USING btree (public_id);


--
-- Name: index_revisions_on_service_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_revisions_on_service_id ON public.revisions USING btree (service_id);


--
-- Name: index_rollout_steps_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_rollout_steps_on_organization_id ON public.rollout_steps USING btree (organization_id);


--
-- Name: index_rollout_steps_on_release_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_rollout_steps_on_release_id ON public.rollout_steps USING btree (release_id);


--
-- Name: index_rollout_steps_on_release_id_and_position; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_rollout_steps_on_release_id_and_position ON public.rollout_steps USING btree (release_id, "position");


--
-- Name: index_schedules_on_environment_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_schedules_on_environment_id ON public.schedules USING btree (environment_id);


--
-- Name: index_schedules_on_environment_id_and_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_schedules_on_environment_id_and_name ON public.schedules USING btree (environment_id, name);


--
-- Name: index_schedules_on_next_run_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_schedules_on_next_run_at ON public.schedules USING btree (next_run_at) WHERE (enabled = true);


--
-- Name: index_schedules_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_schedules_on_organization_id ON public.schedules USING btree (organization_id);


--
-- Name: index_schedules_on_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_schedules_on_project_id ON public.schedules USING btree (project_id);


--
-- Name: index_schedules_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_schedules_on_public_id ON public.schedules USING btree (public_id);


--
-- Name: index_service_routes_on_environment_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_service_routes_on_environment_id ON public.service_routes USING btree (environment_id);


--
-- Name: index_service_routes_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_service_routes_on_organization_id ON public.service_routes USING btree (organization_id);


--
-- Name: index_service_routes_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_service_routes_on_public_id ON public.service_routes USING btree (public_id);


--
-- Name: index_service_routes_on_service_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_service_routes_on_service_id ON public.service_routes USING btree (service_id);


--
-- Name: index_services_on_current_release_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_services_on_current_release_id ON public.services USING btree (current_release_id);


--
-- Name: index_services_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_services_on_organization_id ON public.services USING btree (organization_id);


--
-- Name: index_services_on_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_services_on_project_id ON public.services USING btree (project_id);


--
-- Name: index_services_on_project_id_and_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_services_on_project_id_and_slug ON public.services USING btree (project_id, slug);


--
-- Name: index_services_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_services_on_public_id ON public.services USING btree (public_id);


--
-- Name: index_source_connections_on_connected_by_account_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_connections_on_connected_by_account_id ON public.source_connections USING btree (connected_by_account_id);


--
-- Name: index_source_connections_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_connections_on_organization_id ON public.source_connections USING btree (organization_id);


--
-- Name: index_source_connections_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_source_connections_on_public_id ON public.source_connections USING btree (public_id);


--
-- Name: index_source_fetches_on_created_by_account_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_fetches_on_created_by_account_id ON public.source_fetches USING btree (created_by_account_id);


--
-- Name: index_source_fetches_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_fetches_on_organization_id ON public.source_fetches USING btree (organization_id);


--
-- Name: index_source_fetches_on_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_fetches_on_project_id ON public.source_fetches USING btree (project_id);


--
-- Name: index_source_fetches_on_project_source_binding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_fetches_on_project_source_binding_id ON public.source_fetches USING btree (project_source_binding_id);


--
-- Name: index_source_fetches_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_source_fetches_on_public_id ON public.source_fetches USING btree (public_id);


--
-- Name: index_source_fetches_on_source_connection_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_fetches_on_source_connection_id ON public.source_fetches USING btree (source_connection_id);


--
-- Name: index_source_fetches_on_source_provider_delivery_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_fetches_on_source_provider_delivery_id ON public.source_fetches USING btree (source_provider_delivery_id);


--
-- Name: index_source_fetches_on_source_snapshot_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_fetches_on_source_snapshot_id ON public.source_fetches USING btree (source_snapshot_id);


--
-- Name: index_source_fetches_on_superseded_by_source_fetch_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_fetches_on_superseded_by_source_fetch_id ON public.source_fetches USING btree (superseded_by_source_fetch_id);


--
-- Name: index_source_provider_deliveries_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_provider_deliveries_on_organization_id ON public.source_provider_deliveries USING btree (organization_id);


--
-- Name: index_source_provider_deliveries_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_source_provider_deliveries_on_public_id ON public.source_provider_deliveries USING btree (public_id);


--
-- Name: index_source_provider_deliveries_on_source_connection_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_provider_deliveries_on_source_connection_id ON public.source_provider_deliveries USING btree (source_connection_id);


--
-- Name: index_source_snapshots_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_snapshots_on_organization_id ON public.source_snapshots USING btree (organization_id);


--
-- Name: index_source_snapshots_on_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_snapshots_on_project_id ON public.source_snapshots USING btree (project_id);


--
-- Name: index_source_snapshots_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_source_snapshots_on_public_id ON public.source_snapshots USING btree (public_id);


--
-- Name: index_source_snapshots_on_source_connection_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_snapshots_on_source_connection_id ON public.source_snapshots USING btree (source_connection_id);


--
-- Name: index_source_upload_sessions_on_created_by_account_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_upload_sessions_on_created_by_account_id ON public.source_upload_sessions USING btree (created_by_account_id);


--
-- Name: index_source_upload_sessions_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_upload_sessions_on_organization_id ON public.source_upload_sessions USING btree (organization_id);


--
-- Name: index_source_upload_sessions_on_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_upload_sessions_on_project_id ON public.source_upload_sessions USING btree (project_id);


--
-- Name: index_source_upload_sessions_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_source_upload_sessions_on_public_id ON public.source_upload_sessions USING btree (public_id);


--
-- Name: index_source_upload_sessions_on_source_snapshot_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_upload_sessions_on_source_snapshot_id ON public.source_upload_sessions USING btree (source_snapshot_id);


--
-- Name: index_source_upload_sessions_on_state_and_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_source_upload_sessions_on_state_and_expires_at ON public.source_upload_sessions USING btree (state, expires_at);


--
-- Name: index_usage_ledger_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_usage_ledger_on_organization_id ON public.usage_ledger USING btree (organization_id);


--
-- Name: index_usage_ledger_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_usage_ledger_on_public_id ON public.usage_ledger USING btree (public_id);


--
-- Name: index_webhook_deliveries_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_webhook_deliveries_on_organization_id ON public.webhook_deliveries USING btree (organization_id);


--
-- Name: index_webhook_deliveries_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_webhook_deliveries_on_public_id ON public.webhook_deliveries USING btree (public_id);


--
-- Name: index_webhook_deliveries_on_webhook_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_webhook_deliveries_on_webhook_id ON public.webhook_deliveries USING btree (webhook_id);


--
-- Name: index_webhooks_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_webhooks_on_organization_id ON public.webhooks USING btree (organization_id);


--
-- Name: index_webhooks_on_project_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_webhooks_on_project_id ON public.webhooks USING btree (project_id);


--
-- Name: index_webhooks_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_webhooks_on_public_id ON public.webhooks USING btree (public_id);


--
-- Name: index_workflow_runs_on_organization_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_workflow_runs_on_organization_id ON public.workflow_runs USING btree (organization_id);


--
-- Name: index_workflow_runs_on_workflow_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_workflow_runs_on_workflow_id ON public.workflow_runs USING btree (workflow_id);


--
-- Name: outbox_delivery_queue; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX outbox_delivery_queue ON public.outbox_events USING btree (published_at, discarded_at, next_attempt_at, occurred_at);


--
-- Name: outbox_unpublished_age; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX outbox_unpublished_age ON public.outbox_events USING btree (published_at, occurred_at);


--
-- Name: project_source_provider_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX project_source_provider_lookup ON public.project_source_bindings USING btree (source_connection_id, repository, automatic_deployments);


--
-- Name: releases_monotonic_generation; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX releases_monotonic_generation ON public.releases USING btree (service_id, environment_id, generation);


--
-- Name: service_routes_unique_match; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX service_routes_unique_match ON public.service_routes USING btree (environment_id, hostname, path_prefix);


--
-- Name: source_connections_global_provider_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX source_connections_global_provider_identity ON public.source_connections USING btree (provider, installation_external_id);


--
-- Name: source_connections_provider_identity; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX source_connections_provider_identity ON public.source_connections USING btree (organization_id, provider, installation_external_id);


--
-- Name: source_fetch_expiry_queue; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX source_fetch_expiry_queue ON public.source_fetches USING btree (state, expires_at);


--
-- Name: source_fetch_provider_commit; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX source_fetch_provider_commit ON public.source_fetches USING btree (source_connection_id, repository, requested_commit_sha);


--
-- Name: source_fetch_provider_effect; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX source_fetch_provider_effect ON public.source_fetches USING btree (project_source_binding_id, source_provider_delivery_id) WHERE ((project_source_binding_id IS NOT NULL) AND (source_provider_delivery_id IS NOT NULL));


--
-- Name: source_provider_delivery_dedupe; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX source_provider_delivery_dedupe ON public.source_provider_deliveries USING btree (provider, external_delivery_id);


--
-- Name: source_provider_delivery_timeline; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX source_provider_delivery_timeline ON public.source_provider_deliveries USING btree (source_connection_id, repository, event_type, created_at);


--
-- Name: source_snapshots_project_digest; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX source_snapshots_project_digest ON public.source_snapshots USING btree (organization_id, project_id, digest);


--
-- Name: usage_period_meter; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX usage_period_meter ON public.usage_ledger USING btree (organization_id, period_start, meter_type);


--
-- Name: usage_source_sequence; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX usage_source_sequence ON public.usage_ledger USING btree (source_id, source_epoch, sequence);


--
-- Name: webhook_delivery_attempt; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX webhook_delivery_attempt ON public.webhook_deliveries USING btree (webhook_id, event_public_id, attempt);


--
-- Name: audit_events audit_events_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER audit_events_append_only BEFORE DELETE OR UPDATE ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.lrail_block_mutation();


--
-- Name: deployment_transitions deployment_transitions_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER deployment_transitions_append_only BEFORE DELETE OR UPDATE ON public.deployment_transitions FOR EACH ROW EXECUTE FUNCTION public.lrail_block_mutation();


--
-- Name: memberships memberships_owner_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER memberships_owner_guard BEFORE DELETE OR UPDATE ON public.memberships FOR EACH ROW EXECUTE FUNCTION public.lrail_membership_owner_guard();


--
-- Name: usage_ledger usage_ledger_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER usage_ledger_append_only BEFORE DELETE OR UPDATE ON public.usage_ledger FOR EACH ROW EXECUTE FUNCTION public.lrail_block_mutation();


--
-- Name: deployments fk_rails_009fd21147; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployments
    ADD CONSTRAINT fk_rails_009fd21147 FOREIGN KEY (environment_id) REFERENCES public.environments(id);


--
-- Name: release_targets fk_rails_09f7a8bb0c; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.release_targets
    ADD CONSTRAINT fk_rails_09f7a8bb0c FOREIGN KEY (release_id) REFERENCES public.releases(id) ON DELETE CASCADE;


--
-- Name: release_targets fk_rails_0c22d8b725; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.release_targets
    ADD CONSTRAINT fk_rails_0c22d8b725 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: source_connections fk_rails_0c8d2f6962; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_connections
    ADD CONSTRAINT fk_rails_0c8d2f6962 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: invitations fk_rails_0fe4c14f0e; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT fk_rails_0fe4c14f0e FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: domains fk_rails_10e43d0096; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT fk_rails_10e43d0096 FOREIGN KEY (project_id) REFERENCES public.projects(id);


--
-- Name: attachments fk_rails_12758c21e9; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT fk_rails_12758c21e9 FOREIGN KEY (service_id) REFERENCES public.services(id) ON DELETE CASCADE;


--
-- Name: project_source_bindings fk_rails_12dd1a7a77; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_source_bindings
    ADD CONSTRAINT fk_rails_12dd1a7a77 FOREIGN KEY (source_connection_id) REFERENCES public.source_connections(id) ON DELETE RESTRICT;


--
-- Name: certificates fk_rails_13b0a6586c; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT fk_rails_13b0a6586c FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;


--
-- Name: environments fk_rails_14050e5615; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environments
    ADD CONSTRAINT fk_rails_14050e5615 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: idempotency_keys fk_rails_149452d765; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idempotency_keys
    ADD CONSTRAINT fk_rails_149452d765 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: source_fetches fk_rails_16d5af904e; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_fetches
    ADD CONSTRAINT fk_rails_16d5af904e FOREIGN KEY (superseded_by_source_fetch_id) REFERENCES public.source_fetches(id) ON DELETE RESTRICT;


--
-- Name: domains fk_rails_182f1e5df5; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT fk_rails_182f1e5df5 FOREIGN KEY (environment_id) REFERENCES public.environments(id);


--
-- Name: account_login_change_keys fk_rails_18962144a4; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_login_change_keys
    ADD CONSTRAINT fk_rails_18962144a4 FOREIGN KEY (id) REFERENCES public.accounts(id);


--
-- Name: edge_route_versions fk_rails_1f967ccb7d; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edge_route_versions
    ADD CONSTRAINT fk_rails_1f967ccb7d FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: source_upload_sessions fk_rails_21e1d6ee50; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_upload_sessions
    ADD CONSTRAINT fk_rails_21e1d6ee50 FOREIGN KEY (created_by_account_id) REFERENCES public.accounts(id);


--
-- Name: dns_changes fk_rails_24b08fa7c5; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dns_changes
    ADD CONSTRAINT fk_rails_24b08fa7c5 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: account_webauthn_keys fk_rails_2586b16017; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_webauthn_keys
    ADD CONSTRAINT fk_rails_2586b16017 FOREIGN KEY (account_id) REFERENCES public.accounts(id);


--
-- Name: source_fetches fk_rails_27f5c59167; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_fetches
    ADD CONSTRAINT fk_rails_27f5c59167 FOREIGN KEY (project_source_binding_id) REFERENCES public.project_source_bindings(id) ON DELETE RESTRICT;


--
-- Name: rollout_steps fk_rails_2940ba92c3; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rollout_steps
    ADD CONSTRAINT fk_rails_2940ba92c3 FOREIGN KEY (release_id) REFERENCES public.releases(id) ON DELETE CASCADE;


--
-- Name: account_login_failures fk_rails_2d8f86a1e4; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_login_failures
    ADD CONSTRAINT fk_rails_2d8f86a1e4 FOREIGN KEY (id) REFERENCES public.accounts(id);


--
-- Name: account_verification_keys fk_rails_2e3b612008; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_verification_keys
    ADD CONSTRAINT fk_rails_2e3b612008 FOREIGN KEY (id) REFERENCES public.accounts(id);


--
-- Name: services fk_rails_2e9f369e43; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT fk_rails_2e9f369e43 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: source_snapshots fk_rails_318fb201e8; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_snapshots
    ADD CONSTRAINT fk_rails_318fb201e8 FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: edge_route_versions fk_rails_31f26f4e85; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edge_route_versions
    ADD CONSTRAINT fk_rails_31f26f4e85 FOREIGN KEY (release_id) REFERENCES public.releases(id);


--
-- Name: addons fk_rails_35c764bfb6; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.addons
    ADD CONSTRAINT fk_rails_35c764bfb6 FOREIGN KEY (project_id) REFERENCES public.projects(id);


--
-- Name: source_fetches fk_rails_36ea8a7104; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_fetches
    ADD CONSTRAINT fk_rails_36ea8a7104 FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE RESTRICT;


--
-- Name: releases fk_rails_38dafe0d7b; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.releases
    ADD CONSTRAINT fk_rails_38dafe0d7b FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: source_fetches fk_rails_3ee6483ee8; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_fetches
    ADD CONSTRAINT fk_rails_3ee6483ee8 FOREIGN KEY (created_by_account_id) REFERENCES public.accounts(id) ON DELETE RESTRICT;


--
-- Name: account_previous_password_hashes fk_rails_41c3f1892a; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_previous_password_hashes
    ADD CONSTRAINT fk_rails_41c3f1892a FOREIGN KEY (account_id) REFERENCES public.accounts(id);


--
-- Name: inbox_messages fk_rails_44b9c9a240; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inbox_messages
    ADD CONSTRAINT fk_rails_44b9c9a240 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: source_fetches fk_rails_4718abb6ed; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_fetches
    ADD CONSTRAINT fk_rails_4718abb6ed FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: attestations fk_rails_47a5c68ec4; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attestations
    ADD CONSTRAINT fk_rails_47a5c68ec4 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: service_routes fk_rails_48b51b47be; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_routes
    ADD CONSTRAINT fk_rails_48b51b47be FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: operations fk_rails_491483aaed; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.operations
    ADD CONSTRAINT fk_rails_491483aaed FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: webhooks fk_rails_49212d501e; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhooks
    ADD CONSTRAINT fk_rails_49212d501e FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: edge_route_versions fk_rails_4976d71da7; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edge_route_versions
    ADD CONSTRAINT fk_rails_4976d71da7 FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;


--
-- Name: account_lockouts fk_rails_49d7aeddf1; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_lockouts
    ADD CONSTRAINT fk_rails_49d7aeddf1 FOREIGN KEY (id) REFERENCES public.accounts(id);


--
-- Name: schedules fk_rails_4a3e237880; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schedules
    ADD CONSTRAINT fk_rails_4a3e237880 FOREIGN KEY (project_id) REFERENCES public.projects(id);


--
-- Name: project_source_bindings fk_rails_4effcdcb0e; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_source_bindings
    ADD CONSTRAINT fk_rails_4effcdcb0e FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: certificates fk_rails_52c9fb3a0a; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT fk_rails_52c9fb3a0a FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: releases fk_rails_5588f75019; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.releases
    ADD CONSTRAINT fk_rails_5588f75019 FOREIGN KEY (deployment_id) REFERENCES public.deployments(id);


--
-- Name: builds fk_rails_55e649baa8; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.builds
    ADD CONSTRAINT fk_rails_55e649baa8 FOREIGN KEY (source_snapshot_id) REFERENCES public.source_snapshots(id);


--
-- Name: credential_versions fk_rails_56405ecc5d; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credential_versions
    ADD CONSTRAINT fk_rails_56405ecc5d FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: ownership_challenges fk_rails_5665064932; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ownership_challenges
    ADD CONSTRAINT fk_rails_5665064932 FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;


--
-- Name: revisions fk_rails_57d7afc21f; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.revisions
    ADD CONSTRAINT fk_rails_57d7afc21f FOREIGN KEY (service_id) REFERENCES public.services(id);


--
-- Name: source_provider_deliveries fk_rails_59d46eaf4e; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_provider_deliveries
    ADD CONSTRAINT fk_rails_59d46eaf4e FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: build_steps fk_rails_5aac490417; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.build_steps
    ADD CONSTRAINT fk_rails_5aac490417 FOREIGN KEY (build_id) REFERENCES public.builds(id) ON DELETE CASCADE;


--
-- Name: source_snapshots fk_rails_5eb5d83652; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_snapshots
    ADD CONSTRAINT fk_rails_5eb5d83652 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: service_routes fk_rails_60c2c89669; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_routes
    ADD CONSTRAINT fk_rails_60c2c89669 FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;


--
-- Name: oauth_clients fk_rails_63cac5e83a; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT fk_rails_63cac5e83a FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: memberships fk_rails_64267aab58; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memberships
    ADD CONSTRAINT fk_rails_64267aab58 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: email_intents fk_rails_65ca40de4c; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_intents
    ADD CONSTRAINT fk_rails_65ca40de4c FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: source_snapshots fk_rails_6a9fed0613; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_snapshots
    ADD CONSTRAINT fk_rails_6a9fed0613 FOREIGN KEY (source_connection_id) REFERENCES public.source_connections(id);


--
-- Name: ownership_challenges fk_rails_6b8d0c6242; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ownership_challenges
    ADD CONSTRAINT fk_rails_6b8d0c6242 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: deployment_transitions fk_rails_6cfb122fbe; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_transitions
    ADD CONSTRAINT fk_rails_6cfb122fbe FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: source_fetches fk_rails_6fc5edd6e1; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_fetches
    ADD CONSTRAINT fk_rails_6fc5edd6e1 FOREIGN KEY (source_provider_delivery_id) REFERENCES public.source_provider_deliveries(id) ON DELETE RESTRICT;


--
-- Name: services fk_rails_71cce407f9; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT fk_rails_71cce407f9 FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: invitations fk_rails_7480156672; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.invitations
    ADD CONSTRAINT fk_rails_7480156672 FOREIGN KEY (inviter_id) REFERENCES public.accounts(id);


--
-- Name: project_source_bindings fk_rails_7641f1d1da; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_source_bindings
    ADD CONSTRAINT fk_rails_7641f1d1da FOREIGN KEY (current_source_fetch_id) REFERENCES public.source_fetches(id) ON DELETE SET NULL;


--
-- Name: builds fk_rails_77cdd5b475; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.builds
    ADD CONSTRAINT fk_rails_77cdd5b475 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: api_keys fk_rails_7aab96f30e; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT fk_rails_7aab96f30e FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: email_intents fk_rails_7ceca0de1b; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_intents
    ADD CONSTRAINT fk_rails_7ceca0de1b FOREIGN KEY (account_id) REFERENCES public.accounts(id);


--
-- Name: credential_versions fk_rails_8000ea4236; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credential_versions
    ADD CONSTRAINT fk_rails_8000ea4236 FOREIGN KEY (addon_id) REFERENCES public.addons(id) ON DELETE CASCADE;


--
-- Name: project_source_bindings fk_rails_80ad9cb3c5; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_source_bindings
    ADD CONSTRAINT fk_rails_80ad9cb3c5 FOREIGN KEY (last_provider_delivery_id) REFERENCES public.source_provider_deliveries(id) ON DELETE SET NULL;


--
-- Name: account_otp_keys fk_rails_823f8d7a81; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_otp_keys
    ADD CONSTRAINT fk_rails_823f8d7a81 FOREIGN KEY (id) REFERENCES public.accounts(id);


--
-- Name: addon_backups fk_rails_86edc236d3; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.addon_backups
    ADD CONSTRAINT fk_rails_86edc236d3 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: source_upload_sessions fk_rails_8a782632a8; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_upload_sessions
    ADD CONSTRAINT fk_rails_8a782632a8 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: rollout_steps fk_rails_8b481d114e; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rollout_steps
    ADD CONSTRAINT fk_rails_8b481d114e FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: revisions fk_rails_8dfbf1dbf5; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.revisions
    ADD CONSTRAINT fk_rails_8dfbf1dbf5 FOREIGN KEY (build_id) REFERENCES public.builds(id);


--
-- Name: domains fk_rails_8ea5eec4cf; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT fk_rails_8ea5eec4cf FOREIGN KEY (service_id) REFERENCES public.services(id);


--
-- Name: project_source_bindings fk_rails_8ee7b5ca37; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_source_bindings
    ADD CONSTRAINT fk_rails_8ee7b5ca37 FOREIGN KEY (created_by_account_id) REFERENCES public.accounts(id) ON DELETE RESTRICT;


--
-- Name: organizations fk_rails_8f18379d7a; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT fk_rails_8f18379d7a FOREIGN KEY (created_by_account_id) REFERENCES public.accounts(id);


--
-- Name: attachments fk_rails_915a09a714; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT fk_rails_915a09a714 FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;


--
-- Name: source_upload_sessions fk_rails_9291f88907; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_upload_sessions
    ADD CONSTRAINT fk_rails_9291f88907 FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: account_authentication_audit_logs fk_rails_92c5c23dad; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_authentication_audit_logs
    ADD CONSTRAINT fk_rails_92c5c23dad FOREIGN KEY (account_id) REFERENCES public.accounts(id);


--
-- Name: releases fk_rails_9834c451d1; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.releases
    ADD CONSTRAINT fk_rails_9834c451d1 FOREIGN KEY (service_id) REFERENCES public.services(id);


--
-- Name: source_fetches fk_rails_9836fb3ed8; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_fetches
    ADD CONSTRAINT fk_rails_9836fb3ed8 FOREIGN KEY (source_connection_id) REFERENCES public.source_connections(id) ON DELETE RESTRICT;


--
-- Name: addons fk_rails_99b6240dc9; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.addons
    ADD CONSTRAINT fk_rails_99b6240dc9 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: projects fk_rails_9aee26923d; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT fk_rails_9aee26923d FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: account_remember_keys fk_rails_9b2f6d8501; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_remember_keys
    ADD CONSTRAINT fk_rails_9b2f6d8501 FOREIGN KEY (id) REFERENCES public.accounts(id);


--
-- Name: project_source_bindings fk_rails_9d47847d4d; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.project_source_bindings
    ADD CONSTRAINT fk_rails_9d47847d4d FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: deployments fk_rails_9daa01f154; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployments
    ADD CONSTRAINT fk_rails_9daa01f154 FOREIGN KEY (operation_id) REFERENCES public.operations(id);


--
-- Name: releases fk_rails_9fa53efb49; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.releases
    ADD CONSTRAINT fk_rails_9fa53efb49 FOREIGN KEY (revision_id) REFERENCES public.revisions(id);


--
-- Name: dns_changes fk_rails_a17dc204fe; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dns_changes
    ADD CONSTRAINT fk_rails_a17dc204fe FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;


--
-- Name: schedules fk_rails_a3f1c52893; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schedules
    ADD CONSTRAINT fk_rails_a3f1c52893 FOREIGN KEY (environment_id) REFERENCES public.environments(id);


--
-- Name: schedules fk_rails_a4fb206fd7; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schedules
    ADD CONSTRAINT fk_rails_a4fb206fd7 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: deployments fk_rails_a7d3613e9b; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployments
    ADD CONSTRAINT fk_rails_a7d3613e9b FOREIGN KEY (revision_id) REFERENCES public.revisions(id);


--
-- Name: build_steps fk_rails_a7f79c7f8e; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.build_steps
    ADD CONSTRAINT fk_rails_a7f79c7f8e FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: service_routes fk_rails_aa60e5fe86; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_routes
    ADD CONSTRAINT fk_rails_aa60e5fe86 FOREIGN KEY (service_id) REFERENCES public.services(id) ON DELETE CASCADE;


--
-- Name: releases fk_rails_ac08597f77; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.releases
    ADD CONSTRAINT fk_rails_ac08597f77 FOREIGN KEY (environment_id) REFERENCES public.environments(id);


--
-- Name: attachments fk_rails_b10ecc2b5d; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT fk_rails_b10ecc2b5d FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: source_fetches fk_rails_b3236608f1; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_fetches
    ADD CONSTRAINT fk_rails_b3236608f1 FOREIGN KEY (source_snapshot_id) REFERENCES public.source_snapshots(id) ON DELETE RESTRICT;


--
-- Name: source_provider_deliveries fk_rails_b44274f5c2; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_provider_deliveries
    ADD CONSTRAINT fk_rails_b44274f5c2 FOREIGN KEY (source_connection_id) REFERENCES public.source_connections(id) ON DELETE RESTRICT;


--
-- Name: outbox_events fk_rails_b6cb24ddb3; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.outbox_events
    ADD CONSTRAINT fk_rails_b6cb24ddb3 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: revisions fk_rails_b70eaacafe; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.revisions
    ADD CONSTRAINT fk_rails_b70eaacafe FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: deployments fk_rails_b74667f767; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployments
    ADD CONSTRAINT fk_rails_b74667f767 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: deployments fk_rails_b9a3851b82; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployments
    ADD CONSTRAINT fk_rails_b9a3851b82 FOREIGN KEY (project_id) REFERENCES public.projects(id);


--
-- Name: audit_events fk_rails_be0ed9e37f; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT fk_rails_be0ed9e37f FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: workflow_runs fk_rails_be870aa094; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_runs
    ADD CONSTRAINT fk_rails_be870aa094 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: webhook_deliveries fk_rails_bed195a05d; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT fk_rails_bed195a05d FOREIGN KEY (webhook_id) REFERENCES public.webhooks(id) ON DELETE CASCADE;


--
-- Name: source_connections fk_rails_c27db5df08; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_connections
    ADD CONSTRAINT fk_rails_c27db5df08 FOREIGN KEY (connected_by_account_id) REFERENCES public.accounts(id) ON DELETE RESTRICT;


--
-- Name: domains fk_rails_c92ae0ce41; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT fk_rails_c92ae0ce41 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: account_password_reset_keys fk_rails_ccaeb37cea; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_password_reset_keys
    ADD CONSTRAINT fk_rails_ccaeb37cea FOREIGN KEY (id) REFERENCES public.accounts(id);


--
-- Name: attestations fk_rails_cd245c9af1; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attestations
    ADD CONSTRAINT fk_rails_cd245c9af1 FOREIGN KEY (revision_id) REFERENCES public.revisions(id) ON DELETE CASCADE;


--
-- Name: account_active_session_keys fk_rails_cdedf5be2c; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_active_session_keys
    ADD CONSTRAINT fk_rails_cdedf5be2c FOREIGN KEY (account_id) REFERENCES public.accounts(id);


--
-- Name: environments fk_rails_d1c8c1da6a; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environments
    ADD CONSTRAINT fk_rails_d1c8c1da6a FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE;


--
-- Name: dead_letter_messages fk_rails_d224261ae0; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dead_letter_messages
    ADD CONSTRAINT fk_rails_d224261ae0 FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: deployments fk_rails_d69efd1ece; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployments
    ADD CONSTRAINT fk_rails_d69efd1ece FOREIGN KEY (source_snapshot_id) REFERENCES public.source_snapshots(id);


--
-- Name: webhooks fk_rails_d90278b6a9; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhooks
    ADD CONSTRAINT fk_rails_d90278b6a9 FOREIGN KEY (project_id) REFERENCES public.projects(id);


--
-- Name: attachments fk_rails_d92d0755ba; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attachments
    ADD CONSTRAINT fk_rails_d92d0755ba FOREIGN KEY (addon_id) REFERENCES public.addons(id) ON DELETE CASCADE;


--
-- Name: usage_ledger fk_rails_da8da141fe; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_ledger
    ADD CONSTRAINT fk_rails_da8da141fe FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: addon_backups fk_rails_dae606135f; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.addon_backups
    ADD CONSTRAINT fk_rails_dae606135f FOREIGN KEY (addon_id) REFERENCES public.addons(id) ON DELETE CASCADE;


--
-- Name: services fk_rails_e8003bce7c; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT fk_rails_e8003bce7c FOREIGN KEY (current_release_id) REFERENCES public.releases(id);


--
-- Name: addons fk_rails_e914c3015c; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.addons
    ADD CONSTRAINT fk_rails_e914c3015c FOREIGN KEY (environment_id) REFERENCES public.environments(id);


--
-- Name: account_password_hashes fk_rails_e9403bd13b; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_password_hashes
    ADD CONSTRAINT fk_rails_e9403bd13b FOREIGN KEY (id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: webhook_deliveries fk_rails_ea5a0897ac; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT fk_rails_ea5a0897ac FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: memberships fk_rails_edbc202c67; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.memberships
    ADD CONSTRAINT fk_rails_edbc202c67 FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;


--
-- Name: account_recovery_codes fk_rails_ef43948844; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_recovery_codes
    ADD CONSTRAINT fk_rails_ef43948844 FOREIGN KEY (id) REFERENCES public.accounts(id);


--
-- Name: deployment_transitions fk_rails_f35d91457d; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_transitions
    ADD CONSTRAINT fk_rails_f35d91457d FOREIGN KEY (deployment_id) REFERENCES public.deployments(id) ON DELETE CASCADE;


--
-- Name: api_keys fk_rails_f4470e16d5; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT fk_rails_f4470e16d5 FOREIGN KEY (account_id) REFERENCES public.accounts(id);


--
-- Name: source_upload_sessions fk_rails_fb9d65f726; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.source_upload_sessions
    ADD CONSTRAINT fk_rails_fb9d65f726 FOREIGN KEY (source_snapshot_id) REFERENCES public.source_snapshots(id);


--
-- Name: account_webauthn_user_ids fk_rails_fc5911c897; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_webauthn_user_ids
    ADD CONSTRAINT fk_rails_fc5911c897 FOREIGN KEY (id) REFERENCES public.accounts(id);


--
-- Name: addon_backups; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.addon_backups ENABLE ROW LEVEL SECURITY;

--
-- Name: addon_backups addon_backups_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY addon_backups_tenant_policy ON public.addon_backups USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: addons; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.addons ENABLE ROW LEVEL SECURITY;

--
-- Name: addons addons_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY addons_tenant_policy ON public.addons USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: api_keys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;

--
-- Name: api_keys api_keys_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY api_keys_tenant_policy ON public.api_keys USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: attachments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.attachments ENABLE ROW LEVEL SECURITY;

--
-- Name: attachments attachments_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY attachments_tenant_policy ON public.attachments USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: attestations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.attestations ENABLE ROW LEVEL SECURITY;

--
-- Name: attestations attestations_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY attestations_tenant_policy ON public.attestations USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: audit_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;

--
-- Name: audit_events audit_events_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY audit_events_tenant_policy ON public.audit_events USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: build_steps; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.build_steps ENABLE ROW LEVEL SECURITY;

--
-- Name: build_steps build_steps_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY build_steps_tenant_policy ON public.build_steps USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: builds; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.builds ENABLE ROW LEVEL SECURITY;

--
-- Name: builds builds_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY builds_tenant_policy ON public.builds USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: certificates; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.certificates ENABLE ROW LEVEL SECURITY;

--
-- Name: certificates certificates_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY certificates_tenant_policy ON public.certificates USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: credential_versions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.credential_versions ENABLE ROW LEVEL SECURITY;

--
-- Name: credential_versions credential_versions_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY credential_versions_tenant_policy ON public.credential_versions USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: dead_letter_messages; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.dead_letter_messages ENABLE ROW LEVEL SECURITY;

--
-- Name: dead_letter_messages dead_letter_messages_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY dead_letter_messages_tenant_policy ON public.dead_letter_messages USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: deployment_transitions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.deployment_transitions ENABLE ROW LEVEL SECURITY;

--
-- Name: deployment_transitions deployment_transitions_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY deployment_transitions_tenant_policy ON public.deployment_transitions USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: deployments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.deployments ENABLE ROW LEVEL SECURITY;

--
-- Name: deployments deployments_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY deployments_tenant_policy ON public.deployments USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: dns_changes; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.dns_changes ENABLE ROW LEVEL SECURITY;

--
-- Name: dns_changes dns_changes_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY dns_changes_tenant_policy ON public.dns_changes USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: domains; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.domains ENABLE ROW LEVEL SECURITY;

--
-- Name: domains domains_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY domains_tenant_policy ON public.domains USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: edge_route_versions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.edge_route_versions ENABLE ROW LEVEL SECURITY;

--
-- Name: edge_route_versions edge_route_versions_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY edge_route_versions_tenant_policy ON public.edge_route_versions USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: email_intents; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.email_intents ENABLE ROW LEVEL SECURITY;

--
-- Name: email_intents email_intents_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY email_intents_tenant_policy ON public.email_intents USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: environments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.environments ENABLE ROW LEVEL SECURITY;

--
-- Name: environments environments_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY environments_tenant_policy ON public.environments USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: idempotency_keys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.idempotency_keys ENABLE ROW LEVEL SECURITY;

--
-- Name: idempotency_keys idempotency_keys_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY idempotency_keys_tenant_policy ON public.idempotency_keys USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: inbox_messages; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.inbox_messages ENABLE ROW LEVEL SECURITY;

--
-- Name: inbox_messages inbox_messages_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY inbox_messages_tenant_policy ON public.inbox_messages USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: invitations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.invitations ENABLE ROW LEVEL SECURITY;

--
-- Name: invitations invitations_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY invitations_tenant_policy ON public.invitations USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: memberships; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.memberships ENABLE ROW LEVEL SECURITY;

--
-- Name: memberships memberships_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY memberships_tenant_policy ON public.memberships USING ((((account_id)::text = current_setting('lrail.account_id'::text, true)) OR (((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND (public.lrail_account_has_membership(organization_id) OR (((account_id)::text = current_setting('lrail.account_id'::text, true)) AND ((role)::text = 'owner'::text) AND (EXISTS ( SELECT 1
   FROM public.organizations
  WHERE ((organizations.id = memberships.organization_id) AND ((organizations.created_by_account_id)::text = current_setting('lrail.account_id'::text, true)))))))));


--
-- Name: oauth_clients; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.oauth_clients ENABLE ROW LEVEL SECURITY;

--
-- Name: oauth_clients oauth_clients_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY oauth_clients_tenant_policy ON public.oauth_clients USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: operations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.operations ENABLE ROW LEVEL SECURITY;

--
-- Name: operations operations_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY operations_tenant_policy ON public.operations USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: organizations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;

--
-- Name: organizations organizations_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY organizations_tenant_policy ON public.organizations USING (((((id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(id)) OR ((created_by_account_id)::text = current_setting('lrail.account_id'::text, true)))) WITH CHECK (((created_by_account_id)::text = current_setting('lrail.account_id'::text, true)));


--
-- Name: outbox_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.outbox_events ENABLE ROW LEVEL SECURITY;

--
-- Name: outbox_events outbox_events_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY outbox_events_tenant_policy ON public.outbox_events USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: ownership_challenges; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.ownership_challenges ENABLE ROW LEVEL SECURITY;

--
-- Name: ownership_challenges ownership_challenges_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY ownership_challenges_tenant_policy ON public.ownership_challenges USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: project_source_bindings; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.project_source_bindings ENABLE ROW LEVEL SECURITY;

--
-- Name: project_source_bindings project_source_bindings_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY project_source_bindings_tenant_policy ON public.project_source_bindings USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: projects; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;

--
-- Name: projects projects_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY projects_tenant_policy ON public.projects USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: release_targets; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.release_targets ENABLE ROW LEVEL SECURITY;

--
-- Name: release_targets release_targets_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY release_targets_tenant_policy ON public.release_targets USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: releases; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.releases ENABLE ROW LEVEL SECURITY;

--
-- Name: releases releases_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY releases_tenant_policy ON public.releases USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: revisions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.revisions ENABLE ROW LEVEL SECURITY;

--
-- Name: revisions revisions_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY revisions_tenant_policy ON public.revisions USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: rollout_steps; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.rollout_steps ENABLE ROW LEVEL SECURITY;

--
-- Name: rollout_steps rollout_steps_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY rollout_steps_tenant_policy ON public.rollout_steps USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: schedules; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.schedules ENABLE ROW LEVEL SECURITY;

--
-- Name: schedules schedules_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY schedules_tenant_policy ON public.schedules USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: service_routes; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.service_routes ENABLE ROW LEVEL SECURITY;

--
-- Name: service_routes service_routes_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY service_routes_tenant_policy ON public.service_routes USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: services; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.services ENABLE ROW LEVEL SECURITY;

--
-- Name: services services_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY services_tenant_policy ON public.services USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: source_connections; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.source_connections ENABLE ROW LEVEL SECURITY;

--
-- Name: source_connections source_connections_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY source_connections_tenant_policy ON public.source_connections USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: source_fetches; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.source_fetches ENABLE ROW LEVEL SECURITY;

--
-- Name: source_fetches source_fetches_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY source_fetches_tenant_policy ON public.source_fetches USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: source_provider_deliveries; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.source_provider_deliveries ENABLE ROW LEVEL SECURITY;

--
-- Name: source_provider_deliveries source_provider_deliveries_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY source_provider_deliveries_tenant_policy ON public.source_provider_deliveries FOR SELECT USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: source_snapshots; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.source_snapshots ENABLE ROW LEVEL SECURITY;

--
-- Name: source_snapshots source_snapshots_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY source_snapshots_tenant_policy ON public.source_snapshots USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: source_upload_sessions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.source_upload_sessions ENABLE ROW LEVEL SECURITY;

--
-- Name: source_upload_sessions source_upload_sessions_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY source_upload_sessions_tenant_policy ON public.source_upload_sessions USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: usage_ledger; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.usage_ledger ENABLE ROW LEVEL SECURITY;

--
-- Name: usage_ledger usage_ledger_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY usage_ledger_tenant_policy ON public.usage_ledger USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: webhook_deliveries; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.webhook_deliveries ENABLE ROW LEVEL SECURITY;

--
-- Name: webhook_deliveries webhook_deliveries_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY webhook_deliveries_tenant_policy ON public.webhook_deliveries USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: webhooks; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.webhooks ENABLE ROW LEVEL SECURITY;

--
-- Name: webhooks webhooks_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY webhooks_tenant_policy ON public.webhooks USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- Name: workflow_runs; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.workflow_runs ENABLE ROW LEVEL SECURITY;

--
-- Name: workflow_runs workflow_runs_tenant_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY workflow_runs_tenant_policy ON public.workflow_runs USING ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id))) WITH CHECK ((((organization_id)::text = current_setting('lrail.organization_id'::text, true)) AND public.lrail_account_has_membership(organization_id)));


--
-- PostgreSQL database dump complete
--

SET search_path TO "$user", public;

INSERT INTO "schema_migrations" (version) VALUES
('20260712204349'),
('20260712204510'),
('20260712204511'),
('20260712204512'),
('20260712221000'),
('20260712233000'),
('20260713001500'),
('20260713013000')
ON CONFLICT DO NOTHING;

-- LRAIL_RUNTIME_GRANTS_BEGIN

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
