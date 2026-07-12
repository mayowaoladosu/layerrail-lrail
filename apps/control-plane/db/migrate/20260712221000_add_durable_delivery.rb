class AddDurableDelivery < ActiveRecord::Migration[8.1]
  EVENT_ID_PATTERN = "^[a-z]{2,5}_[0-9a-f-]{36}$"

  def up
    add_outbox_delivery_state
    add_email_delivery_state
    create_inbox_tables
    create_email_provider_events
    create_worker_functions
    create_email_provider_function
    configure_runtime_roles
  end

  def down
    drop_runtime_functions
    drop_table :email_provider_events
    drop_table :dead_letter_messages
    drop_table :inbox_messages

    remove_check_constraint :email_intents, name: "email_intents_state"
    remove_index :email_intents, name: "index_email_intents_on_provider_message_id"
    remove_index :email_intents, name: "email_intent_delivery_queue"
    remove_columns :email_intents, :attempt_count, :last_error, :provider,
      :locked_at, :locked_by, :bounced_at, :complained_at, :terminal_at
    remove_index :outbox_events, name: "outbox_delivery_queue"
    remove_columns :outbox_events, :organization_public_id, :next_attempt_at, :locked_at, :locked_by, :discarded_at
  end

  private

  def add_outbox_delivery_state
    change_table :outbox_events, bulk: true do |table|
      table.string :organization_public_id, limit: 64
      table.datetime :next_attempt_at
      table.datetime :locked_at
      table.string :locked_by, limit: 128
      table.datetime :discarded_at
    end
    execute <<~SQL
      UPDATE outbox_events
      SET organization_public_id = organizations.public_id
      FROM organizations
      WHERE organizations.id = outbox_events.organization_id;
    SQL
    change_column_null :outbox_events, :organization_public_id, false
    add_index :outbox_events, %i[published_at discarded_at next_attempt_at occurred_at],
      name: "outbox_delivery_queue"
  end

  def add_email_delivery_state
    change_table :email_intents, bulk: true do |table|
      table.integer :attempt_count, null: false, default: 0
      table.text :last_error
      table.string :provider, limit: 32
      table.datetime :locked_at
      table.string :locked_by, limit: 128
      table.datetime :bounced_at
      table.datetime :complained_at
      table.datetime :terminal_at
    end
    add_check_constraint :email_intents,
      "state IN ('pending', 'sending', 'sent', 'delivered', 'retryable', 'bounced', 'complained', 'failed')",
      name: "email_intents_state"
    add_index :email_intents, :provider_message_id, unique: true, where: "provider_message_id IS NOT NULL"
    add_index :email_intents, %i[state next_attempt_at locked_at], name: "email_intent_delivery_queue"
  end

  def create_inbox_tables
    create_table :inbox_messages do |table|
      table.string :public_id, null: false, limit: 64
      table.references :organization, null: false, foreign_key: { on_delete: :cascade }
      table.string :consumer, null: false, limit: 128
      table.string :event_public_id, null: false, limit: 64
      table.string :event_type, null: false, limit: 128
      table.integer :schema_version, null: false
      table.string :subject, null: false, limit: 256
      table.string :payload_digest, null: false, limit: 71
      table.string :state, null: false, default: "processing"
      table.integer :attempt_count, null: false, default: 1
      table.datetime :first_received_at, null: false
      table.datetime :processed_at
      table.text :last_error
      table.timestamps
      table.index :public_id, unique: true
      table.index %i[consumer event_public_id], unique: true, name: "inbox_consumer_event"
      table.index %i[state first_received_at]
      table.check_constraint "public_id ~ '#{EVENT_ID_PATTERN}'", name: "inbox_messages_public_id_format"
      table.check_constraint "state IN ('processing', 'completed', 'dead_lettered')", name: "inbox_messages_state"
    end

    create_table :dead_letter_messages do |table|
      table.string :public_id, null: false, limit: 64
      table.references :organization, null: false, foreign_key: { on_delete: :cascade }
      table.string :consumer, null: false, limit: 128
      table.string :event_public_id, null: false, limit: 64
      table.string :event_type, null: false, limit: 128
      table.string :subject, null: false, limit: 256
      table.string :reason, null: false, limit: 256
      table.jsonb :event_payload, null: false, default: {}
      table.jsonb :message_headers, null: false, default: {}
      table.integer :attempt_count, null: false
      table.datetime :first_failed_at, null: false
      table.datetime :last_failed_at, null: false
      table.datetime :replayed_at
      table.timestamps
      table.index :public_id, unique: true
      table.index %i[consumer event_public_id], unique: true, name: "dead_letter_consumer_event"
      table.check_constraint "public_id ~ '#{EVENT_ID_PATTERN}'", name: "dead_letter_messages_public_id_format"
    end

    %i[inbox_messages dead_letter_messages].each do |table|
      execute <<~SQL
        ALTER TABLE #{table} ENABLE ROW LEVEL SECURITY;
        ALTER TABLE #{table} FORCE ROW LEVEL SECURITY;
        CREATE POLICY #{table}_tenant_policy ON #{table}
        USING (
          organization_id::text = current_setting('lrail.organization_id', true)
          AND lrail_account_has_membership(organization_id)
        )
        WITH CHECK (
          organization_id::text = current_setting('lrail.organization_id', true)
          AND lrail_account_has_membership(organization_id)
        );
      SQL
    end
  end

  def create_email_provider_events
    create_table :email_provider_events do |table|
      table.string :provider_event_id, null: false, limit: 128
      table.string :event_type, null: false, limit: 64
      table.string :provider_message_id, limit: 128
      table.string :payload_digest, null: false, limit: 71
      table.string :outcome, null: false, default: "received", limit: 32
      table.datetime :received_at, null: false
      table.datetime :processed_at
      table.timestamps
      table.index :provider_event_id, unique: true
      table.index :provider_message_id
    end
  end

  def create_worker_functions
    execute <<~SQL
      CREATE FUNCTION lrail_claim_outbox(worker_name text, requested_limit integer)
      RETURNS SETOF outbox_events AS $$
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
      $$ LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp SET row_security = off;

      CREATE FUNCTION lrail_finish_outbox(
        event_id bigint,
        worker_name text,
        was_published boolean,
        error_message text,
        retry_at timestamptz,
        dead_letter boolean
      ) RETURNS boolean AS $$
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
      $$ LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp SET row_security = off;

      CREATE FUNCTION lrail_claim_email(worker_name text, requested_limit integer)
      RETURNS SETOF email_intents AS $$
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
      $$ LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp SET row_security = off;

      CREATE FUNCTION lrail_finish_email(
        intent_id bigint,
        worker_name text,
        result_state text,
        provider_name text,
        message_id text,
        error_message text,
        retry_at timestamptz
      ) RETURNS boolean AS $$
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
      $$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp SET row_security = off;
    SQL
  end

  def create_email_provider_function
    execute <<~SQL
      CREATE FUNCTION lrail_apply_email_provider_event(
        delivery_id text,
        delivery_type text,
        payload_sha256 text,
        message_id text,
        event_time timestamptz
      ) RETURNS text AS $$
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
      $$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp SET row_security = off;
    SQL
  end

  def configure_runtime_roles
    revoke_public_function_access
    configure_worker_role
    configure_web_role
  end

  def revoke_public_function_access
    execute "REVOKE ALL ON FUNCTION lrail_claim_outbox(text, integer) FROM PUBLIC"
    execute "REVOKE ALL ON FUNCTION lrail_finish_outbox(bigint, text, boolean, text, timestamptz, boolean) FROM PUBLIC"
    execute "REVOKE ALL ON FUNCTION lrail_claim_email(text, integer) FROM PUBLIC"
    execute "REVOKE ALL ON FUNCTION lrail_finish_email(bigint, text, text, text, text, text, timestamptz) FROM PUBLIC"
    execute "REVOKE ALL ON FUNCTION lrail_apply_email_provider_event(text, text, text, text, timestamptz) FROM PUBLIC"
  end

  def configure_worker_role
    role = "lrail_worker"
    return unless role_exists?(role)

    quoted_role = connection.quote_table_name(role)
    execute "GRANT USAGE ON SCHEMA public TO #{quoted_role}"
    execute "GRANT EXECUTE ON FUNCTION lrail_claim_outbox(text, integer) TO #{quoted_role}"
    execute "GRANT EXECUTE ON FUNCTION lrail_finish_outbox(bigint, text, boolean, text, timestamptz, boolean) TO #{quoted_role}"
    execute "GRANT EXECUTE ON FUNCTION lrail_claim_email(text, integer) TO #{quoted_role}"
    execute "GRANT EXECUTE ON FUNCTION lrail_finish_email(bigint, text, text, text, text, text, timestamptz) TO #{quoted_role}"
  end

  def configure_web_role
    role = ENV.fetch("LRAIL_WEB_DATABASE_ROLE", "lrail_web")
    return unless role_exists?(role)

    quoted_role = connection.quote_table_name(role)
    execute "REVOKE ALL ON schema_migrations, ar_internal_metadata FROM #{quoted_role}"
    execute "REVOKE ALL ON email_provider_events FROM #{quoted_role}"
    execute "REVOKE ALL ON email_provider_events_id_seq FROM #{quoted_role}"
    execute "REVOKE UPDATE, DELETE ON outbox_events, email_intents FROM #{quoted_role}"
    execute "GRANT SELECT, INSERT, UPDATE ON inbox_messages, dead_letter_messages TO #{quoted_role}"
    execute "GRANT USAGE, SELECT ON inbox_messages_id_seq, dead_letter_messages_id_seq TO #{quoted_role}"
    execute "GRANT EXECUTE ON FUNCTION lrail_apply_email_provider_event(text, text, text, text, timestamptz) TO #{quoted_role}"
  end

  def drop_runtime_functions
    execute "DROP FUNCTION IF EXISTS lrail_apply_email_provider_event(text, text, text, text, timestamptz)"
    execute "DROP FUNCTION IF EXISTS lrail_finish_email(bigint, text, text, text, text, text, timestamptz)"
    execute "DROP FUNCTION IF EXISTS lrail_claim_email(text, integer)"
    execute "DROP FUNCTION IF EXISTS lrail_finish_outbox(bigint, text, boolean, text, timestamptz, boolean)"
    execute "DROP FUNCTION IF EXISTS lrail_claim_outbox(text, integer)"
  end

  def role_exists?(role)
    select_value("SELECT 1 FROM pg_roles WHERE rolname = #{connection.quote(role)}")
  end
end
