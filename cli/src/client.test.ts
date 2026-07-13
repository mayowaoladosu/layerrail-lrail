import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { LrailClient } from "./client.js";

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("LrailClient", () => {
  it("authorizes, uploads bounded parts, and finalizes without exposing the API token to object storage", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(
        response(
          {
            data: {
              id: "upl_test",
              state: "uploading",
              expires_at: new Date().toISOString(),
            },
            parts: [
              {
                number: 1,
                url: "https://objects.example/1",
                expires_at: new Date().toISOString(),
              },
              {
                number: 2,
                url: "https://objects.example/2",
                expires_at: new Date().toISOString(),
              },
            ],
          },
          201,
        ),
      )
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
      .mockResolvedValueOnce(response({ data: { state: "complete" } }));
    const client = new LrailClient({
      apiUrl: "https://api.example/",
      token: "lrail_key_prefix_secret",
      organization: "org_test",
      fetch,
    });
    const bytes = Buffer.from("abcdefghij");
    const authorization = await client.authorizeUpload(
      "prj_test",
      bytes.length,
      "sha256:test",
      2,
      0,
    );
    const parts = await client.uploadParts(authorization, bytes);
    await client.finalizeUpload(authorization.data.id, parts);

    expect(fetch).toHaveBeenCalledTimes(4);
    const objectRequest = fetch.mock.calls[1];
    expect(objectRequest?.[1]?.headers).toBeUndefined();
    expect(parts).toEqual([
      {
        number: 1,
        size: 5,
        sha256: `sha256:${createHash("sha256").update("abcde").digest("hex")}`,
      },
      {
        number: 2,
        size: 5,
        sha256: `sha256:${createHash("sha256").update("fghij").digest("hex")}`,
      },
    ]);
  });

  it("rejects insecure remote APIs and malformed upload part sequences", async () => {
    expect(
      () => new LrailClient({ apiUrl: "http://api.example/", token: "unused" }),
    ).toThrow("control-plane URL must use HTTPS");

    const client = new LrailClient({
      apiUrl: "https://api.example/",
      token: "unused",
    });
    await expect(
      client.uploadParts(
        {
          data: {
            id: "upl_test",
            state: "uploading",
            expires_at: new Date().toISOString(),
          },
          parts: [
            {
              number: 1,
              url: "https://objects.example/1",
              expires_at: new Date().toISOString(),
            },
            {
              number: 3,
              url: "https://objects.example/3",
              expires_at: new Date().toISOString(),
            },
          ],
        },
        Buffer.from("abcdefghij"),
      ),
    ).rejects.toThrow("invalid source upload part numbers");
  });

  it("creates an explicitly accepted deploy and resumes retained operation events", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(
        response(
          {
            data: {
              id: "dep_test",
              state: "created",
              source_snapshot_id: "snp_test",
              operation_id: "op_test",
              build_mode: "auto",
              build_file: null,
              accept_detected: true,
              artifact_ready_at: null,
            },
            operation: {
              id: "op_test",
              state: "accepted",
              stage: "sourcing",
              waiting_reason: null,
              progress: { completed: 0, total: 11 },
              error: null,
            },
          },
          202,
        ),
      )
      .mockResolvedValueOnce(
        response({
          data: [],
          operation: {
            id: "op_test",
            state: "running",
            stage: "building",
            waiting_reason: null,
            progress: { completed: 5, total: 11 },
            error: null,
          },
          generation: 1,
          next_sequence: 41,
        }),
      );
    const client = new LrailClient({
      apiUrl: "https://api.example/",
      token: "test-token",
      organization: "org_test",
      fetch,
    });

    await client.createDeployment("prj_test", {
      environmentId: "env_test",
      source: { kind: "local", source_snapshot_id: "snp_test" },
      manifestRevision: 1,
      reason: "cli test",
      buildMode: "auto",
      acceptDetected: true,
      idempotencyKey: "cli-test-deployment",
    });
    await client.getOperationEvents("op_test", 1, 41, 100);

    const create = fetch.mock.calls[0];
    expect((create?.[1]?.headers as Headers).get("Idempotency-Key")).toBe(
      "cli-test-deployment",
    );
    expect(JSON.parse(String(create?.[1]?.body))).toMatchObject({
      build_mode: "auto",
      accept_detected: true,
      source: { kind: "local", source_snapshot_id: "snp_test" },
    });
    expect(String(fetch.mock.calls[1]?.[0])).toContain(
      "generation=1&after=41&limit=100",
    );
  });

  it("creates an exact Git deployment through an authorized source connection", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValueOnce(
      response(
        {
          data: {
            id: "dep_git",
            state: "created",
            source_snapshot_id: "snp_git",
            operation_id: "op_git",
            build_mode: "auto",
            build_file: null,
            accept_detected: true,
            artifact_ready_at: null,
          },
          operation: {
            id: "op_git",
            state: "accepted",
            stage: "sourcing",
            waiting_reason: null,
            progress: { completed: 0, total: 11 },
            error: null,
          },
        },
        202,
      ),
    );
    const client = new LrailClient({
      apiUrl: "https://api.example/",
      token: "test-token",
      organization: "org_test",
      fetch,
    });

    await client.createDeployment("prj_test", {
      environmentId: "env_test",
      source: {
        kind: "git",
        connection_id: "src_test",
        repository: "owner/repository",
        commit: "a".repeat(40),
        root_directory: "apps/web",
      },
      manifestRevision: 1,
      reason: "cli_git_deploy",
      buildMode: "auto",
      acceptDetected: true,
      idempotencyKey: "cli-git-deploy-test",
    });

    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toMatchObject({
      source: {
        kind: "git",
        connection_id: "src_test",
        repository: "owner/repository",
        commit: "a".repeat(40),
        root_directory: "apps/web",
      },
    });
  });

  it("retries a transient object-store part failure and sends cancellation reason", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 503 }))
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
      .mockResolvedValueOnce(
        response(
          {
            data: {
              id: "op_test",
              state: "canceling",
              stage: "canceling",
              waiting_reason: null,
              progress: { completed: 5, total: 11 },
              error: null,
            },
          },
          202,
        ),
      );
    const client = new LrailClient({
      apiUrl: "https://api.example/",
      token: "test-token",
      fetch,
    });
    const authorization = {
      data: {
        id: "upl_test",
        state: "uploading",
        expires_at: new Date().toISOString(),
      },
      parts: [
        {
          number: 1,
          url: "https://objects.example/1",
          expires_at: new Date().toISOString(),
        },
      ],
    };

    const parts = await client.uploadParts(authorization, Buffer.from("retry"));
    await client.cancelDeployment(
      "dep_test",
      "cli-test-cancel",
      "user requested test cancellation",
    );

    expect(parts).toHaveLength(1);
    expect(fetch).toHaveBeenCalledTimes(3);
    const cancel = fetch.mock.calls[2];
    expect((cancel?.[1]?.headers as Headers).get("Idempotency-Key")).toBe(
      "cli-test-cancel",
    );
    expect(JSON.parse(String(cancel?.[1]?.body))).toEqual({
      reason: "user requested test cancellation",
    });
  });
});
