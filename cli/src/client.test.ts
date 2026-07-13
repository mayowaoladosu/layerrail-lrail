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
});
