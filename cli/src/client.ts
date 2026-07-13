import { createHash, randomUUID } from "node:crypto";
import type {
  DeploymentCreateResult,
  DeploymentResource,
  OperationEventsResult,
  OperationResource,
  SourceUploadResult,
  UploadAuthorization,
  UploadedPart,
} from "./types.js";

interface ClientOptions {
  apiUrl: string;
  token: string;
  organization?: string;
  fetch?: typeof globalThis.fetch;
}

const MAX_API_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_PART_ATTEMPTS = 4;

export class LrailClient {
  readonly #baseUrl: URL;
  readonly #token: string;
  readonly #organization: string | undefined;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options: ClientOptions) {
    this.#baseUrl = new URL(options.apiUrl);
    validateTransport(this.#baseUrl, "control-plane");
    if (!this.#baseUrl.pathname.endsWith("/")) this.#baseUrl.pathname += "/";
    if (!options.token || /[\r\n]/u.test(options.token)) {
      throw new Error("API token is missing or invalid");
    }
    this.#token = options.token;
    this.#organization = options.organization;
    this.#fetch = options.fetch ?? globalThis.fetch;
  }

  async authorizeUpload(
    projectId: string,
    archiveBytes: number,
    archiveSha256: string,
    expectedParts: number,
    excludedCount: number,
  ): Promise<UploadAuthorization> {
    return this.#request<UploadAuthorization>(
      `v1/projects/${encodeURIComponent(projectId)}/source_uploads`,
      {
        method: "POST",
        idempotencyKey: randomUUID(),
        body: {
          source_upload: {
            expected_archive_bytes: archiveBytes,
            expected_archive_sha256: archiveSha256,
            expected_parts: expectedParts,
            root_directory: "",
            excluded_count: excludedCount,
          },
        },
      },
    );
  }

  async uploadParts(
    authorization: UploadAuthorization,
    bytes: Buffer,
  ): Promise<UploadedPart[]> {
    const parts = [...authorization.parts].sort(
      (left, right) => left.number - right.number,
    );
    const partCount = parts.length;
    if (partCount < 1)
      throw new Error("server returned no source upload parts");
    if (parts.some((part, index) => part.number !== index + 1)) {
      throw new Error("server returned invalid source upload part numbers");
    }
    const chunkBytes = Math.ceil(bytes.length / partCount);
    if (chunkBytes > 16 * 1024 * 1024)
      throw new Error("server returned insufficient source upload parts");
    const uploaded: UploadedPart[] = [];
    for (const part of parts) {
      validateTransport(new URL(part.url), `source part ${part.number}`);
      const offset = (part.number - 1) * chunkBytes;
      const body = bytes.subarray(
        offset,
        Math.min(offset + chunkBytes, bytes.length),
      );
      if (body.length === 0)
        throw new Error(`empty source upload part ${part.number}`);
      const uploadBody = Uint8Array.from(body).buffer;
      await this.#uploadPart(part.url, uploadBody, part.number);
      uploaded.push({
        number: part.number,
        size: body.length,
        sha256: `sha256:${createHash("sha256").update(body).digest("hex")}`,
      });
    }
    return uploaded;
  }

  async #uploadPart(
    url: string,
    body: ArrayBuffer,
    partNumber: number,
  ): Promise<void> {
    let lastStatus: number | undefined;
    for (let attempt = 1; attempt <= MAX_PART_ATTEMPTS; attempt += 1) {
      try {
        const response = await this.#fetch(url, { method: "PUT", body });
        if (response.ok) return;
        lastStatus = response.status;
        if (!retryableStatus(response.status)) break;
      } catch (error) {
        if (attempt === MAX_PART_ATTEMPTS) throw error;
      }
      if (attempt < MAX_PART_ATTEMPTS) await delay(100 * 2 ** (attempt - 1));
    }
    throw new Error(
      `source part ${partNumber} upload failed${lastStatus ? ` with HTTP ${lastStatus}` : ""}`,
    );
  }

  async finalizeUpload(
    sessionId: string,
    parts: UploadedPart[],
  ): Promise<SourceUploadResult> {
    return this.#request<SourceUploadResult>(
      `v1/source_uploads/${encodeURIComponent(sessionId)}/finalize`,
      {
        method: "POST",
        idempotencyKey: randomUUID(),
        body: { source_upload: { parts } },
      },
    );
  }

  async createDeployment(
    projectId: string,
    input: {
      environmentId: string;
      source:
        | { kind: "local"; source_snapshot_id: string }
        | {
            kind: "git";
            connection_id: string;
            repository: string;
            commit: string;
          };
      manifestRevision: number;
      reason: string;
      buildMode: "auto" | "repository";
      acceptDetected: boolean;
      buildFile?: string;
      idempotencyKey: string;
    },
  ): Promise<DeploymentCreateResult> {
    return this.#request<DeploymentCreateResult>(
      `v1/projects/${encodeURIComponent(projectId)}/deployments`,
      {
        method: "POST",
        idempotencyKey: input.idempotencyKey,
        body: {
          environment_id: input.environmentId,
          source: input.source,
          manifest_revision: input.manifestRevision,
          reason: input.reason,
          build_mode: input.buildMode,
          accept_detected: input.acceptDetected,
          ...(input.buildFile ? { build_file: input.buildFile } : {}),
        },
      },
    );
  }

  async getDeployment(deploymentId: string): Promise<DeploymentResource> {
    const result = await this.#request<{ data: DeploymentResource }>(
      `v1/deployments/${encodeURIComponent(deploymentId)}`,
      { method: "GET" },
    );
    return result.data;
  }

  async cancelDeployment(
    deploymentId: string,
    idempotencyKey: string,
    reason: string,
  ): Promise<OperationResource> {
    const result = await this.#request<{ data: OperationResource }>(
      `v1/deployments/${encodeURIComponent(deploymentId)}`,
      { method: "DELETE", idempotencyKey, body: { reason } },
    );
    return result.data;
  }

  async getOperation(operationId: string): Promise<OperationResource> {
    const result = await this.#request<{ data: OperationResource }>(
      `v1/operations/${encodeURIComponent(operationId)}`,
      { method: "GET" },
    );
    return result.data;
  }

  async getOperationEvents(
    operationId: string,
    generation: number,
    after: number,
    limit = 250,
  ): Promise<OperationEventsResult> {
    const query = new URLSearchParams({
      generation: String(generation),
      after: String(after),
      limit: String(limit),
    });
    return this.#request<OperationEventsResult>(
      `v1/operations/${encodeURIComponent(operationId)}/events?${query.toString()}`,
      { method: "GET" },
    );
  }

  async #request<T>(
    path: string,
    options: { method: string; idempotencyKey?: string; body?: unknown },
  ): Promise<T> {
    const headers = new Headers({
      Accept: "application/json",
      Authorization: `Bearer ${this.#token}`,
    });
    if (this.#organization)
      headers.set("X-Lrail-Organization", this.#organization);
    if (options.idempotencyKey)
      headers.set("Idempotency-Key", options.idempotencyKey);
    if (options.body !== undefined)
      headers.set("Content-Type", "application/json");
    const request: RequestInit = {
      method: options.method,
      headers,
    };
    if (options.body !== undefined) request.body = JSON.stringify(options.body);
    const response = await this.#fetch(new URL(path, this.#baseUrl), request);
    const contentLength = Number(response.headers.get("content-length") ?? "0");
    if (contentLength > MAX_API_RESPONSE_BYTES) {
      throw new Error("Lrail API response exceeded the safety limit");
    }
    const raw = await response.text();
    if (Buffer.byteLength(raw) > MAX_API_RESPONSE_BYTES) {
      throw new Error("Lrail API response exceeded the safety limit");
    }
    let payload: unknown;
    try {
      payload = JSON.parse(raw);
    } catch {
      throw new Error(`Lrail API returned non-JSON HTTP ${response.status}`);
    }
    if (!response.ok) {
      const message =
        (payload as { error?: { message?: string } }).error?.message ??
        `HTTP ${response.status}`;
      throw new Error(message);
    }
    return payload as T;
  }
}

function retryableStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function validateTransport(url: URL, name: string): void {
  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]";
  if (
    url.username ||
    url.password ||
    (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
  ) {
    throw new Error(
      `${name} URL must use HTTPS or loopback HTTP without user information`,
    );
  }
}
