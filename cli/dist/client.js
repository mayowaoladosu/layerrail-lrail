import { createHash, randomUUID } from "node:crypto";
export class LrailClient {
    #baseUrl;
    #token;
    #organization;
    #fetch;
    constructor(options) {
        this.#baseUrl = new URL(options.apiUrl);
        validateTransport(this.#baseUrl, "control-plane");
        if (!this.#baseUrl.pathname.endsWith("/"))
            this.#baseUrl.pathname += "/";
        this.#token = options.token;
        this.#organization = options.organization;
        this.#fetch = options.fetch ?? globalThis.fetch;
    }
    async authorizeUpload(projectId, archiveBytes, archiveSha256, expectedParts, excludedCount) {
        return this.#request(`v1/projects/${encodeURIComponent(projectId)}/source_uploads`, {
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
        });
    }
    async uploadParts(authorization, bytes) {
        const parts = [...authorization.parts].sort((left, right) => left.number - right.number);
        const partCount = parts.length;
        if (partCount < 1)
            throw new Error("server returned no source upload parts");
        if (parts.some((part, index) => part.number !== index + 1)) {
            throw new Error("server returned invalid source upload part numbers");
        }
        const chunkBytes = Math.ceil(bytes.length / partCount);
        if (chunkBytes > 16 * 1024 * 1024)
            throw new Error("server returned insufficient source upload parts");
        const uploaded = [];
        for (const part of parts) {
            validateTransport(new URL(part.url), `source part ${part.number}`);
            const offset = (part.number - 1) * chunkBytes;
            const body = bytes.subarray(offset, Math.min(offset + chunkBytes, bytes.length));
            if (body.length === 0)
                throw new Error(`empty source upload part ${part.number}`);
            const uploadBody = Uint8Array.from(body).buffer;
            const response = await this.#fetch(part.url, {
                method: "PUT",
                body: uploadBody,
            });
            if (!response.ok)
                throw new Error(`source part ${part.number} upload failed with HTTP ${response.status}`);
            uploaded.push({
                number: part.number,
                size: body.length,
                sha256: `sha256:${createHash("sha256").update(body).digest("hex")}`,
            });
        }
        return uploaded;
    }
    async finalizeUpload(sessionId, parts) {
        return this.#request(`v1/source_uploads/${encodeURIComponent(sessionId)}/finalize`, {
            method: "POST",
            idempotencyKey: randomUUID(),
            body: { source_upload: { parts } },
        });
    }
    async #request(path, options) {
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
        const request = {
            method: options.method,
            headers,
        };
        if (options.body !== undefined)
            request.body = JSON.stringify(options.body);
        const response = await this.#fetch(new URL(path, this.#baseUrl), request);
        const raw = await response.text();
        let payload;
        try {
            payload = JSON.parse(raw);
        }
        catch {
            throw new Error(`Lrail API returned non-JSON HTTP ${response.status}`);
        }
        if (!response.ok) {
            const message = payload.error?.message ??
                `HTTP ${response.status}`;
            throw new Error(message);
        }
        return payload;
    }
}
function validateTransport(url, name) {
    const loopback = url.hostname === "localhost" ||
        url.hostname === "127.0.0.1" ||
        url.hostname === "[::1]";
    if (url.username ||
        url.password ||
        (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))) {
        throw new Error(`${name} URL must use HTTPS or loopback HTTP without user information`);
    }
}
//# sourceMappingURL=client.js.map