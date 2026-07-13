import type { UploadAuthorization, UploadedPart } from "./types.js";
interface ClientOptions {
    apiUrl: string;
    token: string;
    organization?: string;
    fetch?: typeof globalThis.fetch;
}
export declare class LrailClient {
    #private;
    constructor(options: ClientOptions);
    authorizeUpload(projectId: string, archiveBytes: number, archiveSha256: string, expectedParts: number, excludedCount: number): Promise<UploadAuthorization>;
    uploadParts(authorization: UploadAuthorization, bytes: Buffer): Promise<UploadedPart[]>;
    finalizeUpload(sessionId: string, parts: UploadedPart[]): Promise<unknown>;
}
export {};
