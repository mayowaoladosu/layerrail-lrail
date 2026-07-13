import type { DeploymentCreateResult, DeploymentResource, OperationEventsResult, OperationResource, SourceUploadResult, UploadAuthorization, UploadedPart } from "./types.js";
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
    finalizeUpload(sessionId: string, parts: UploadedPart[]): Promise<SourceUploadResult>;
    createDeployment(projectId: string, input: {
        environmentId: string;
        source: {
            kind: "local";
            source_snapshot_id: string;
        } | {
            kind: "git";
            connection_id: string;
            repository: string;
            commit: string;
            root_directory?: string;
        };
        manifestRevision: number;
        reason: string;
        buildMode: "auto" | "repository";
        acceptDetected: boolean;
        buildFile?: string;
        idempotencyKey: string;
    }): Promise<DeploymentCreateResult>;
    getDeployment(deploymentId: string): Promise<DeploymentResource>;
    cancelDeployment(deploymentId: string, idempotencyKey: string, reason: string): Promise<OperationResource>;
    getOperation(operationId: string): Promise<OperationResource>;
    getOperationEvents(operationId: string, generation: number, after: number, limit?: number): Promise<OperationEventsResult>;
}
export {};
