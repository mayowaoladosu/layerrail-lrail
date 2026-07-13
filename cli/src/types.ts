export interface SourceManifestEntry {
  path: string;
  type: "file";
  mode: 420 | 493;
  size: number;
  sha256: `sha256:${string}`;
}

export interface SourceManifest {
  version: 1;
  policy_version: "source-v1";
  root_directory: string;
  entries: SourceManifestEntry[];
  included_count: number;
  included_bytes: number;
  excluded_count: number;
  warnings: string[];
  scan: { status: "passed"; findings: [] };
}

export interface SourceArchive {
  bytes: Buffer;
  sha256: `sha256:${string}`;
  manifest: SourceManifest;
}

export interface UploadAuthorization {
  data: {
    id: string;
    state: string;
    expires_at: string;
  };
  parts: Array<{ number: number; url: string; expires_at: string }>;
}

export interface UploadedPart {
  number: number;
  size: number;
  sha256: `sha256:${string}`;
}

export interface SourceUploadResult {
  data: {
    state: "complete";
    snapshot_sha256: `sha256:${string}`;
  };
  snapshot: {
    id: string;
    kind: "local" | "git" | "promoted" | "migration";
    digest: `sha256:${string}`;
    object_ref: string;
    size_bytes: number;
  };
}

export interface DeploymentResource {
  id: string;
  state: string;
  source_snapshot_id: string | null;
  operation_id: string;
  build_mode: "auto" | "repository";
  build_file: string | null;
  accept_detected: boolean;
  artifact_ready_at: string | null;
}

export interface OperationResource {
  id: string;
  state:
    | "accepted"
    | "running"
    | "waiting"
    | "retrying"
    | "succeeded"
    | "failed"
    | "canceling"
    | "canceled";
  stage: string;
  waiting_reason: string | null;
  progress: { completed: number; total: number };
  error: { code: string; message: string } | null;
}

export interface DeploymentCreateResult {
  data: DeploymentResource;
  operation: OperationResource;
}

export interface OperationEvent {
  generation: number;
  sequence: number;
  attempt: number;
  stage: string;
  kind: string;
  output: string | null;
  vertex: string | null;
  name: string | null;
  current: number | null;
  total: number | null;
  cached: boolean;
  stream: number;
  line: string | null;
  code: string | null;
  message: string | null;
  occurred_at: string;
}

export interface OperationEventsResult {
  data: OperationEvent[];
  operation: OperationResource;
  generation: number;
  next_sequence: number;
}
