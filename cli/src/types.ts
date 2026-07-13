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
