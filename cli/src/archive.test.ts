import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { createSourceArchive } from "./archive.js";

async function fixture(): Promise<string> {
  return mkdtemp(path.join(tmpdir(), "lrail-cli-"));
}

describe("createSourceArchive", () => {
  it("is deterministic, sorted, executable-aware, and ignore-aware", async () => {
    const root = await fixture();
    await mkdir(path.join(root, "bin"));
    await writeFile(path.join(root, "z.txt"), "z\n");
    await writeFile(path.join(root, "a.txt"), "a\n");
    await writeFile(path.join(root, "ignored.txt"), "ignored\n");
    await writeFile(path.join(root, ".gitignore"), "ignored.txt\n");
    await writeFile(path.join(root, ".env.example"), "SAFE=true\n");
    await writeFile(path.join(root, "é.txt"), "unicode\n");
    await mkdir(path.join(root, ".ssh"));
    await writeFile(path.join(root, ".ssh", "config"), "Host example\n");
    await writeFile(path.join(root, "bin", "start"), "#!/bin/sh\n", {
      mode: 0o755,
    });

    const first = await createSourceArchive(root);
    const second = await createSourceArchive(root);

    expect(first.sha256).toBe(second.sha256);
    expect(first.bytes.equals(second.bytes)).toBe(true);
    expect(first.manifest).toEqual(second.manifest);
    expect(first.manifest.entries.map((entry) => entry.path)).toEqual([
      ".env.example",
      ".gitignore",
      "a.txt",
      "bin/start",
      "z.txt",
      "é.txt",
    ]);
    expect(first.manifest.warnings).toEqual(
      process.platform === "win32" ? [] : ["executable source file: bin/start"],
    );
    expect(first.manifest.excluded_count).toBe(2);
  });

  it("rejects symlinks and secret material", async () => {
    const symlinkRoot = await fixture();
    await writeFile(path.join(symlinkRoot, "target"), "safe\n");
    await symlink(
      path.join(symlinkRoot, "target"),
      path.join(symlinkRoot, "link"),
    );
    await expect(createSourceArchive(symlinkRoot)).rejects.toThrow(
      "unsafe source entry",
    );

    const secretRoot = await fixture();
    await writeFile(
      path.join(secretRoot, "fixture.txt"),
      "-----BEGIN PRIVATE KEY-----\n",
    );
    await expect(createSourceArchive(secretRoot)).rejects.toThrow(
      "blocked credential marker",
    );

    const lateSecretRoot = await fixture();
    await writeFile(
      path.join(lateSecretRoot, "late.txt"),
      `${"a".repeat(1024 * 1024 + 1)}-----BEGIN PRIVATE KEY-----\n`,
    );
    await expect(createSourceArchive(lateSecretRoot)).rejects.toThrow(
      "blocked credential marker",
    );

    const apiKeyRoot = await fixture();
    const token = `lrail_key_${"A".repeat(12)}_${"b".repeat(43)}`;
    await writeFile(path.join(apiKeyRoot, "credentials.txt"), token);
    await expect(createSourceArchive(apiKeyRoot)).rejects.toThrow(
      "blocked credential marker",
    );
  });
});
