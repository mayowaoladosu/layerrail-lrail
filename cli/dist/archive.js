import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { createGzip } from "node:zlib";
import ignore, {} from "ignore";
import tar from "tar-stream";
const MAX_ENTRIES = 50_000;
const MAX_FILE_BYTES = 128 * 1024 * 1024;
const MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_PATH_BYTES = 512;
const ALWAYS_EXCLUDED = [
    ".git/",
    ".svn/",
    ".hg/",
    ".ssh/",
    "node_modules/",
    ".env",
    ".env.*",
    "!.env.example",
    "**/id_rsa",
    "**/id_ed25519",
    "**/*.pem",
    "**/*.key",
];
const SECRET_MARKERS = [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "github_pat_",
    "ghp_",
];
const LRAIL_API_KEY_PATTERN = /lrail_key_[A-Za-z0-9]{12}_[A-Za-z0-9_-]{43}/;
export async function createSourceArchive(root) {
    const absoluteRoot = path.resolve(root);
    const rootStat = await fs.lstat(absoluteRoot);
    if (!rootStat.isDirectory())
        throw new Error("source root must be a directory");
    const matcher = await buildIgnoreMatcher(absoluteRoot);
    const candidates = [];
    let excludedCount = 0;
    let includedBytes = 0;
    async function walk(relativeDirectory) {
        const absoluteDirectory = path.join(absoluteRoot, relativeDirectory);
        const directoryEntries = await fs.readdir(absoluteDirectory, {
            withFileTypes: true,
        });
        directoryEntries.sort((left, right) => compareUtf8(left.name, right.name));
        for (const directoryEntry of directoryEntries) {
            const relative = normalizeRelative(path.posix.join(relativeDirectory.replaceAll("\\", "/"), directoryEntry.name));
            const absolute = path.join(absoluteRoot, ...relative.split("/"));
            if (matcher.ignores(relative) || matcher.ignores(`${relative}/`)) {
                excludedCount += 1;
                continue;
            }
            const stat = await fs.lstat(absolute);
            if (stat.isSymbolicLink() || (!stat.isFile() && !stat.isDirectory())) {
                throw new Error(`unsafe source entry: ${relative}`);
            }
            if (stat.isDirectory()) {
                await walk(relative);
                continue;
            }
            if (candidates.length >= MAX_ENTRIES)
                throw new Error("source entry limit exceeded");
            if (stat.size > MAX_FILE_BYTES)
                throw new Error(`source file exceeds limit: ${relative}`);
            includedBytes += stat.size;
            if (includedBytes > MAX_TOTAL_BYTES)
                throw new Error("source expanded byte limit exceeded");
            const bytes = await fs.readFile(absolute);
            rejectSecretMaterial(relative, bytes);
            candidates.push({
                absolute,
                entry: {
                    path: relative,
                    type: "file",
                    mode: stat.mode & 0o111 ? 493 : 420,
                    size: stat.size,
                    sha256: sha256(bytes),
                },
            });
        }
    }
    await walk("");
    candidates.sort((left, right) => compareUtf8(left.entry.path, right.entry.path));
    const warnings = candidates
        .filter(({ entry }) => entry.mode === 493)
        .map(({ entry }) => `executable source file: ${entry.path}`);
    const manifest = {
        version: 1,
        policy_version: "source-v1",
        root_directory: "",
        entries: candidates.map(({ entry }) => entry),
        included_count: candidates.length,
        included_bytes: includedBytes,
        excluded_count: excludedCount,
        warnings,
        scan: { status: "passed", findings: [] },
    };
    const pack = tar.pack();
    const gzip = createGzip({ level: 9 });
    const chunks = [];
    const output = pack.pipe(gzip);
    output.on("data", (chunk) => chunks.push(chunk));
    const complete = new Promise((resolve, reject) => {
        output.once("end", resolve);
        output.once("error", reject);
        pack.once("error", reject);
    });
    for (const candidate of candidates) {
        const bytes = await fs.readFile(candidate.absolute);
        await new Promise((resolve, reject) => {
            pack.entry({
                name: candidate.entry.path,
                size: candidate.entry.size,
                mode: candidate.entry.mode,
                type: "file",
                mtime: new Date(0),
                uid: 0,
                gid: 0,
                uname: "root",
                gname: "root",
            }, bytes, (error) => (error ? reject(error) : resolve()));
        });
    }
    pack.finalize();
    await complete;
    const bytes = Buffer.concat(chunks);
    if (bytes.length > 1024 * 1024 * 1024)
        throw new Error("compressed source archive exceeds limit");
    return { bytes, sha256: sha256(bytes), manifest };
}
async function buildIgnoreMatcher(root) {
    const matcher = ignore().add(ALWAYS_EXCLUDED);
    for (const name of [".gitignore", ".lrailignore"]) {
        try {
            matcher.add(await fs.readFile(path.join(root, name), "utf8"));
        }
        catch (error) {
            if (error.code !== "ENOENT")
                throw error;
        }
    }
    return matcher;
}
function normalizeRelative(value) {
    const normalized = value.normalize("NFC");
    if (!normalized ||
        normalized.startsWith("/") ||
        normalized.includes("\\") ||
        normalized.includes("\0") ||
        normalized.split("/").includes("..") ||
        Buffer.byteLength(normalized) > MAX_PATH_BYTES) {
        throw new Error(`unsafe source path: ${value}`);
    }
    return normalized;
}
function rejectSecretMaterial(relative, bytes) {
    const lower = relative.toLowerCase();
    const basename = path.posix.basename(lower);
    if (basename === ".env" ||
        (basename.startsWith(".env.") && basename !== ".env.example") ||
        basename === "id_rsa" ||
        basename === "id_ed25519") {
        throw new Error(`source contains blocked credential path: ${relative}`);
    }
    if (SECRET_MARKERS.some((marker) => bytes.includes(marker)) ||
        LRAIL_API_KEY_PATTERN.test(bytes.toString("utf8"))) {
        throw new Error(`source contains blocked credential marker: ${relative}`);
    }
}
function compareUtf8(left, right) {
    return Buffer.compare(Buffer.from(left.normalize("NFC"), "utf8"), Buffer.from(right.normalize("NFC"), "utf8"));
}
function sha256(bytes) {
    return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}
//# sourceMappingURL=archive.js.map