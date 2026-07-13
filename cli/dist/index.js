#!/usr/bin/env node
import { randomUUID } from "node:crypto";
import { Command } from "commander";
import { createSourceArchive } from "./archive.js";
import { LrailClient } from "./client.js";
const program = new Command();
program
    .name("lrail")
    .description("LayerRail Lrail developer CLI")
    .version("0.1.0");
program
    .command("source:inspect")
    .description("Build a safe deterministic source archive without uploading it")
    .argument("[directory]", "source directory", ".")
    .action(async (directory) => {
    const archive = await createSourceArchive(directory);
    process.stdout.write(`${JSON.stringify({
        archive_bytes: archive.bytes.length,
        archive_sha256: archive.sha256,
        manifest: archive.manifest,
    })}\n`);
});
program
    .command("source:upload")
    .description("Archive a directory and upload it directly to an Lrail project")
    .requiredOption("--project <id>", "project resource ID")
    .option("--directory <path>", "source directory", ".")
    .option("--api-url <url>", "control-plane origin", process.env.LRAIL_API_URL ?? "http://127.0.0.1:3210/")
    .option("--organization <id>", "organization resource ID", process.env.LRAIL_ORGANIZATION)
    .action(async (options) => {
    const token = process.env.LRAIL_API_TOKEN;
    if (!token)
        throw new Error("LRAIL_API_TOKEN is required");
    const archive = await createSourceArchive(options.directory);
    const partBytes = 16 * 1024 * 1024;
    const expectedParts = Math.ceil(archive.bytes.length / partBytes);
    const client = new LrailClient({
        apiUrl: options.apiUrl,
        token,
        ...(options.organization ? { organization: options.organization } : {}),
    });
    const result = await uploadSource(client, options.project, archive, expectedParts);
    process.stdout.write(`${JSON.stringify(result)}\n`);
});
program
    .command("deploy")
    .description("Upload local source, create a deployment, and follow retained build events")
    .argument("[directory]", "source directory", ".")
    .requiredOption("--project <id>", "project resource ID")
    .requiredOption("--environment <id>", "environment resource ID")
    .option("--accept-detected", "explicitly accept an unambiguous detector proposal")
    .option("--build-file <path>", "use a repository Lrailfile.star instead of detector configuration")
    .option("--manifest-revision <number>", "project manifest revision", "1")
    .option("--reason <text>", "deployment reason", "cli_local_deploy")
    .option("--no-wait", "return after the deployment is accepted")
    .option("--json", "emit newline-delimited JSON events")
    .option("--api-url <url>", "control-plane origin", process.env.LRAIL_API_URL ?? "http://127.0.0.1:3210/")
    .option("--organization <id>", "organization resource ID", process.env.LRAIL_ORGANIZATION)
    .action(async (directory, options) => {
    if (options.acceptDetected === Boolean(options.buildFile)) {
        throw new Error("choose exactly one of --accept-detected or --build-file");
    }
    const manifestRevision = positiveInteger(options.manifestRevision, "manifest revision");
    const client = clientFor(options);
    const archive = await createSourceArchive(directory);
    const expectedParts = Math.ceil(archive.bytes.length / (16 * 1024 * 1024));
    const upload = await uploadSource(client, options.project, archive, expectedParts);
    const deployment = await client.createDeployment(options.project, {
        environmentId: options.environment,
        source: { kind: "local", source_snapshot_id: upload.snapshot.id },
        manifestRevision,
        reason: options.reason,
        buildMode: options.buildFile ? "repository" : "auto",
        acceptDetected: Boolean(options.acceptDetected),
        ...(options.buildFile ? { buildFile: options.buildFile } : {}),
        idempotencyKey: `cli-deploy-${randomUUID()}`,
    });
    if (!options.wait) {
        process.stdout.write(`${JSON.stringify(deployment)}\n`);
        return;
    }
    const terminal = await followOperation(client, deployment.operation.id, 1, Boolean(options.json));
    assertSuccessful(terminal);
});
program
    .command("deploy:watch")
    .description("Resume ordered retained deployment events after a disconnect")
    .requiredOption("--operation <id>", "operation resource ID")
    .option("--generation <number>", "build generation", "1")
    .option("--after <sequence>", "last persisted sequence", "0")
    .option("--json", "emit newline-delimited JSON events")
    .option("--api-url <url>", "control-plane origin", process.env.LRAIL_API_URL ?? "http://127.0.0.1:3210/")
    .option("--organization <id>", "organization resource ID", process.env.LRAIL_ORGANIZATION)
    .action(async (options) => {
    const terminal = await followOperation(clientFor(options), options.operation, positiveInteger(options.generation, "generation"), Boolean(options.json), nonnegativeInteger(options.after, "event sequence"));
    assertSuccessful(terminal);
});
program
    .command("deploy:cancel")
    .description("Cancel one deployment and its exact active build generation")
    .requiredOption("--deployment <id>", "deployment resource ID")
    .option("--reason <text>", "cancellation reason", "cli_requested")
    .option("--api-url <url>", "control-plane origin", process.env.LRAIL_API_URL ?? "http://127.0.0.1:3210/")
    .option("--organization <id>", "organization resource ID", process.env.LRAIL_ORGANIZATION)
    .action(async (options) => {
    if (options.reason.length < 3 || options.reason.length > 512) {
        throw new Error("cancellation reason must contain 3 to 512 characters");
    }
    const result = await clientFor(options).cancelDeployment(options.deployment, `cli-cancel-${randomUUID()}`, options.reason);
    process.stdout.write(`${JSON.stringify(result)}\n`);
});
async function uploadSource(client, projectId, archive, expectedParts) {
    const authorization = await client.authorizeUpload(projectId, archive.bytes.length, archive.sha256, expectedParts, archive.manifest.excluded_count);
    const parts = await client.uploadParts(authorization, archive.bytes);
    return client.finalizeUpload(authorization.data.id, parts);
}
function clientFor(options) {
    const token = process.env.LRAIL_API_TOKEN;
    if (!token)
        throw new Error("LRAIL_API_TOKEN is required");
    return new LrailClient({
        apiUrl: options.apiUrl,
        token,
        ...(options.organization ? { organization: options.organization } : {}),
    });
}
async function followOperation(client, operationId, generation, json, initialSequence = 0) {
    let sequence = initialSequence;
    for (;;) {
        const batch = await client.getOperationEvents(operationId, generation, sequence);
        for (const event of batch.data)
            printEvent(event, json);
        if (batch.next_sequence < sequence) {
            throw new Error("operation event cursor moved backwards");
        }
        if (batch.data.length > 0 && batch.next_sequence === sequence) {
            throw new Error("operation event cursor did not advance");
        }
        sequence = batch.next_sequence;
        if (isTerminal(batch.operation))
            return batch.operation;
        await delay(750);
    }
}
function printEvent(event, json) {
    if (json) {
        process.stdout.write(`${JSON.stringify(event)}\n`);
        return;
    }
    const text = event.line ?? event.message;
    if (text)
        process.stdout.write(`${text}\n`);
    else if (event.kind !== "progress") {
        process.stdout.write(`[${event.stage}] ${event.kind}\n`);
    }
}
function assertSuccessful(operation) {
    if (operation.state === "succeeded") {
        process.stdout.write(`${JSON.stringify({ operation })}\n`);
        return;
    }
    const message = operation.error?.message ??
        operation.waiting_reason ??
        `deployment ended in ${operation.state}`;
    throw new Error(message);
}
function isTerminal(operation) {
    return ["succeeded", "failed", "canceled", "waiting"].includes(operation.state);
}
function positiveInteger(value, name) {
    const result = Number(value);
    if (!Number.isSafeInteger(result) || result < 1) {
        throw new Error(`${name} must be a positive integer`);
    }
    return result;
}
function nonnegativeInteger(value, name) {
    const result = Number(value);
    if (!Number.isSafeInteger(result) || result < 0) {
        throw new Error(`${name} must be a nonnegative integer`);
    }
    return result;
}
function delay(milliseconds) {
    return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
program.parseAsync().catch((error) => {
    process.stderr.write(`lrail: ${error instanceof Error ? error.message : "unknown error"}\n`);
    process.exitCode = 1;
});
//# sourceMappingURL=index.js.map