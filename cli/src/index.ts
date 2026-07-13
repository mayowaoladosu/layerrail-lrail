#!/usr/bin/env node

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
  .action(async (directory: string) => {
    const archive = await createSourceArchive(directory);
    process.stdout.write(
      `${JSON.stringify({
        archive_bytes: archive.bytes.length,
        archive_sha256: archive.sha256,
        manifest: archive.manifest,
      })}\n`,
    );
  });

program
  .command("source:upload")
  .description("Archive a directory and upload it directly to an Lrail project")
  .requiredOption("--project <id>", "project resource ID")
  .option("--directory <path>", "source directory", ".")
  .option(
    "--api-url <url>",
    "control-plane origin",
    process.env.LRAIL_API_URL ?? "http://127.0.0.1:3210/",
  )
  .option(
    "--organization <id>",
    "organization resource ID",
    process.env.LRAIL_ORGANIZATION,
  )
  .action(
    async (options: {
      project: string;
      directory: string;
      apiUrl: string;
      organization?: string;
    }) => {
      const token = process.env.LRAIL_API_TOKEN;
      if (!token) throw new Error("LRAIL_API_TOKEN is required");
      const archive = await createSourceArchive(options.directory);
      const partBytes = 16 * 1024 * 1024;
      const expectedParts = Math.ceil(archive.bytes.length / partBytes);
      const client = new LrailClient({
        apiUrl: options.apiUrl,
        token,
        ...(options.organization ? { organization: options.organization } : {}),
      });
      const authorization = await client.authorizeUpload(
        options.project,
        archive.bytes.length,
        archive.sha256,
        expectedParts,
        archive.manifest.excluded_count,
      );
      const parts = await client.uploadParts(authorization, archive.bytes);
      const result = await client.finalizeUpload(authorization.data.id, parts);
      process.stdout.write(`${JSON.stringify(result)}\n`);
    },
  );

program.parseAsync().catch((error: unknown) => {
  process.stderr.write(
    `lrail: ${error instanceof Error ? error.message : "unknown error"}\n`,
  );
  process.exitCode = 1;
});
