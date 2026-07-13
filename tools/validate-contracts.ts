import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020, { type AnySchema } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parse } from "yaml";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const contracts = resolve(root, "contracts");

const schemaFiles = [
  "jsonschema/common/resource-id.schema.json",
  "jsonschema/common/condition.schema.json",
  "jsonschema/common/error.schema.json",
  "jsonschema/common/operation.schema.json",
  "jsonschema/detector/detection-result.schema.json",
  "jsonschema/detector/detection-result-v2.schema.json",
  "events/domain-event.schema.json",
  "jsonschema/regional/target-bundle.schema.json",
  "jsonschema/build/build-ir.schema.json",
  "jsonschema/manifest/lrail.schema.json",
  "jsonschema/source/source-manifest.schema.json",
];

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);

const schemas = new Map<string, AnySchema>();
for (const relative of schemaFiles) {
  const schema = JSON.parse(
    readFileSync(resolve(contracts, relative), "utf8"),
  ) as AnySchema;
  const identifier = (schema as { $id?: string }).$id;
  if (!identifier) throw new Error(`${relative} has no $id`);
  if (schemas.has(identifier))
    throw new Error(`duplicate schema id ${identifier}`);
  schemas.set(identifier, schema);
  ajv.addSchema(schema, identifier);
}

const fixtureContracts: Record<string, string> = {
  "build-ir": "https://contracts.lrail.dev/build/build-ir.schema.json",
  detector: "https://contracts.lrail.dev/detector/detection-result.schema.json",
  "detector-v2":
    "https://contracts.lrail.dev/detector/v2/detection-result.schema.json",
  event: "https://contracts.lrail.dev/events/domain-event.schema.json",
  manifest: "https://contracts.lrail.dev/manifest/lrail.schema.json",
  operation: "https://contracts.lrail.dev/common/operation.schema.json",
  "source-manifest":
    "https://contracts.lrail.dev/source/source-manifest.schema.json",
  "target-bundle":
    "https://contracts.lrail.dev/regional/target-bundle.schema.json",
};

let fixtureCount = 0;
for (const file of readdirSync(resolve(contracts, "fixtures")).sort()) {
  const match =
    /^(build-ir|detector|detector-v2|event|manifest|operation|source-manifest|target-bundle)\.(valid|invalid)\.json$/.exec(
      file,
    );
  if (!match) continue;
  const [, contract, expectation] = match;
  const validate = ajv.getSchema(fixtureContracts[contract]);
  if (!validate) throw new Error(`validator missing for ${contract}`);
  const fixture = JSON.parse(
    readFileSync(resolve(contracts, "fixtures", file), "utf8"),
  );
  const valid = validate(fixture);
  if ((expectation === "valid") !== valid) {
    throw new Error(
      `${file}: expected ${expectation}, got ${valid}; ${ajv.errorsText(validate.errors)}`,
    );
  }
  fixtureCount += 1;
}

const openapi = parse(
  readFileSync(resolve(contracts, "openapi/lrail-v1.yaml"), "utf8"),
) as {
  paths: Record<string, Record<string, unknown>>;
};
const methods = new Set(["get", "post", "put", "patch", "delete"]);
let operationCount = 0;
for (const [path, pathItem] of Object.entries(openapi.paths)) {
  for (const [method, rawOperation] of Object.entries(pathItem)) {
    if (!methods.has(method)) continue;
    const operation = rawOperation as {
      operationId?: string;
      parameters?: Array<{ name?: string; $ref?: string }>;
      [key: string]: unknown;
    };
    operationCount += 1;
    if (!operation.operationId)
      throw new Error(`${method.toUpperCase()} ${path} lacks operationId`);
    if (
      !path.startsWith("/live") &&
      !path.startsWith("/ready") &&
      !operation["x-lrail-action"]
    ) {
      throw new Error(`${operation.operationId} lacks x-lrail-action`);
    }
    if (["post", "put", "patch", "delete"].includes(method)) {
      const parameters = operation.parameters ?? [];
      const idempotent = parameters.some(
        (parameter) =>
          parameter.name === "Idempotency-Key" ||
          parameter.$ref === "#/components/parameters/IdempotencyKey",
      );
      if (!idempotent)
        throw new Error(`${operation.operationId} lacks Idempotency-Key`);
    }
  }
}

if (fixtureCount !== 16)
  throw new Error(`expected 16 contract fixtures, validated ${fixtureCount}`);
if (operationCount < 20)
  throw new Error(
    `expected at least 20 public operations, found ${operationCount}`,
  );

console.log(
  `Validated ${schemaFiles.length} schemas, ${fixtureCount} fixtures, and ${operationCount} API operations.`,
);
