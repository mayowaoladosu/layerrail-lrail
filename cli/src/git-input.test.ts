import { describe, expect, it } from "vitest";
import {
  normalizedCommit,
  normalizedRepository,
  normalizedRoot,
} from "./git-input.js";

describe("Git deployment input", () => {
  it("allows an omitted repository root and canonicalizes explicit values", () => {
    expect(normalizedRoot("")).toBe("");
    expect(normalizedRoot("  apps/web  ")).toBe("apps/web");
    expect(normalizedRepository(" Owner/Repository ")).toBe(
      "owner/repository",
    );
    expect(normalizedCommit(` ${"A".repeat(40)} `)).toBe("a".repeat(40));
  });

  it.each(["/apps/web", "apps/web/", "apps//web", "../web", "apps\\web"])(
    "rejects unsafe repository root %s",
    (value) => {
      expect(() => normalizedRoot(value)).toThrow(
        "root must be a canonical relative repository path",
      );
    },
  );
});
