export function normalizedRepository(value: string): string {
  const result = value.trim().toLowerCase();
  if (
    !/^[a-z0-9](?:[a-z0-9_.-]{0,98}[a-z0-9])?\/[a-z0-9_.-]{1,100}$/u.test(
      result,
    )
  ) {
    throw new Error("repository must be an owner/name identifier");
  }
  return result;
}

export function normalizedCommit(value: string): string {
  const result = value.trim().toLowerCase();
  if (
    !/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/u.test(result) ||
    /^0+$/u.test(result)
  ) {
    throw new Error("commit must be an exact nonzero 40 or 64 character SHA");
  }
  return result;
}

export function normalizedRoot(value: string): string {
  const result = value.trim();
  if (result === "") return result;

  const parts = result.split("/");
  if (
    result.length > 512 ||
    result.startsWith("/") ||
    result.endsWith("/") ||
    result.includes("\\") ||
    result.includes(":") ||
    parts.some((part) => part === "." || part === ".." || part === "")
  ) {
    throw new Error("root must be a canonical relative repository path");
  }
  return result;
}
