/**
 * Sanitizes user input for safe processing.
 * Removes dangerous characters, normalizes whitespace,
 * and strips potential injection markers.
 */
export function sanitizeChat(message: string): string {
  let clean = message;

  // Remove null bytes
  clean = clean.replace(/\0/g, "");

  // Remove control characters (except newlines and tabs)
  clean = clean.replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // Normalize unicode whitespace to regular spaces
  clean = clean.replace(/[\u200B-\u200D\uFEFF\u00A0]/g, " ");

  // Remove potential prompt delimiter markers
  clean = clean.replace(/<\|[^|]*\|>/g, "");
  clean = clean.replace(/\[\/?(INST|SYS|SYSTEM)\]/gi, "");

  // Collapse excessive whitespace
  clean = clean.replace(/[ \t]+/g, " ");
  clean = clean.replace(/\n{3,}/g, "\n\n");

  // Trim
  clean = clean.trim();

  // Length limit (prevent token abuse)
  if (clean.length > 10000) {
    clean = clean.slice(0, 10000);
  }

  return clean;
}

/**
 * Sanitizes plain text output (strips HTML-like content).
 */
export function sanitizeText(text: string): string {
  return text
    .replace(/<[^>]*>/g, "")
    .replace(/&[a-z]+;/gi, "")
    .replace(/javascript:/gi, "")
    .replace(/on\w+\s*=/gi, "")
    .trim();
}
