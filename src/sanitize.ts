export interface SanitizeOptions {
  /** Default 10 000 characters. */
  maxLength?: number;
}

/**
 * Cleans user text before it goes into a prompt: removes control and invisible
 * characters, chat-template markers like `[INST]` or `<|im_start|>`, and caps the length.
 *
 * Run `analyzeMessage` / `guard.check` on the raw text first. Sanitizing removes the
 * markers the analyzer looks for.
 */
export function sanitizeChat(message: string, { maxLength = 10_000 }: SanitizeOptions = {}): string {
  return message
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
    .replace(/[​-‏⁠-⁤﻿­]/g, "")
    .replace(/<\|[^|>]{1,32}\|>/g, "")
    .replace(/\[\/?(INST|SYS|SYSTEM)\]|<<\/?SYS>>/gi, "")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim()
    .slice(0, maxLength);
}
