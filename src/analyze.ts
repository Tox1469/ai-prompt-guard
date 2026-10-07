import { DEFAULT_RULES, type Layer, type LayerRule, type ThreatLevel } from "./patterns.ts";

export interface CustomPattern {
  pattern: RegExp;
  layer?: Layer | (string & {});
  level?: ThreatLevel;
  weight?: number;
}

export interface AnalyzeOptions {
  /** Layers to skip, e.g. `["sql"]` for a coding assistant. */
  ignoreLayers?: Layer[];
  /** Extra rules, checked after the built-in ones. */
  extraPatterns?: CustomPattern[];
}

export interface ThreatResult {
  detected: boolean;
  level: ThreatLevel;
  layer: Layer | (string & {}) | null;
  /** Source of the regex that matched, for logs. Never the user's text. */
  pattern: string | null;
  weight: number;
  /** True when the match was found inside a base64 chunk, not in the plain text. */
  encoded: boolean;
}

const SAFE: ThreatResult = {
  detected: false,
  level: "none",
  layer: null,
  pattern: null,
  weight: 0,
  encoded: false,
};

// Cyrillic and Greek letters that render like Latin ones ("іgnоre" with Cyrillic і and о).
const LOOKALIKES: Record<string, string> = {
  а: "a", е: "e", о: "o", р: "p", с: "c", у: "y", х: "x", і: "i", ј: "j", ѕ: "s",
  А: "A", Е: "E", О: "O", Р: "P", С: "C", Х: "X", І: "I",
  ο: "o", α: "a", ε: "e", ι: "i", ν: "v", Ο: "O", Α: "A", Ε: "E",
};

/** The text the patterns actually see. Exported so you can log the same thing the guard judged. */
export function normalize(text: string): string {
  return text
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[​-‏⁠-⁤﻿­]/g, "")
    .replace(/[Ͱ-ϿЀ-ӿ]/g, (c) => LOOKALIKES[c] ?? c)
    .replace(/\s+/g, " ")
    .trim();
}

function match(text: string, rules: LayerRule[], extra: CustomPattern[]): Omit<ThreatResult, "encoded"> | null {
  for (const rule of rules) {
    for (const pattern of rule.patterns) {
      if (pattern.test(text)) {
        return { detected: true, level: rule.level, layer: rule.layer, pattern: pattern.source, weight: rule.weight };
      }
    }
  }
  for (const custom of extra) {
    if (custom.pattern.test(text)) {
      return {
        detected: true,
        level: custom.level ?? "high",
        layer: custom.layer ?? "custom",
        pattern: custom.pattern.source,
        weight: custom.weight ?? 2,
      };
    }
  }
  return null;
}

const BASE64_CHUNK = /[A-Za-z0-9+/]{16,}={0,2}/g;

function decodeChunks(message: string): string[] {
  const decoded: string[] = [];
  for (const chunk of message.match(BASE64_CHUNK) ?? []) {
    try {
      const text = atob(chunk.length % 4 === 0 ? chunk : chunk + "=".repeat(4 - (chunk.length % 4)));
      const printable = text.replace(/[^\x20-\x7E\n\t]/g, "").length;
      if (printable / text.length > 0.9) decoded.push(text);
    } catch {
      // not base64 after all
    }
  }
  return decoded;
}

export function analyzeMessage(message: string, options: AnalyzeOptions = {}): ThreatResult {
  if (typeof message !== "string" || message.length === 0) return SAFE;

  const ignore = new Set(options.ignoreLayers ?? []);
  const rules = ignore.size ? DEFAULT_RULES.filter((r) => !ignore.has(r.layer)) : DEFAULT_RULES;
  const extra = options.extraPatterns ?? [];

  const plain = match(normalize(message), rules, extra);
  if (plain) return { ...plain, encoded: false };

  for (const text of decodeChunks(message)) {
    const hidden = match(normalize(text), rules, extra);
    if (hidden) return { ...hidden, encoded: true };
  }

  return SAFE;
}
