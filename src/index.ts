export { analyzeMessage, normalize } from "./analyze.ts";
export type { AnalyzeOptions, CustomPattern, ThreatResult } from "./analyze.ts";
export { createGuard, memoryStore } from "./guard.ts";
export type { CheckResult, Guard, GuardOptions, StrikeState, StrikeStore } from "./guard.ts";
export { sanitizeChat } from "./sanitize.ts";
export type { SanitizeOptions } from "./sanitize.ts";
export { DEFAULT_RULES } from "./patterns.ts";
export type { Layer, LayerRule, ThreatLevel } from "./patterns.ts";
