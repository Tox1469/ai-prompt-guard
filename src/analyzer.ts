export type Severity = "low" | "medium" | "high" | "critical";

export type InjectionType =
  | "role_override"
  | "system_leak"
  | "encoding_bypass"
  | "context_manipulation"
  | "data_extraction"
  | "instruction_injection"
  | "safe";

export interface AnalysisResult {
  isInjection: boolean;
  type: InjectionType;
  severity: Severity;
  confidence: number;
  matchedPattern: string | null;
}

interface Pattern {
  regex: RegExp;
  type: InjectionType;
  severity: Severity;
  weight: number;
}

const DEFAULT_PATTERNS: Pattern[] = [
  // Role override attempts
  {
    regex: /ignore\s+(all\s+)?(previous|your|above|prior)\s+(instructions|rules|prompts)/i,
    type: "role_override",
    severity: "critical",
    weight: 1.0,
  },
  {
    regex: /you\s+are\s+now\s+(a|an|the)\s+/i,
    type: "role_override",
    severity: "high",
    weight: 0.8,
  },
  {
    regex: /a\s+partir\s+de\s+agora\s+(você|vc|voce)\s+(é|eh|sera)/i,
    type: "role_override",
    severity: "high",
    weight: 0.8,
  },
  {
    regex: /ignore\s+(suas|as)\s+(instruções|instrucoes|regras)/i,
    type: "role_override",
    severity: "critical",
    weight: 1.0,
  },
  {
    regex: /forget\s+(everything|all|your)\s+(you|about|instructions)/i,
    type: "role_override",
    severity: "critical",
    weight: 1.0,
  },

  // System prompt leaking
  {
    regex: /show\s+(me\s+)?(your|the)\s+(system|initial|original)\s+prompt/i,
    type: "system_leak",
    severity: "high",
    weight: 0.9,
  },
  {
    regex: /repeat\s+(your|the)\s+(instructions|system\s+prompt|rules)/i,
    type: "system_leak",
    severity: "high",
    weight: 0.9,
  },
  {
    regex: /mostre\s+(seu|o)\s+(prompt|system\s*prompt|instrução)/i,
    type: "system_leak",
    severity: "high",
    weight: 0.9,
  },
  {
    regex: /what\s+(are|were)\s+your\s+(instructions|rules|guidelines)/i,
    type: "system_leak",
    severity: "high",
    weight: 0.85,
  },

  // Encoding bypass
  {
    regex: /base64|atob|btoa|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/i,
    type: "encoding_bypass",
    severity: "medium",
    weight: 0.6,
  },

  // Context manipulation
  {
    regex: /\[system\]|\[INST\]|<\|im_start\|>|<\|system\|>/i,
    type: "context_manipulation",
    severity: "critical",
    weight: 1.0,
  },
  {
    regex: /new\s+conversation|reset\s+context|start\s+over/i,
    type: "context_manipulation",
    severity: "medium",
    weight: 0.5,
  },

  // Data extraction
  {
    regex: /list\s+(all|every)\s+(users?|customers?|data|records?|emails?)/i,
    type: "data_extraction",
    severity: "high",
    weight: 0.85,
  },
  {
    regex: /dump\s+(the\s+)?(database|table|data|records)/i,
    type: "data_extraction",
    severity: "critical",
    weight: 1.0,
  },
  {
    regex: /liste\s+(todos?|todas?)\s+(os|as)\s+(usuários|dados|registros|clientes)/i,
    type: "data_extraction",
    severity: "high",
    weight: 0.85,
  },

  // Instruction injection
  {
    regex: /execute\s+(the\s+following|this|o\s+seguinte)\s+(command|code|script|comando)/i,
    type: "instruction_injection",
    severity: "critical",
    weight: 1.0,
  },
  {
    regex: /run\s+(this|the\s+following)\s+(code|query|script)/i,
    type: "instruction_injection",
    severity: "critical",
    weight: 1.0,
  },
];

/**
 * Analyzes a message for prompt injection patterns.
 * Returns the analysis result with type, severity, and confidence.
 */
export function analyzeMessage(
  message: string,
  customPatterns: Pattern[] = []
): AnalysisResult {
  const allPatterns = [...DEFAULT_PATTERNS, ...customPatterns];
  let highestMatch: { pattern: Pattern; match: string } | null = null;

  for (const pattern of allPatterns) {
    const match = message.match(pattern.regex);
    if (match) {
      if (!highestMatch || pattern.weight > highestMatch.pattern.weight) {
        highestMatch = { pattern, match: match[0] };
      }
    }
  }

  if (!highestMatch) {
    return {
      isInjection: false,
      type: "safe",
      severity: "low",
      confidence: 0,
      matchedPattern: null,
    };
  }

  return {
    isInjection: true,
    type: highestMatch.pattern.type,
    severity: highestMatch.pattern.severity,
    confidence: highestMatch.pattern.weight,
    matchedPattern: highestMatch.match,
  };
}
