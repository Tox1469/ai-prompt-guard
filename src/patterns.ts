export type ThreatLevel = "none" | "low" | "medium" | "high" | "critical";

export type Layer =
  | "direct_injection"
  | "prompt_extraction"
  | "jailbreak"
  | "token_smuggling"
  | "data_exfiltration"
  | "sql"
  | "indirect_injection"
  | "multilang";

export interface LayerRule {
  layer: Layer;
  level: ThreatLevel;
  /** How much one hit adds to a user's strike score. */
  weight: number;
  patterns: RegExp[];
}

// Patterns run against normalized text: case-insensitive, accents stripped
// ("instruções" -> "instrucoes"), invisible characters removed and whitespace collapsed.
// That is why the Portuguese rules below are written without accents.

const DIRECT_INJECTION = [
  /ignore\s+(all\s+)?(the\s+)?(previous|above|prior|earlier|system|initial)\s+(instructions?|prompts?|rules?|context)/i,
  /disregard\s+(all\s+)?(the\s+)?(previous|above|prior|your)\s+(instructions?|prompts?|rules?|programming)/i,
  /forget\s+(all\s+)?(the\s+)?(previous|your|above)\s+(instructions?|rules?|prompts?)/i,
  /override\s+(your|the|all)\s+(instructions?|rules?|prompts?|safety|guidelines)/i,
  /bypass\s+(your|the|all|any)\s+(instructions?|rules?|safety|restrictions?|filters?|guidelines)/i,
  /ignor[ea]\s+(todas?\s+)?(as\s+)?(suas\s+)?(instruc|regras?|prompt|ordens?|diretrizes)/i,
  /esquec[ea]\s+(todas?\s+)?(as\s+)?(suas\s+)?(instruc|regras?|ordens?)/i,
  /desconsider[ea]\s+(todas?\s+)?(as\s+)?(suas\s+)?(instruc|regras?|ordens?)/i,
  /sobrescrev[ea]\s+(as\s+)?(suas\s+)?(instruc|regras)/i,
];

const PROMPT_EXTRACTION = [
  /show\s+(me\s+)?(the\s+|your\s+)?(system\s+|initial\s+|original\s+)prompt/i,
  /reveal\s+(your\s+)?(system\s+|hidden\s+)?instructions?/i,
  /print\s+(your\s+)?(system\s+|initial\s+)prompt/i,
  /display\s+(your\s+)?(system\s+|original\s+)instructions?/i,
  /what\s+(are|is)\s+your\s+(system\s+)?prompt/i,
  /what\s+were\s+you\s+told\s+(to\s+do|initially)/i,
  /repeat\s+(the\s+|your\s+)?(system\s+|initial\s+|original\s+)(prompt|instructions?)/i,
  /mostr[ea]\s+(o\s+)?(seu\s+)?(system\s+)?prompt/i,
  /exib[ea]\s+(as\s+|suas\s+)?instrucoes/i,
  /repita\s+(o\s+|as\s+)?(seu\s+|suas\s+)?(prompt|instruc)/i,
  /qua(l|is)\s+(e\s+|sao\s+)?(o\s+|as\s+)?(seu\s+|suas\s+)?(prompt|instruc)/i,
  /me\s+(diga|fala|conta)\s+(o\s+)?(seu\s+)?prompt/i,
];

const JAILBREAK = [
  /\bDo\s+Anything\s+Now\b/i,
  /\bDAN\s+(mode|prompt)\b/i,
  /developer\s+mode/i,
  /modo\s+(desenvolvedor|dev|admin|root|sudo|deus)/i,
  /\bjailbreak\b/i,
  /you\s+are\s+now\s+(a\s+|an\s+|in\s+)?(new|different|unrestricted|uncensored|evil|dark)/i,
  /act\s+as\s+(if\s+)?(you\s+)?(have\s+no|are\s+not|were\s+not|had\s+no|unlimited|unrestricted)/i,
  /pretend\s+(you\s+)?(are|have)\s+(no|unlimited|unrestricted|full)/i,
  /roleplay\s+as\s+(an?\s+)?(evil|dark|unrestricted|hacker|admin)/i,
  /from\s+now\s+on\s+you\s+(are|will|must|can)/i,
  /enable\s+(unrestricted|god|admin|root|sudo)\s+mode/i,
  /voce\s+agora\s+e\s+(um|outro|livre|sem\s+restric)/i,
  /finja\s+que\s+(voce|vc)\s+(nao\s+tem|pode|e\s+um|tem\s+acesso)/i,
  /a\s+partir\s+de\s+agora\s+(voce|vc)\s+(e|vai|pode|deve)\b/i,
  /ativ[ea]\s+(o\s+)?modo\s+(sem\s+restric|deus|admin|root)/i,
];

const TOKEN_SMUGGLING = [
  /\[\/?INST\]/i,
  /\[\/?(system|sys)\]/i,
  /<\|(im_start|im_end|system|user|assistant)\|>/i,
  /<<\/?SYS>>/i,
  /###\s*(system|instruction|human)\s*:/i,
  /BEGINOF(INPUT|PROMPT)|ENDOFINPUT/i,
];

const DATA_EXFILTRATION = [
  /(show|list|print|reveal)\s+(me\s+)?(all\s+)?(the\s+|your\s+)?(api\s+keys?|secrets?|tokens|credentials|passwords)/i,
  /(show|dump|print)\s+(me\s+)?(the\s+)?(whole\s+|entire\s+)?database/i,
  /(show|print|list)\s+(me\s+)?(the\s+|your\s+)?env(ironment)?\s*(var|variable)/i,
  /what\s+(is|are)\s+(your|the)\s+(api\s+key|secret|credentials)/i,
  /service.?role.?key/i,
  /mostr[ea]\s+(as\s+|suas\s+)?(chaves?\s*(de\s+)?api|senhas|credenciais|tokens)/i,
  /mostr[ea]\s+(o\s+)?banco\s+de\s+dados/i,
  /qual\s+(e\s+)?(a\s+)?(sua\s+)?chave\s+(da\s+|de\s+)?api/i,
];

// Off by default for code assistants: `ignoreLayers: ["sql"]`.
const SQL = [
  /\bDROP\s+(TABLE|DATABASE|SCHEMA)\b/i,
  /\bDELETE\s+FROM\b/i,
  /\bTRUNCATE\s+TABLE\b/i,
  /\bALTER\s+TABLE\b/i,
  /\bUNION\s+(ALL\s+)?SELECT\b/i,
  /'\s*OR\s+'?1'?\s*=\s*'?1/i,
];

// Text hidden inside documents, emails or web pages that the model will read.
const INDIRECT_INJECTION = [
  /\[\s*(IMPORTANT\s*:\s*)?NEW\s+INSTRUCTIONS?\s*\]/i,
  /\[\s*(SYSTEM\s+UPDATE|ADMIN\s+OVERRIDE|PRIORITY\s+INSTRUCTIONS?)\s*\]/i,
  /\bAI\s*:\s*ignore\s+previous/i,
  /NOTE\s+TO\s+(THE\s+)?(AI|ASSISTANT|LLM)\s*:/i,
  /INSTRUCTIONS?\s+FOR\s+(THE\s+)?(AI|ASSISTANT|LLM)\s*:/i,
  /BEGIN\s+NEW\s+INSTRUCTIONS?/i,
  /INSTRUC(AO|OES)\s+PARA\s+(A\s+)?IA\s*:/i,
];

const MULTILANG = [
  /ignore[rz]?\s+(toutes\s+)?(les\s+)?instructions\s+(precedentes|anterieures)/i,
  /ignora\s+(todas\s+)?(las\s+)?instrucciones\s+(anteriores|previas)/i,
  /ignoriere?\s+(alle\s+)?(die\s+)?(vorherigen\s+)?anweisungen/i,
];

// Order matters: the first rule that matches wins, so the most severe go first.
export const DEFAULT_RULES: LayerRule[] = [
  { layer: "data_exfiltration", level: "critical", weight: 3, patterns: DATA_EXFILTRATION },
  { layer: "token_smuggling", level: "critical", weight: 3, patterns: TOKEN_SMUGGLING },
  { layer: "direct_injection", level: "high", weight: 2, patterns: DIRECT_INJECTION },
  { layer: "prompt_extraction", level: "high", weight: 2, patterns: PROMPT_EXTRACTION },
  { layer: "jailbreak", level: "high", weight: 2, patterns: JAILBREAK },
  { layer: "sql", level: "high", weight: 2, patterns: SQL },
  { layer: "indirect_injection", level: "medium", weight: 1, patterns: INDIRECT_INJECTION },
  { layer: "multilang", level: "medium", weight: 1, patterns: MULTILANG },
];
