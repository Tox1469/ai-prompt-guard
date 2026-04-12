import type { InjectionType, Severity } from "./analyzer";

interface Strike {
  timestamp: number;
  type: InjectionType;
  severity: Severity;
  message: string;
}

interface StrikeRecord {
  strikes: Strike[];
  lockedUntil: number | null;
}

interface StrikeConfig {
  maxStrikes: number;
  lockDurationMs: number;
  logAttempts: boolean;
}

const DEFAULT_CONFIG: StrikeConfig = {
  maxStrikes: 3,
  lockDurationMs: 3600000, // 1 hour
  logAttempts: true,
};

// In-memory store. Replace with database for production.
const store = new Map<string, StrikeRecord>();

/**
 * Records a strike against a user for a detected injection attempt.
 * Returns whether the user is now locked.
 */
export async function recordStrike(
  userId: string,
  strike: Omit<Strike, "timestamp">,
  config: Partial<StrikeConfig> = {}
): Promise<{ locked: boolean; totalStrikes: number }> {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const now = Date.now();

  let record = store.get(userId);
  if (!record) {
    record = { strikes: [], lockedUntil: null };
    store.set(userId, record);
  }

  // Check if currently locked
  if (record.lockedUntil && now < record.lockedUntil) {
    return { locked: true, totalStrikes: record.strikes.length };
  }

  // Clear expired lock
  if (record.lockedUntil && now >= record.lockedUntil) {
    record.lockedUntil = null;
  }

  // Add strike
  record.strikes.push({ ...strike, timestamp: now });

  if (cfg.logAttempts) {
    console.warn(
      `[prompt-guard] Strike ${record.strikes.length}/${cfg.maxStrikes} for user ${userId}: ${strike.type} (${strike.severity})`
    );
  }

  // Lock if exceeded
  if (record.strikes.length >= cfg.maxStrikes) {
    record.lockedUntil = now + cfg.lockDurationMs;

    if (cfg.logAttempts) {
      console.warn(
        `[prompt-guard] User ${userId} LOCKED for ${cfg.lockDurationMs / 1000}s after ${record.strikes.length} strikes`
      );
    }

    return { locked: true, totalStrikes: record.strikes.length };
  }

  return { locked: false, totalStrikes: record.strikes.length };
}

/**
 * Checks if a user is currently locked.
 */
export function isLocked(userId: string): boolean {
  const record = store.get(userId);
  if (!record?.lockedUntil) return false;
  if (Date.now() >= record.lockedUntil) {
    record.lockedUntil = null;
    return false;
  }
  return true;
}

/**
 * Gets the strike history for a user.
 */
export function getStrikes(userId: string): Strike[] {
  return store.get(userId)?.strikes ?? [];
}

/**
 * Clears all strikes for a user (admin action).
 */
export function clearStrikes(userId: string): void {
  store.delete(userId);
}
