import { analyzeMessage, type AnalyzeOptions, type ThreatResult } from "./analyze.ts";

export interface StrikeState {
  strikes: number;
  /** Sum of the weights of every hit inside the current window. */
  score: number;
  firstAt: number;
  lockedUntil: number | null;
}

/** Anything that can get/set a small JSON object by key: a Map, Redis, a database table. */
export interface StrikeStore {
  get(key: string): StrikeState | undefined | Promise<StrikeState | undefined>;
  set(key: string, state: StrikeState): void | Promise<void>;
  delete(key: string): void | Promise<void>;
}

export interface GuardOptions extends AnalyzeOptions {
  /** Score that locks the user. Default 5 (e.g. three high-severity hits, or two critical). */
  lockThreshold?: number;
  /** Strikes older than this are forgotten. Default 1 hour. */
  windowMs?: number;
  /** How long a lock lasts. Default 1 hour. Use `Infinity` to keep it until `reset()`. */
  lockMs?: number;
  /** Default: in-memory, per process. Use a shared store when you run more than one instance. */
  store?: StrikeStore;
  /** Called once, when a user crosses the threshold. Lock the account, alert someone, etc. */
  onLock?: (userId: string, state: StrikeState, threat: ThreatResult) => void | Promise<void>;
  /** Clock, for tests. */
  now?: () => number;
}

export interface CheckResult {
  /** Send the message to the model only when this is true. */
  allowed: boolean;
  locked: boolean;
  threat: ThreatResult;
  strikes: number;
  score: number;
}

/** In-memory store. Keeps at most `maxEntries` users and drops the oldest first. */
export function memoryStore(maxEntries = 10_000): StrikeStore {
  const map = new Map<string, StrikeState>();
  return {
    get: (key) => map.get(key),
    set: (key, state) => {
      map.delete(key);
      map.set(key, state);
      if (map.size > maxEntries) map.delete(map.keys().next().value!);
    },
    delete: (key) => void map.delete(key),
  };
}

export function createGuard(options: GuardOptions = {}) {
  const {
    lockThreshold = 5,
    windowMs = 60 * 60 * 1000,
    lockMs = 60 * 60 * 1000,
    store = memoryStore(),
    onLock,
    now = Date.now,
  } = options;

  async function current(userId: string): Promise<StrikeState | undefined> {
    const state = await store.get(userId);
    if (!state) return undefined;
    const t = now();
    const lockOver = state.lockedUntil !== null && t >= state.lockedUntil;
    const windowOver = state.lockedUntil === null && t - state.firstAt >= windowMs;
    if (lockOver || windowOver) {
      await store.delete(userId);
      return undefined;
    }
    return state;
  }

  return {
    /** Analyze a message from `userId`, count a strike if it is an attack, and tell you whether to let it through. */
    async check(userId: string, message: string): Promise<CheckResult> {
      const threat = analyzeMessage(message, options);
      let state = await current(userId);

      if (state?.lockedUntil != null) {
        return { allowed: false, locked: true, threat, strikes: state.strikes, score: state.score };
      }
      if (!threat.detected) {
        return { allowed: true, locked: false, threat, strikes: state?.strikes ?? 0, score: state?.score ?? 0 };
      }

      const t = now();
      state = state ?? { strikes: 0, score: 0, firstAt: t, lockedUntil: null };
      state = { ...state, strikes: state.strikes + 1, score: state.score + threat.weight };
      const locks = state.score >= lockThreshold;
      if (locks) state.lockedUntil = t + lockMs;
      await store.set(userId, state);
      if (locks) await onLock?.(userId, state, threat);

      return { allowed: false, locked: locks, threat, strikes: state.strikes, score: state.score };
    },

    async isLocked(userId: string): Promise<boolean> {
      return (await current(userId))?.lockedUntil != null;
    },

    /** Forget a user's strikes and lift any lock. */
    async reset(userId: string): Promise<void> {
      await store.delete(userId);
    },
  };
}

export type Guard = ReturnType<typeof createGuard>;
