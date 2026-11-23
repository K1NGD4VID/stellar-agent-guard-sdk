/**
 * Admin operations helpers for stellar-agent-guard smart accounts.
 *
 * Provides typed transaction submission and call construction helpers for
 * operator actions:
 *  - `submitSetPolicy` (updates spend caps, rolling windows, allowlists)
 *  - `submitFreeze` (emergency panic-button freeze)
 *  - `submitUnfreeze` (unfreezes account and re-arms heartbeat)
 *  - `submitRotateAgentKey` (re-binds the agent's Ed25519 public key)
 *
 * Policy encoding strictly reuses canonical `policyToScVal` from `src/policy.ts`
 * to guarantee identical field mapping, validation, and sorted ScMap serialization
 * with zero duplicated encoder logic.
 */
import { Keypair, StrKey, rpc, xdr } from "@stellar/stellar-sdk";
import { DEFAULT_RPC_TIMEOUT_MS, invoke, type InvokeOutcome } from "./invoke.ts";
import { InvalidInputError } from "./errors.ts";
import { systemClock, type Clock } from "./clock.ts";
import { hexToBytes } from "./hash.ts";
import { policyToScVal, type ContractAddress, type ReadonlyPolicyConfig } from "./policy.ts";
import type { AdminSigner, ContractCall } from "./tx.ts";

export const DEFAULT_NETWORK_PASSPHRASE = "Test SDF Network ; September 2015";

const AGENT_PUBLIC_KEY_FORMAT =
  "expected a valid G... Ed25519 public key, a 32-byte Uint8Array, a 64-character hex string, or a Keypair";

/** Convert a keypair, StrKey ('G...'), raw Uint8Array, or hex string to Soroban BytesN<32> ScVal. */
export function agentPubkeyToScVal(newAgent: string | Uint8Array | Keypair): xdr.ScVal {
  let publicKey: Uint8Array;
  if (
    typeof newAgent === "object" &&
    newAgent !== null &&
    "rawPublicKey" in newAgent &&
    typeof (newAgent as Keypair).rawPublicKey === "function"
  ) {
    publicKey = (newAgent as Keypair).rawPublicKey();
  } else if (newAgent instanceof Uint8Array) {
    publicKey = newAgent;
  } else if (typeof newAgent === "string") {
    if (newAgent.startsWith("G") && StrKey.isValidEd25519PublicKey(newAgent)) {
      publicKey = StrKey.decodeEd25519PublicKey(newAgent);
    } else if (/^[0-9a-fA-F]{64}$/.test(newAgent)) {
      publicKey = hexToBytes(newAgent);
    } else {
      throw new InvalidInputError("newAgent", "agent_public_key_format", AGENT_PUBLIC_KEY_FORMAT);
    }
  } else {
    throw new InvalidInputError("newAgent", "agent_public_key_format", AGENT_PUBLIC_KEY_FORMAT);
  }

  if (publicKey.length !== 32) {
    throw new InvalidInputError("newAgent", "agent_public_key_length", AGENT_PUBLIC_KEY_FORMAT);
  }
  return xdr.ScVal.scvBytes(Uint8Array.from(publicKey));
}

/** Build a contract call for set_policy, reusing canonical policyToScVal. */
export function buildSetPolicyCall(
  guard: ContractAddress,
  policy: ReadonlyPolicyConfig,
): ContractCall {
  return {
    contract: guard,
    fn: "set_policy",
    args: [policyToScVal(policy)],
  };
}

/** Build a contract call for freeze. */
export function buildFreezeCall(guard: ContractAddress): ContractCall {
  return {
    contract: guard,
    fn: "freeze",
    args: [],
  };
}

/** Build a contract call for unfreeze. */
export function buildUnfreezeCall(guard: ContractAddress): ContractCall {
  return {
    contract: guard,
    fn: "unfreeze",
    args: [],
  };
}

/** Build a contract call for rotate_agent_key. */
export function buildRotateAgentKeyCall(
  guard: ContractAddress,
  newAgent: string | Uint8Array | Keypair,
): ContractCall {
  return {
    contract: guard,
    fn: "rotate_agent_key",
    args: [agentPubkeyToScVal(newAgent)],
  };
}

/** The guard operations whose submissions this module brands as admin outcomes. */
export type AdminOpName = "set_policy" | "freeze" | "unfreeze" | "rotate_agent_key";

/** Identity of the admin operation that produced an {@link AdminOpOutcome}. */
export interface AdminOpMetadata {
  readonly op: AdminOpName;
  readonly guard: ContractAddress;
  /**
   * The hash the network assigned, or `null` when the operation never reached a
   * trackable broadcast (dry run, pre-broadcast failure, ambiguous response).
   */
  readonly transactionHash: string | null;
}

declare const adminOpBrand: unique symbol;
/**
 * An `invoke()` outcome returned by one of this module's submit helpers.
 *
 * The brand is type-only: `isAdminOpOutcome()` checks the runtime association,
 * so a plain `InvokeOutcome` cannot be passed to `waitForAdminOp()` by accident.
 */
export type AdminOpOutcome = InvokeOutcome & { readonly [adminOpBrand]: AdminOpMetadata };

const ADMIN_OP_OUTCOMES = new WeakMap<object, AdminOpMetadata>();

function brandAdminOutcome(outcome: InvokeOutcome, adminOp: AdminOpMetadata): AdminOpOutcome {
  ADMIN_OP_OUTCOMES.set(outcome, adminOp);
  return outcome as AdminOpOutcome;
}

/** True only for an outcome produced by one of this module's submit helpers. */
export function isAdminOpOutcome(value: unknown): value is AdminOpOutcome {
  return typeof value === "object" && value !== null && ADMIN_OP_OUTCOMES.has(value);
}

function nonEmptyHash(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/** Read the recovery hash from every outcome arm that can carry one. */
function transactionHashOf(outcome: InvokeOutcome): string | null {
  const record = outcome as {
    transactionHash?: unknown;
    submission?: { hash?: unknown } | null;
    error?: { transactionHash?: unknown; error?: { transactionHash?: unknown } } | null;
  };
  return (
    nonEmptyHash(record.transactionHash) ??
    nonEmptyHash(record.submission?.hash) ??
    nonEmptyHash(record.error?.transactionHash) ??
    nonEmptyHash(record.error?.error?.transactionHash) ??
    null
  );
}

/** Default bound for {@link waitForAdminOp}; a timeout is reported as `pending`. */
export const DEFAULT_ADMIN_OP_WAIT_TIMEOUT_MS = DEFAULT_RPC_TIMEOUT_MS;
const DEFAULT_ADMIN_OP_POLL_INTERVAL_MS = 1_000;

/** Terminal state of an admin operation's confirmation wait. */
export type AdminOpWaitStatus = "confirmed" | "failed" | "pending" | "undetermined";

/** What {@link waitForAdminOp} reports, with the submitting operation attached. */
export interface AdminOpWaitResult {
  readonly status: AdminOpWaitStatus;
  readonly transactionHash: string;
  readonly admin: AdminOpMetadata;
  /** One-line operator summary; never a substitute for `status`. */
  readonly detail: string;
  /** Ledger that included the transaction, when the RPC reported one. */
  readonly ledger: number | null;
}

export interface WaitForAdminOpOptions {
  /** RPC used only for `getTransaction(hash)`; no submission is ever made. */
  server: rpc.Server;
  /**
   * Overall wait budget in milliseconds. Defaults to
   * `DEFAULT_ADMIN_OP_WAIT_TIMEOUT_MS` (30s). A fired bound returns `pending`:
   * the transaction may still land. `0` waits without a time bound.
   */
  timeoutMs?: number | undefined;
  /** Caller cancellation. An abort returns `pending`; it never rebroadcasts. */
  signal?: AbortSignal | undefined;
  /** Delay between `getTransaction` polls. Defaults to 1,000ms. */
  pollIntervalMs?: number | undefined;
  /** Time source for the budget and poll delays. Defaults to `systemClock`. */
  clock?: Clock | undefined;
}

function assertWaitForAdminOpOptions(options: WaitForAdminOpOptions): void {
  if (typeof options !== "object" || options === null) {
    throw new InvalidInputError("options", "object", "waitForAdminOp requires options");
  }
  const server = options.server as { getTransaction?: unknown } | null | undefined;
  if (!server || typeof server.getTransaction !== "function") {
    throw new InvalidInputError("server", "rpc_server_with_getTransaction");
  }
  if (options.timeoutMs !== undefined) {
    if (!Number.isFinite(options.timeoutMs) || options.timeoutMs < 0) {
      throw new InvalidInputError(
        "timeoutMs",
        "finite_non_negative_number",
        String(options.timeoutMs),
      );
    }
  }
  if (options.pollIntervalMs !== undefined) {
    if (!Number.isFinite(options.pollIntervalMs) || options.pollIntervalMs < 0) {
      throw new InvalidInputError(
        "pollIntervalMs",
        "finite_non_negative_number",
        String(options.pollIntervalMs),
      );
    }
  }
  const signal = options.signal as
    | { aborted?: unknown; addEventListener?: unknown; removeEventListener?: unknown }
    | null
    | undefined;
  if (
    signal !== undefined &&
    signal !== null &&
    (typeof signal.aborted !== "boolean" ||
      typeof signal.addEventListener !== "function" ||
      typeof signal.removeEventListener !== "function")
  ) {
    throw new InvalidInputError("signal", "abort_signal");
  }
  const clock = options.clock as unknown;
  if (
    clock !== undefined &&
    (typeof clock !== "object" ||
      clock === null ||
      typeof (clock as Clock).now !== "function" ||
      typeof (clock as Clock).sleep !== "function")
  ) {
    throw new InvalidInputError("clock", "object_with_now_and_sleep");
  }
}

function abortableSleep(
  clock: Clock,
  delayMs: number,
  signal: AbortSignal | undefined,
): Promise<void> {
  if (!signal) return clock.sleep(delayMs);
  if (signal.aborted) return Promise.resolve();
  return new Promise<void>((resolve) => {
    const onAbort = () => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    };
    signal.addEventListener("abort", onAbort, { once: true });
    void clock.sleep(Math.max(0, delayMs)).then(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    });
  });
}

/**
 * Wait for an admin submission's transaction to be included.
 *
 * This is a read-only confirmation wrapper: it calls `getTransaction(hash)`
 * only, and returns a `pending` status (never a failure, never a rebroadcast)
 * when the budget or cancellation stops the wait. An RPC error is reported as
 * `undetermined` so the caller can reconcile the hash out of band.
 */
export async function waitForAdminOp(
  outcome: AdminOpOutcome,
  options: WaitForAdminOpOptions,
): Promise<AdminOpWaitResult> {
  assertWaitForAdminOpOptions(options);
  if (!isAdminOpOutcome(outcome)) {
    throw new InvalidInputError(
      "outcome",
      "admin_outcome",
      "pass the result of submitSetPolicy, submitFreeze, submitUnfreeze or submitRotateAgentKey",
    );
  }
  const adminOp = ADMIN_OP_OUTCOMES.get(outcome);
  const transactionHash = adminOp?.transactionHash;
  if (adminOp === undefined || transactionHash === null || transactionHash === undefined) {
    throw new InvalidInputError(
      "outcome",
      "admin_outcome_transaction_hash",
      "the operation has no trackable transaction hash",
    );
  }

  const clock = options.clock ?? systemClock;
  const timeoutMs = options.timeoutMs ?? DEFAULT_ADMIN_OP_WAIT_TIMEOUT_MS;
  const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_ADMIN_OP_POLL_INTERVAL_MS;
  const startedAt = clock.now();
  const result = (
    status: AdminOpWaitStatus,
    detail: string,
    ledger: number | null = null,
  ): AdminOpWaitResult => ({ status, transactionHash, admin: adminOp, detail, ledger });

  if (options.signal?.aborted) {
    return result("pending", `wait for transaction ${transactionHash} was aborted`);
  }

  for (;;) {
    const remainingMs = timeoutMs === 0 ? Infinity : timeoutMs - (clock.now() - startedAt);
    if (remainingMs <= 0) {
      return result(
        "pending",
        `transaction ${transactionHash} was not confirmed within ${timeoutMs}ms`,
      );
    }
    if (options.signal?.aborted) {
      return result("pending", `wait for transaction ${transactionHash} was aborted`);
    }

    let response: unknown;
    try {
      response = await options.server.getTransaction(transactionHash);
    } catch (error) {
      return result(
        "undetermined",
        `could not read transaction ${transactionHash}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
    if (options.signal?.aborted) {
      return result("pending", `wait for transaction ${transactionHash} was aborted`);
    }

    const statusValue = (response as { status?: unknown } | null)?.status;
    const ledgerValue = (response as { ledger?: unknown } | null)?.ledger;
    const ledger = typeof ledgerValue === "number" ? ledgerValue : null;
    if (statusValue === rpc.Api.GetTransactionStatus.SUCCESS) {
      return result("confirmed", `transaction ${transactionHash} was included`, ledger);
    }
    if (statusValue === rpc.Api.GetTransactionStatus.FAILED) {
      return result("failed", `transaction ${transactionHash} failed on the network`, ledger);
    }
    if (statusValue !== rpc.Api.GetTransactionStatus.NOT_FOUND) {
      return result(
        "undetermined",
        `transaction ${transactionHash} returned an unrecognized status: ${String(statusValue)}`,
      );
    }

    const waitMs = timeoutMs === 0 ? pollIntervalMs : Math.min(pollIntervalMs, remainingMs);
    await abortableSleep(clock, waitMs, options.signal);
  }
}

export interface AdminOpParams {
  server: rpc.Server;
  guard: ContractAddress;
  admin: Keypair | AdminSigner;
  source?: Keypair | AdminSigner | undefined;
  networkPassphrase?: string | undefined;
  dryRun?: boolean | undefined;
  pollAttempts?: number | undefined;
  pollIntervalMs?: number | undefined;
  /**
   * Caller-owned cancellation, forwarded to `invoke()` unchanged.
   *
   * An already-aborted signal short-circuits before any RPC call and produces
   * the same documented typed outcome an aborted `invoke()` produces: the
   * `error` arm carrying an `RpcTimeoutError` with `aborted: true`. A
   * mid-flight abort stops the operation at the next RPC boundary.
   *
   * Cancellation never relaxes the guard: it can only stop the SDK from
   * waiting, never turn a refusal into an approval.
   */
  signal?: AbortSignal | undefined;
  /**
   * Bound on each individual RPC call, in milliseconds, forwarded to
   * `invoke()` unchanged. Defaults to `DEFAULT_RPC_TIMEOUT_MS` (30s); pass
   * `0` to disable the bound and rely solely on `signal`.
   */
  timeoutMs?: number | undefined;
  /**
   * Optional local bound on each `AgentSigner.signDigest()` call inside the
   * underlying `invoke()`, in milliseconds. `0` keeps the signer unbounded.
   * A fired bound produces a typed `SignerTimeoutError` and is never retried.
   */
  signerTimeoutMs?: number | undefined;
}

export interface SetPolicyParams extends AdminOpParams {
  policy: ReadonlyPolicyConfig;
}

export interface RotateAgentKeyParams extends AdminOpParams {
  newAgent: string | Uint8Array | Keypair;
}

async function submitAdminOp(
  op: AdminOpName,
  params: AdminOpParams,
  call: ContractCall,
): Promise<AdminOpOutcome> {
  const outcome = await invoke({
    server: params.server,
    source: params.source ?? params.admin,
    call,
    networkPassphrase: params.networkPassphrase ?? DEFAULT_NETWORK_PASSPHRASE,
    accountSigners: [params.admin],
    dryRun: params.dryRun,
    pollAttempts: params.pollAttempts,
    pollIntervalMs: params.pollIntervalMs,
    signal: params.signal,
    timeoutMs: params.timeoutMs,
    signerTimeoutMs: params.signerTimeoutMs,
  });
  return brandAdminOutcome(outcome, {
    op,
    guard: params.guard,
    transactionHash: transactionHashOf(outcome),
  });
}

/**
 * Submit set_policy to the guard contract with an admin signer.
 * Reuses canonical policyToScVal without duplicating encoding logic.
 */
export function submitSetPolicy(params: SetPolicyParams): Promise<AdminOpOutcome> {
  return submitAdminOp("set_policy", params, buildSetPolicyCall(params.guard, params.policy));
}

/**
 * Submit freeze to the guard contract with an admin signer.
 */
export function submitFreeze(params: AdminOpParams): Promise<AdminOpOutcome> {
  return submitAdminOp("freeze", params, buildFreezeCall(params.guard));
}

/**
 * Submit unfreeze to the guard contract with an admin signer.
 */
export function submitUnfreeze(params: AdminOpParams): Promise<AdminOpOutcome> {
  return submitAdminOp("unfreeze", params, buildUnfreezeCall(params.guard));
}

/**
 * Submit rotate_agent_key to the guard contract with an admin signer.
 */
export function submitRotateAgentKey(params: RotateAgentKeyParams): Promise<AdminOpOutcome> {
  return submitAdminOp(
    "rotate_agent_key",
    params,
    buildRotateAgentKeyCall(params.guard, params.newAgent),
  );
}
