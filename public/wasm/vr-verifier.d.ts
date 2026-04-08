/* tslint:disable */
/* eslint-disable */

/**
 * Compute the BLAKE3 digest of arbitrary bytes, returned as a 64-char hex string.
 *
 * Useful for the website to compute digests client-side for display
 * without reimplementing BLAKE3 in JavaScript.
 */
export function digest_hex(input: Uint8Array): string;

/**
 * Return the verifier's schema profile version.
 *
 * Allows the website to display which profile version the WASM verifier uses,
 * ensuring transparency about verification semantics.
 */
export function verifier_version(): string;

/**
 * Verify a chain of receipt envelopes.
 *
 * Accepts the chain as a JSON array string.
 * Returns a `VerificationResult` serialized as JCS-canonical JSON.
 *
 * This function never throws. Malformed input produces an `INVALID` result.
 */
export function verify_chain_json(chain_json: string): string;

/**
 * Verify a single receipt envelope.
 *
 * Accepts the receipt envelope as a JSON string.
 * Returns a `VerificationResult` serialized as JCS-canonical JSON.
 *
 * This function never throws. Malformed input produces an `INVALID` result.
 */
export function verify_receipt_json(receipt_json: string): string;

/**
 * Verify a signed receipt envelope.
 *
 * Accepts the receipt envelope JSON and signature bundle JSON as separate strings.
 * Returns a `VerificationResult` serialized as JCS-canonical JSON.
 *
 * This function never throws. Malformed input produces an `INVALID` result.
 */
export function verify_signed_receipt_json(receipt_json: string, signature_json: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly digest_hex: (a: number, b: number) => [number, number];
    readonly verifier_version: () => [number, number];
    readonly verify_chain_json: (a: number, b: number) => [number, number];
    readonly verify_receipt_json: (a: number, b: number) => [number, number];
    readonly verify_signed_receipt_json: (a: number, b: number, c: number, d: number) => [number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
