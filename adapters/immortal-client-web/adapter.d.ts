export const ABI_VERSION: 1
export const REQUESTER_API_SHA256: string

export class ImmortalClientError extends Error {
  readonly code: string
  readonly detail: string
}

export interface ImmortalClientMetadata {
  readonly schema: "openagents.immortal.mkt-swp.browser-abi.v1"
  readonly abi_version: 1
  readonly source_revision: string
  readonly requester_api_sha256: string
  readonly maximum_request_bytes: number
  readonly maximum_response_bytes: number
  readonly operations: readonly string[]
  readonly custody: "host_owned"
}

export class ImmortalClient {
  static instantiate(
    source: Response | ArrayBuffer | ArrayBufferView | URL | string,
    options?: { sourceRevision?: string; requesterApiSha256?: string },
  ): Promise<ImmortalClient>

  readonly metadata: ImmortalClientMetadata
  invoke<Result = unknown>(operation: string, input: unknown): Result
}
