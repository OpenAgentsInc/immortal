export const ABI_VERSION = 1
export const REQUESTER_API_SHA256 =
  "bf52fda5f4d349fbbe195e4cff58af59a3930e1ee8ab1f1413b6338ba44fb3a8"

export class ImmortalClientError extends Error {
  constructor(code, detail) {
    super(`${code}: ${detail}`)
    this.name = "ImmortalClientError"
    this.code = code
    this.detail = detail
  }
}

export class ImmortalClient {
  static async instantiate(source, options = {}) {
    const expectedRevision = options.sourceRevision
    const expectedRequesterApi =
      options.requesterApiSha256 ?? REQUESTER_API_SHA256
    const bytes = await wasmBytes(source)
    const module = await WebAssembly.compile(bytes)
    const imports = WebAssembly.Module.imports(module)
    if (imports.length !== 0) {
      throw new ImmortalClientError(
        "browser_wasm_imports_forbidden",
        "the requester engine must not import host authority",
      )
    }
    const instance = await WebAssembly.instantiate(module, {})
    const client = new ImmortalClient(instance.exports)
    if (client.exports.immortal_mkt_swp_browser_abi_version() !== ABI_VERSION) {
      throw new ImmortalClientError(
        "browser_abi_version_mismatch",
        `expected browser ABI ${ABI_VERSION}`,
      )
    }
    const metadata = client.invoke("metadata", {})
    if (metadata.requester_api_sha256 !== expectedRequesterApi) {
      throw new ImmortalClientError(
        "browser_requester_api_mismatch",
        "the requester API contract digest does not match the host pin",
      )
    }
    if (expectedRevision && metadata.source_revision !== expectedRevision) {
      throw new ImmortalClientError(
        "browser_source_revision_mismatch",
        "the requester engine source revision does not match the host pin",
      )
    }
    client.metadata = Object.freeze(metadata)
    return client
  }

  constructor(exports) {
    const required = [
      "immortal_mkt_swp_browser_abi_version",
      "immortal_mkt_swp_browser_max_request_bytes",
      "immortal_mkt_swp_browser_max_response_bytes",
      "immortal_mkt_swp_browser_request_reset",
      "immortal_mkt_swp_browser_request_push",
      "immortal_mkt_swp_browser_invoke",
      "immortal_mkt_swp_browser_response_len",
      "immortal_mkt_swp_browser_response_byte",
    ]
    for (const name of required) {
      if (typeof exports[name] !== "function") {
        throw new ImmortalClientError(
          "browser_wasm_export_missing",
          `the requester engine omits ${name}`,
        )
      }
    }
    this.exports = exports
    this.metadata = undefined
  }

  invoke(operation, input) {
    const request = new TextEncoder().encode(
      JSON.stringify({ abi_version: ABI_VERSION, operation, input }),
    )
    const maximum = this.exports.immortal_mkt_swp_browser_max_request_bytes()
    if (request.byteLength > maximum) {
      throw new ImmortalClientError(
        "browser_request_bound",
        `request exceeds ${maximum} bytes`,
      )
    }
    checkStatus(this.exports.immortal_mkt_swp_browser_request_reset(), "reset")
    for (const byte of request) {
      checkStatus(
        this.exports.immortal_mkt_swp_browser_request_push(byte),
        "request transfer",
      )
    }
    checkStatus(this.exports.immortal_mkt_swp_browser_invoke(), "invoke")
    const length = this.exports.immortal_mkt_swp_browser_response_len()
    const maximumResponse =
      this.exports.immortal_mkt_swp_browser_max_response_bytes()
    if (length === 0 || length > maximumResponse) {
      throw new ImmortalClientError(
        "browser_response_bound",
        "the requester engine returned an invalid response length",
      )
    }
    const response = new Uint8Array(length)
    for (let index = 0; index < length; index += 1) {
      const byte = this.exports.immortal_mkt_swp_browser_response_byte(index)
      if (byte > 255) {
        throw new ImmortalClientError(
          "browser_response_invalid",
          "the requester engine response ended early",
        )
      }
      response[index] = byte
    }
    let document
    try {
      document = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(response))
    } catch (error) {
      throw new ImmortalClientError(
        "browser_response_invalid",
        `the requester engine returned invalid JSON: ${error.message}`,
      )
    }
    if (
      document.abi_version !== ABI_VERSION ||
      document.schema !== "openagents.immortal.mkt-swp.browser-abi.v1"
    ) {
      throw new ImmortalClientError(
        "browser_abi_version_mismatch",
        "the requester engine response contract is unsupported",
      )
    }
    if (document.error) {
      throw new ImmortalClientError(document.error.code, document.error.detail)
    }
    return document.result
  }
}

function checkStatus(status, action) {
  if (status !== 0) {
    throw new ImmortalClientError(
      "browser_wasm_state_error",
      `the requester engine failed during ${action} with status ${status}`,
    )
  }
}

async function wasmBytes(source) {
  if (source instanceof Response) {
    return source.arrayBuffer()
  }
  if (source instanceof ArrayBuffer || ArrayBuffer.isView(source)) {
    return source
  }
  const response = await fetch(source)
  if (!response.ok) {
    throw new ImmortalClientError(
      "browser_wasm_fetch_failed",
      `requester engine fetch returned HTTP ${response.status}`,
    )
  }
  return response.arrayBuffer()
}
