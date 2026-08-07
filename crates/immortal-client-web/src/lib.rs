//! Ordinary WebAssembly artifact for the Immortal requester browser API.
//!
//! Bytes cross the boundary through bounded byte-at-a-time functions instead
//! of raw pointers. The wrapper owns no signer, network, persistence, or wallet
//! capability; it delegates every request to `immortal_client::browser_api`.

#![deny(unsafe_op_in_unsafe_fn)]

use std::sync::Mutex;

use immortal_client::browser_api::{ABI_VERSION, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, dispatch};

const NO_BYTE: u32 = 256;
const STATE_ERROR: u32 = 1;
const REQUEST_TOO_LARGE: u32 = 2;

#[derive(Default)]
struct AbiState {
    request: Vec<u8>,
    response: Vec<u8>,
}

static STATE: Mutex<AbiState> = Mutex::new(AbiState {
    request: Vec::new(),
    response: Vec::new(),
});

#[unsafe(no_mangle)]
pub extern "C" fn immortal_mkt_swp_browser_abi_version() -> u32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn immortal_mkt_swp_browser_max_request_bytes() -> u32 {
    u32::try_from(MAX_REQUEST_BYTES).expect("browser request bound fits u32")
}

#[unsafe(no_mangle)]
pub extern "C" fn immortal_mkt_swp_browser_max_response_bytes() -> u32 {
    u32::try_from(MAX_RESPONSE_BYTES).expect("browser response bound fits u32")
}

#[unsafe(no_mangle)]
pub extern "C" fn immortal_mkt_swp_browser_request_reset() -> u32 {
    let Ok(mut state) = STATE.lock() else {
        return STATE_ERROR;
    };
    state.request.clear();
    state.response.clear();
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn immortal_mkt_swp_browser_request_push(byte: u32) -> u32 {
    if byte > u32::from(u8::MAX) {
        return STATE_ERROR;
    }
    let Ok(mut state) = STATE.lock() else {
        return STATE_ERROR;
    };
    if state.request.len() >= MAX_REQUEST_BYTES {
        return REQUEST_TOO_LARGE;
    }
    state.request.push(byte as u8);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn immortal_mkt_swp_browser_invoke() -> u32 {
    let Ok(mut state) = STATE.lock() else {
        return STATE_ERROR;
    };
    state.response = dispatch(&state.request);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn immortal_mkt_swp_browser_response_len() -> u32 {
    let Ok(state) = STATE.lock() else {
        return 0;
    };
    u32::try_from(state.response.len()).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn immortal_mkt_swp_browser_response_byte(index: u32) -> u32 {
    let Ok(state) = STATE.lock() else {
        return NO_BYTE;
    };
    usize::try_from(index)
        .ok()
        .and_then(|index| state.response.get(index))
        .copied()
        .map(u32::from)
        .unwrap_or(NO_BYTE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_wrapper_round_trips_metadata() {
        let request = br#"{"abi_version":1,"operation":"metadata","input":{}}"#;
        assert_eq!(immortal_mkt_swp_browser_request_reset(), 0);
        for byte in request {
            assert_eq!(immortal_mkt_swp_browser_request_push(u32::from(*byte)), 0);
        }
        assert_eq!(immortal_mkt_swp_browser_invoke(), 0);
        let response = (0..immortal_mkt_swp_browser_response_len())
            .map(|index| immortal_mkt_swp_browser_response_byte(index) as u8)
            .collect::<Vec<_>>();
        let response = String::from_utf8(response).expect("UTF-8 response");
        assert!(response.contains("\"custody\":\"host_owned\""));
    }
}
