#![cfg(target_arch = "wasm32")]

#[unsafe(no_mangle)]
pub extern "C" fn immortal_mkt_swp_provider_fixture_probe() -> u32 {
    immortal_provider::mkt_swp_fixture_probe()
}
