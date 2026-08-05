use immortal_lab::funded;

#[test]
#[ignore = "requires the disposable funded regtest lab; run scripts/test-provider-funded.sh"]
fn funded_provider_completes_submarine_reverse_and_refund() {
    funded::run_funded_smoke().expect("funded provider live smoke failed");
}

#[test]
fn terminal_bitcoin_contract_reads_a_bounded_numeric_output_index() {
    funded::test_bounded_numeric_output_index();
}
