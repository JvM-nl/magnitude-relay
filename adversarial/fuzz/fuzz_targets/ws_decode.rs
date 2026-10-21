#![no_main]

#[global_allocator]
static ALLOC: relay_adversarial::alloc::Counting = relay_adversarial::alloc::Counting;

libfuzzer_sys::fuzz_target!(|data: &[u8]| relay_adversarial::fuzz::libfuzzer_one("ws_decode", data));
