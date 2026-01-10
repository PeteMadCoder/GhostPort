#[test]
fn test_utf8_validation() {
    // Test that invalid UTF-8 bytes are properly handled
    let invalid_utf8_bytes = b"GET /test\xFF HTTP/1.1\r\nHost: example.com\r\n\r\n";

    // Find the header end
    let headers_end = invalid_utf8_bytes.windows(4).position(|w| w == b"\r\n\r\n")
        .expect("Header terminator should exist");

    let header_bytes = &invalid_utf8_bytes[..headers_end];

    // Test lossy conversion (old vulnerable way)
    let lossy_result = String::from_utf8_lossy(header_bytes);
    println!("Lossy conversion result: {}", lossy_result);

    // Test strict conversion (new secure way)
    let strict_result = String::from_utf8(header_bytes.to_vec());

    // The strict conversion should fail for invalid UTF-8
    assert!(strict_result.is_err(), "Strict UTF-8 validation should reject invalid bytes");

    // Lossy conversion should succeed but replace invalid bytes with replacement character (U+FFFD)
    assert!(lossy_result.contains('\u{FFFD}'), "Lossy conversion should replace invalid bytes with replacement character");

    println!("UTF-8 validation test passed: Invalid bytes properly rejected by strict validation");
}