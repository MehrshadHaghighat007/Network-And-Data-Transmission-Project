Reflex Protocol Project
Contributors
Mobin Yousefi – ID: 402100594

Mehrshad Haghighat – ID: 402100418

Project Description
This project implements the Reflex Protocol for Xray-Core. It focuses on secure, high-performance data transmission using ChaCha20-Poly1305 encryption. Key features include traffic morphing (packet size and timing manipulation) to bypass deep packet inspection (DPI) and a robust replay protection mechanism using rolling nonces.

How to Run
To verify the implementation and run the comprehensive test suite, use the following commands:

Run All Tests:

Bash
go test -v ./tests/...
Run Performance Benchmarks:

Bash
go test -v -bench=. -benchmem ./tests/performance_test.go
Security Fuzzing:

Bash
go test -v -fuzz=FuzzReadFrame -fuzztime=30s ./tests/security_fuzz_test.go
Challenges and Solutions
Cross-Package Accessibility: We encountered issues accessing internal session fields from the external tests package. This was resolved by exporting the AEAD interface (changing aead to AEAD), allowing secure external validation of encrypted frames.

Interface Mocking: Testing the inbound.Handler required a specialized stat.Connection. We implemented a FakeConn wrapper to bridge the standard net.Pipe with Xray’s internal telemetry interfaces.

Replay Attacks & Race Conditions: During integration testing, we identified potential timing leaks and replay vulnerabilities. These were mitigated by implementing Constant-Time comparisons for sensitive data and strict Nonce sequencing for every frame.

Namespace Conflicts: Duplicate test declarations across multiple files were resolved by strictly organizing security and fuzzing logic into distinct, non-overlapping test functions within the tests package.
