# Certificate Cloning for MITM via Custom CA

This repository demonstrates a core technique used in our project: cloning a server's TLS certificate and reissuing it with our own custom Certificate Authority (CA). This is a common approach used in man-in-the-middle (MITM) proxies that need to intercept and inspect HTTPS traffic.

## Overview

Using Rust libraries such as [`rcgen`](https://crates.io/crates/rcgen) and [`x509-parser`](https://crates.io/crates/x509-parser), this example extracts the original certificate served by the destination server, parses its key fields, and then recreates a new certificate with matching fields (e.g., Common Name, Subject Alternative Names, etc.). The cloned certificate is then signed using a trusted custom CA.

This approach enables on-the-fly certificate generation during HTTPS interception, where clients are presented with certificates that appear valid and match the original server's identity — while actually being issued by our own CA.

## Purpose

This repository is not intended to be a full MITM proxy implementation. It is a minimal and focused example showcasing one part of a larger HTTPS inspection system used internally. It may serve as a reference for those building secure networking tools, debuggers, or research utilities.

## Disclaimer

This code is provided for **educational** and **research** purposes only. Intercepting HTTPS traffic without consent may violate laws and ethical guidelines. Use responsibly and only in environments where you have explicit permission.

