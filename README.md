# Spoticord Content Decryption Module

A wrapper around Google's Widevine CDM that can be used to decrypt and use audio provided by Spotify's Web Playback SDK.

> This project is intended to be used by Spoticord. It has not been tested for performance or security. Use at your own risk!

> This project will not work on Windows devices as Google's Widevine CDM refuses to function inside unsigned programs.

> This project will be archived in the case it is ported to a more generic Widevine CDM wrapper for Rust

## Usage

```rs
use spoticord_cdm::{initialize, cdm_version, CdmInstance, ffi::cdm}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // You must load and initialize the CDM first
    initialize("/path/to/libwidevinecdm.so")?;

    println!("Widevine CDM version {}", cdm_version()?);

    // You can now create a CDM instance
    let cdm = CdmInstance::create()?;

    // (Optional) provide a server certificate
    let certificate = ... // fetch from server
    cdm.set_server_certificate(certificate)?;

    // Create a session
    let pssh = ... // fetch pssh info for encrypted content
    let (session, message) = cdm.create_session(pssh)?;

    // The first message should be a kLicenseRequest
    assert_eq!(message.message_type, cdm::MessageType::kLicenseRequest);

    // Request license from server
    let license = reqwest::blocking::Client::new()
        .post("https://example.com/widevine/license")
        .body(message.message)
        .send()?
        .error_for_status()? // Server may respond with 403
        .bytes()?;

    // Submit license to CDM
    session.update(&license)?;

    // We should now have access to one or multiple keys
    let keys = session.keys();
    let key = keys.first().unwrap(); // Grab the first key in this example

    let encrypted_chunk = ... // Fetch encrypted data from somewhere
    let iv = ... // Fetch or derive IV from encrypted data

    let plain = cdm.decrypt(
        // Assuming Cenc encryption
        EncryptedData::cenc(
            &encrypted_chunk,
            // Cenc optionally requires subsamples
            &[cdm::SubsampleEntry {
                clear_bytes: 8,
                cipher_bytes: (encrypted_chunk.len() - 8) as _,
            }],
        ),
        &iv,
        key, // Assuming first key is the correct key
    )?;

    println!("Decryption successful, output byte length: {}", plain.len());

    Ok(())
}
```
