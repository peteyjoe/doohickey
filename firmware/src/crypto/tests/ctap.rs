//! Compile the real protocol modules on the host. No USB, OTP or flash access.
#[allow(dead_code, unused_imports)]
#[path = "../../ctap/mod.rs"]
mod ctap;

use ctap::{
    Command, Handlers, Request, RequestContext, Result, Status,
    credential_management as management, credentials::*, extensions::*, pin_uv,
};
use doohickey_crypto::ctap::{PinUvKeyAgreement, PinUvProtocol};
use hex_literal::hex;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use zeroize::Zeroizing;

fn ready<F: core::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = core::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        core::task::Poll::Ready(value) => value,
        core::task::Poll::Pending => panic!("test handlers complete immediately"),
    }
}

#[test]
fn command_namespace_accepts_only_the_selected_core() {
    for byte in 0..=u8::MAX {
        let supported = [1, 2, 4, 6, 7, 8, 10, 11].contains(&byte);
        match Command::try_from(byte) {
            Ok(command) => {
                assert!(supported);
                assert_eq!(command as u8, byte);
            }
            Err(status) => {
                assert!(!supported);
                assert_eq!(status, Status::InvalidCommand);
            }
        }
    }
    for byte in 0..=u8::MAX {
        assert_eq!(
            management::Subcommand::try_from(byte).is_ok(),
            (1..=7).contains(&byte)
        );
    }
    assert_eq!(Status::PinAuthInvalid as u8, 0x33);
    assert_eq!(Status::KeepaliveCancel as u8, 0x2d);
    assert_eq!(ctap::status::CTAP2_OK, 0);
}

#[test]
fn algorithm_selection_skips_unsupported_preferences() {
    let params = [
        Parameter {
            credential_type: "public-key",
            algorithm: -257,
        },
        Parameter {
            credential_type: "other",
            algorithm: ES256,
        },
        Parameter {
            credential_type: "public-key",
            algorithm: ES256,
        },
    ];
    assert_eq!(select_algorithm(&params), Ok(-7));
    assert_eq!(
        select_algorithm(&params[..2]),
        Err(Status::UnsupportedAlgorithm)
    );
    assert_eq!(select_algorithm(&[]), Err(Status::UnsupportedAlgorithm));
    assert!(!MakeOptions::default().resident_key);
    assert!(MakeOptions::default().user_presence);
    assert!(MakeOptions::default().user_verification.is_none());
    assert!(AssertionOptions::default().user_presence);
}

#[test]
fn permissions_reject_unavailable_features_and_ignore_undefined_bits() {
    use pin_uv::{Permission::*, Permissions};
    for bits in 0..=u64::from(u8::MAX) {
        assert_eq!(
            Permissions::from_bits(bits).is_ok(),
            bits != 0 && bits & 0x78 == 0
        );
    }
    assert_eq!(Permissions::from_bits(0), Err(Status::InvalidParameter));
    assert_eq!(
        Permissions::from_bits(0x08),
        Err(Status::UnauthorizedPermission)
    );
    assert_eq!(Permissions::from_bits(1 << 63).unwrap().bits(), 0);
    assert_eq!(Permissions::from_bits(0x81).unwrap().bits(), 1);
    let cm = Permissions::from_bits(4).unwrap();
    assert!(cm.contains(CredentialManagement));
    assert!(!cm.requires_rp_id());
    let combined = Permissions::from_bits(7).unwrap();
    assert!(combined.contains(MakeCredential));
    assert!(combined.contains(GetAssertion));
    assert!(combined.requires_rp_id());
    assert_eq!(combined.bits(), 7);
    assert_eq!(pin_uv::Request::GetRetries.subcommand(), 1);
    assert_eq!(
        pin_uv::Request::GetKeyAgreement { protocol: 2 }.subcommand(),
        2
    );
}

#[test]
fn credential_protection_preserves_discovery_and_verification_boundaries() {
    use CredProtect::*;
    assert_eq!(CredProtect::default(), Optional);
    for uv in [false, true] {
        for supplied_id in [false, true] {
            assert!(Optional.permits_assertion(uv, supplied_id));
        }
    }
    assert!(!OptionalWithCredentialIdList.permits_assertion(false, false));
    assert!(OptionalWithCredentialIdList.permits_assertion(false, true));
    assert!(OptionalWithCredentialIdList.permits_assertion(true, false));
    assert!(!Required.permits_assertion(false, false));
    assert!(!Required.permits_assertion(false, true));
    assert!(Required.permits_assertion(true, false));
    assert!(Required.permits_assertion(true, true));
    for invalid in [0, 4, 255] {
        assert!(CredProtect::try_from(invalid).is_err());
    }
}

fn evidence(uv: bool) -> AssertionEvidence {
    AssertionEvidence {
        user_presence_requested: true,
        user_present: true,
        user_verified: uv,
    }
}

fn seeds() -> HmacSecret {
    let mut bytes = Zeroizing::new([0x11; 64]);
    bytes[32..].fill(0x22);
    HmacSecret::from_bytes(bytes)
}

#[test]
fn hmac_secret_matches_independent_vectors_for_both_uv_modes_and_salt_counts() {
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let authenticator = PinUvKeyAgreement::generate(&mut rng);
    let host = PinUvKeyAgreement::generate(&mut rng);
    let host_point = host.public_key();
    let shared = host
        .agree(&authenticator.public_key(), PinUvProtocol::Two)
        .unwrap();
    let original = seeds();
    // Reloading persisted seeds must preserve output, independently of sessions.
    let reloaded = HmacSecret::from_bytes(Zeroizing::new(*original.storage_bytes()));
    // Python stdlib hmac/hashlib fixtures, not computed with the helper under test.
    let expected_with_uv = hex!(
        "af052b22795d34c82a9326dd3c5b03e4c83647e0e56d7235c0bb72885e8eb11bd257d39eb5c42bd6555a5e7899bf46dc1b49c8d3803c96dc700b5b4c6901d46a"
    );
    let expected_without_uv = hex!(
        "0165c8c12b1fd89a414b98bf0ef4318ce5c45304ab736e92f33edd8fbbdfeb4d6fa74386f39a52ec7bc734ef931b7f712542afd91df5f72b2bfa3824454092e4"
    );
    for salt_len in [32, 64] {
        let mut salts = [0x33; 64];
        salts[32..].fill(0x44);
        let mut encrypted = [0; 80];
        let n = shared
            .encrypt(&mut rng, &salts[..salt_len], &mut encrypted)
            .unwrap();
        let mut auth = [0; 32];
        shared.authenticate(&encrypted[..n], &mut auth).unwrap();
        for uv in [false, true] {
            for secret in [&original, &reloaded] {
                let input = HmacSecretInput {
                    key_agreement: &host_point,
                    salt_enc: &encrypted[..n],
                    salt_auth: &auth,
                    protocol: Some(2),
                };
                let mut output = [0; 80];
                let m = secret
                    .process(&authenticator, input, evidence(uv), &mut rng, &mut output)
                    .unwrap();
                assert_eq!(m, salt_len + 16);
                let mut plaintext = [0; 64];
                assert_eq!(
                    shared.decrypt(&output[..m], &mut plaintext).unwrap(),
                    salt_len
                );
                let expected = if uv {
                    &expected_with_uv
                } else {
                    &expected_without_uv
                };
                assert_eq!(&plaintext[..salt_len], &expected[..salt_len]);
            }
        }
    }
}

#[test]
fn hmac_secret_rejects_unauthenticated_salts_and_unsupported_inputs() {
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let authenticator = PinUvKeyAgreement::generate(&mut rng);
    let host = PinUvKeyAgreement::generate(&mut rng);
    let host_point = host.public_key();
    let shared = host
        .agree(&authenticator.public_key(), PinUvProtocol::Two)
        .unwrap();
    let mut salt_enc = [0; 48];
    shared
        .encrypt(&mut rng, &[0x33; 32], &mut salt_enc)
        .unwrap();
    let mut auth = [0; 32];
    shared.authenticate(&salt_enc, &mut auth).unwrap();
    let secret = seeds();
    for protocol in [None, Some(1), Some(3)] {
        let mut output = [0xa5; 80];
        let input = HmacSecretInput {
            key_agreement: &host_point,
            salt_enc: &salt_enc,
            salt_auth: &auth,
            protocol,
        };
        assert_eq!(
            secret.process(&authenticator, input, evidence(true), &mut rng, &mut output),
            Err(Status::PinAuthInvalid)
        );
        assert_eq!(output, [0; 80]);
    }
    for offset in 0..salt_enc.len() {
        let mut changed = salt_enc;
        changed[offset] ^= 1;
        let mut output = [0xa5; 80];
        let input = HmacSecretInput {
            key_agreement: &host_point,
            salt_enc: &changed,
            salt_auth: &auth,
            protocol: Some(2),
        };
        assert_eq!(
            secret.process(&authenticator, input, evidence(true), &mut rng, &mut output),
            Err(Status::PinAuthInvalid)
        );
        assert_eq!(output, [0; 80]);
    }
    for (up_requested, present, status) in [
        (false, false, Status::UnsupportedOption),
        (true, false, Status::OperationDenied),
    ] {
        let input = HmacSecretInput {
            key_agreement: &host_point,
            salt_enc: &salt_enc,
            salt_auth: &auth,
            protocol: Some(2),
        };
        let mut output = [0xa5; 80];
        let proof = AssertionEvidence {
            user_presence_requested: up_requested,
            user_present: present,
            user_verified: true,
        };
        assert_eq!(
            secret.process(&authenticator, input, proof, &mut rng, &mut output),
            Err(status)
        );
        assert_eq!(output, [0; 80]);
    }
    let invalid_point = [0; 65];
    let input = HmacSecretInput {
        key_agreement: &invalid_point,
        salt_enc: &salt_enc,
        salt_auth: &auth,
        protocol: Some(2),
    };
    let mut output = [0xa5; 80];
    assert_eq!(
        secret.process(&authenticator, input, evidence(true), &mut rng, &mut output),
        Err(Status::InvalidParameter)
    );
    assert_eq!(output, [0; 80]);
    for len in [0, 1, 31, 47] {
        let mut output = vec![0xa5; len];
        let input = HmacSecretInput {
            key_agreement: &host_point,
            salt_enc: &salt_enc,
            salt_auth: &auth,
            protocol: Some(2),
        };
        assert_eq!(
            secret.process(&authenticator, input, evidence(true), &mut rng, &mut output),
            Err(Status::Other)
        );
        assert!(output.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn authenticated_wrong_salt_lengths_are_rejected_and_secret_generation_is_explicit() {
    let mut rng = ChaCha20Rng::from_seed([3; 32]);
    let first = HmacSecret::generate(&mut rng);
    let second = HmacSecret::generate(&mut rng);
    assert_ne!(first.storage_bytes(), second.storage_bytes());
    let authenticator = PinUvKeyAgreement::generate(&mut rng);
    let host = PinUvKeyAgreement::generate(&mut rng);
    let host_point = host.public_key();
    let shared = host
        .agree(&authenticator.public_key(), PinUvProtocol::Two)
        .unwrap();
    for len in [16, 48, 80] {
        let mut salt_enc = [0; 96];
        let n = shared
            .encrypt(&mut rng, &[0x33; 80][..len], &mut salt_enc)
            .unwrap();
        let mut auth = [0; 32];
        shared.authenticate(&salt_enc[..n], &mut auth).unwrap();
        let input = HmacSecretInput {
            key_agreement: &host_point,
            salt_enc: &salt_enc[..n],
            salt_auth: &auth,
            protocol: Some(2),
        };
        let mut output = [0xa5; 80];
        assert_eq!(
            first.process(&authenticator, input, evidence(true), &mut rng, &mut output),
            Err(Status::InvalidParameter)
        );
        assert_eq!(output, [0; 80]);
    }
}

// A recording backend is only a dispatch test, not a device implementation.
struct Backend {
    last: Option<(Command, u32)>,
    result: Result<usize>,
}
impl Backend {
    fn reply(
        &mut self,
        command: Command,
        context: RequestContext,
        output: &mut [u8],
    ) -> Result<usize> {
        self.last = Some((command, context.session_id));
        output.fill(0x55);
        self.result
    }
}
impl Handlers for Backend {
    async fn make_credential(
        &mut self,
        context: RequestContext,
        _request: MakeCredential<'_>,
        output: &mut [u8],
    ) -> Result<usize> {
        self.reply(Command::MakeCredential, context, output)
    }
    async fn get_assertion(
        &mut self,
        context: RequestContext,
        _request: GetAssertion<'_>,
        output: &mut [u8],
    ) -> Result<usize> {
        self.reply(Command::GetAssertion, context, output)
    }
    async fn get_info(&mut self, context: RequestContext, output: &mut [u8]) -> Result<usize> {
        self.reply(Command::GetInfo, context, output)
    }
    async fn client_pin(
        &mut self,
        context: RequestContext,
        _request: pin_uv::Request<'_>,
        output: &mut [u8],
    ) -> Result<usize> {
        self.reply(Command::ClientPin, context, output)
    }
    async fn reset(&mut self, context: RequestContext) -> Result<()> {
        self.reply(Command::Reset, context, &mut []).map(|_| ())
    }
    async fn get_next_assertion(
        &mut self,
        context: RequestContext,
        output: &mut [u8],
    ) -> Result<usize> {
        self.reply(Command::GetNextAssertion, context, output)
    }
    async fn credential_management(
        &mut self,
        context: RequestContext,
        _request: management::Request<'_>,
        output: &mut [u8],
    ) -> Result<usize> {
        self.reply(Command::CredentialManagement, context, output)
    }
    async fn selection(&mut self, context: RequestContext) -> Result<()> {
        self.reply(Command::Selection, context, &mut []).map(|_| ())
    }
}

#[test]
fn dispatch_routes_every_command_preserves_errors_and_clears_failed_output() {
    let hash = [0; 32];
    let make = MakeCredential {
        client_data_hash: &hash,
        rp: RelyingParty {
            id: "example.com",
            name: None,
        },
        user: User {
            id: b"account",
            name: None,
            display_name: None,
        },
        parameters: &[],
        exclude_list: None,
        options: MakeOptions::default(),
        auth: Default::default(),
        extensions: Default::default(),
        enterprise_attestation: None,
        attestation_formats_preference: &[],
    };
    let assertion = GetAssertion {
        rp_id: "example.com",
        client_data_hash: &hash,
        allow_list: None,
        options: AssertionOptions::default(),
        auth: Default::default(),
        hmac_secret: None,
    };
    let cm = management::Request {
        subcommand: management::Subcommand::GetMetadata,
        rp_id_hash: None,
        credential: None,
        user: None,
        auth: Default::default(),
        encoded_subcommand_params: None,
    };
    let cases = [
        (Command::MakeCredential, Request::MakeCredential(make)),
        (Command::GetAssertion, Request::GetAssertion(assertion)),
        (Command::GetInfo, Request::GetInfo),
        (
            Command::ClientPin,
            Request::ClientPin(pin_uv::Request::GetRetries),
        ),
        (Command::Reset, Request::Reset),
        (Command::GetNextAssertion, Request::GetNextAssertion),
        (
            Command::CredentialManagement,
            Request::CredentialManagement(cm),
        ),
        (Command::Selection, Request::Selection),
    ];
    for (command, request) in cases {
        let mut backend = Backend {
            last: None,
            result: Err(Status::OperationDenied),
        };
        let mut output = [0xa5; 32];
        assert_eq!(
            ready(ctap::execute(
                &mut backend,
                RequestContext { session_id: 42 },
                request,
                &mut output
            )),
            Err(Status::OperationDenied)
        );
        assert_eq!(backend.last, Some((command, 42)));
        assert_eq!(output, [0; 32]);
    }
}

#[test]
fn dispatch_rejects_invalid_backend_lengths_and_empty_responses_remain_empty() {
    let mut backend = Backend {
        last: None,
        result: Ok(33),
    };
    let mut output = [0xa5; 32];
    assert_eq!(
        ready(ctap::execute(
            &mut backend,
            RequestContext { session_id: 42 },
            Request::GetInfo,
            &mut output
        )),
        Err(Status::Other)
    );
    assert_eq!(output, [0; 32]);
    backend.result = Ok(2);
    assert_eq!(
        ready(ctap::execute(
            &mut backend,
            RequestContext { session_id: 42 },
            Request::GetInfo,
            &mut output
        )),
        Ok(2)
    );
    for request in [Request::Reset, Request::Selection] {
        output.fill(0xa5);
        assert_eq!(
            ready(ctap::execute(
                &mut backend,
                RequestContext { session_id: 42 },
                request,
                &mut output
            )),
            Ok(0)
        );
        assert_eq!(output, [0; 32]);
    }
}
