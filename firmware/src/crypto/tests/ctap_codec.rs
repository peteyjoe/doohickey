//! Actual no_std codec with independently assembled test messages. No hardware
//! or credential/PIN backend is involved; fixture identities are synthetic.
#![allow(dead_code, unused_imports)]
#[path = "../../ctap/mod.rs"]
mod ctap;
use ctap::{
    Request, Status, cbor,
    codec::{self, Scratch},
    credential_management, pin_uv,
};

// Independent, allocating TEST encoder. Production parsing/encoding uses no heap.
enum C {
    U(u64),
    I(i64),
    B(Vec<u8>),
    T(&'static str),
    Bool(bool),
    A(Vec<C>),
    M(Vec<(C, C)>),
}
fn u(v: u64) -> C {
    C::U(v)
}
fn b(v: &[u8]) -> C {
    C::B(v.to_vec())
}
fn t(v: &'static str) -> C {
    C::T(v)
}
fn a(v: Vec<C>) -> C {
    C::A(v)
}
fn m(v: Vec<(C, C)>) -> C {
    C::M(v)
}
fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    if n < 24 {
        out.push(major << 5 | n as u8);
    } else if n <= 255 {
        out.extend([major << 5 | 24, n as u8]);
    } else if n <= 65535 {
        out.push(major << 5 | 25);
        out.extend((n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(major << 5 | 26);
        out.extend((n as u32).to_be_bytes());
    } else {
        out.push(major << 5 | 27);
        out.extend(n.to_be_bytes());
    }
}
fn encode(value: C) -> Vec<u8> {
    let mut out = Vec::new();
    match value {
        C::U(n) => head(&mut out, 0, n),
        C::I(n) if n >= 0 => head(&mut out, 0, n as u64),
        C::I(n) => head(&mut out, 1, (-1 - n) as u64),
        C::B(bytes) => {
            head(&mut out, 2, bytes.len() as u64);
            out.extend(bytes);
        }
        C::T(text) => {
            head(&mut out, 3, text.len() as u64);
            out.extend(text.bytes());
        }
        C::Bool(value) => out.push(if value { 0xf5 } else { 0xf4 }),
        C::A(values) => {
            head(&mut out, 4, values.len() as u64);
            for value in values {
                out.extend(encode(value));
            }
        }
        C::M(values) => {
            let mut values: Vec<_> = values
                .into_iter()
                .map(|(k, v)| (encode(k), encode(v)))
                .collect();
            values.sort_by(|(a, _), (b, _)| {
                (a[0] >> 5)
                    .cmp(&(b[0] >> 5))
                    .then(a.len().cmp(&b.len()))
                    .then(a.cmp(b))
            });
            head(&mut out, 5, values.len() as u64);
            for (k, v) in values {
                out.extend(k);
                out.extend(v);
            }
        }
    }
    out
}
fn wire(command: u8, value: C) -> Vec<u8> {
    let mut out = vec![command];
    out.extend(encode(value));
    out
}
fn error(input: &[u8]) -> Status {
    let mut scratch = Scratch::new();
    match codec::decode(input, &mut scratch) {
        Err(e) => e,
        Ok(_) => panic!("expected decode error"),
    }
}
fn cbor_error(input: &[u8]) -> Status {
    match cbor::decode(input) {
        Err(e) => e,
        Ok(_) => panic!("expected CBOR error"),
    }
}
fn rp() -> C {
    m(vec![(t("id"), t("example.com"))])
}
fn user() -> C {
    m(vec![
        (t("id"), b(&[1])),
        (t("name"), t("test")),
        (t("displayName"), t("Test User")),
    ])
}
fn descriptor() -> C {
    m(vec![(t("id"), b(&[7; 32])), (t("type"), t("public-key"))])
}
fn params() -> C {
    a(vec![
        m(vec![(t("alg"), C::I(-257)), (t("type"), t("public-key"))]),
        m(vec![(t("alg"), C::I(-7)), (t("type"), t("public-key"))]),
    ])
}
fn make(extra: Vec<(C, C)>) -> Vec<u8> {
    let mut fields = vec![
        (u(1), b(&[5; 32])),
        (u(2), rp()),
        (u(3), user()),
        (u(4), params()),
    ];
    fields.extend(extra);
    wire(1, m(fields))
}
fn assertion(extra: Vec<(C, C)>) -> Vec<u8> {
    let mut fields = vec![(u(1), t("example.com")), (u(2), b(&[5; 32]))];
    fields.extend(extra);
    wire(2, m(fields))
}
fn cose(kty: i64, alg: i64, curve: i64, point: &[u8]) -> C {
    m(vec![
        (u(1), C::I(kty)),
        (u(3), C::I(alg)),
        (C::I(-1), C::I(curve)),
        (C::I(-2), b(&point[1..33])),
        (C::I(-3), b(&point[33..])),
    ])
}
fn public_key() -> [u8; 65] {
    doohickey_crypto::ctap::Es256Key::from_bytes(&[1; 32])
        .unwrap()
        .public_key()
}

#[test]
fn golden_make_request_decodes_without_reencoding_or_allocating_input_values() {
    let msg = hex_literal::hex!(
        "01 a4 01 5820
        0000000000000000000000000000000000000000000000000000000000000000
        02 a1 626964 6b6578616d706c652e636f6d
        03 a1 626964 4101
        04 81 a2 63616c67 26 6474797065 6a7075626c69632d6b6579"
    );
    let mut scratch = Scratch::new();
    let Request::MakeCredential(request) = codec::decode(&msg, &mut scratch).unwrap() else {
        panic!()
    };
    assert_eq!(request.client_data_hash, &[0; 32]);
    assert_eq!(request.rp.id, "example.com");
    assert_eq!(request.user.id, &[1]);
    assert_eq!(request.parameters[0].algorithm, -7);
    assert!(request.exclude_list.is_none());
    assert!(request.auth.parameter.is_none());
    assert!(request.options.user_presence);
    assert!(!request.options.resident_key);
    assert!(request.options.user_verification.is_none());
    let p = request.rp.id.as_ptr() as usize;
    assert!((msg.as_ptr() as usize..msg.as_ptr() as usize + msg.len()).contains(&p));
}

#[test]
fn make_options_extensions_and_empty_vs_absent_fields_are_preserved() {
    let msg = make(vec![
        (u(5), a(vec![])),
        (
            u(6),
            m(vec![
                (t("credProtect"), u(3)),
                (t("hmac-secret"), C::Bool(false)),
            ]),
        ),
        (
            u(7),
            m(vec![
                (t("rk"), C::Bool(true)),
                (t("uv"), C::Bool(false)),
                (t("up"), C::Bool(false)),
            ]),
        ),
        (u(8), b(&[])),
        (u(9), u(2)),
        (u(10), u(1)),
        (u(11), a(vec![t("packed")])),
    ]);
    let mut scratch = Scratch::new();
    let Request::MakeCredential(r) = codec::decode(&msg, &mut scratch).unwrap() else {
        panic!()
    };
    assert!(r.exclude_list.unwrap().is_empty());
    assert_eq!(r.auth.parameter, Some(&[][..]));
    assert!(r.options.resident_key);
    assert!(!r.options.user_presence);
    assert_eq!(r.options.user_verification, Some(false));
    assert_eq!(
        r.extensions.cred_protect,
        Some(ctap::extensions::CredProtect::Required)
    );
    assert_eq!(r.extensions.hmac_secret, Some(false));
    assert_eq!(r.auth.protocol, Some(2));
    assert_eq!(r.enterprise_attestation, Some(1));
    assert_eq!(r.attestation_formats_preference, &["packed"]);
    assert_eq!(ctap::credentials::select_algorithm(r.parameters), Ok(-7));
}

#[test]
fn assertion_keeps_explicit_forbidden_rk_and_unknown_fields_are_validated_then_ignored() {
    let msg = assertion(vec![
        (u(3), a(vec![descriptor()])),
        (u(5), m(vec![(t("rk"), C::Bool(false))])),
        (u(99), m(vec![(t("future"), a(vec![u(1), C::Bool(true)]))])),
    ]);
    let mut scratch = Scratch::new();
    let Request::GetAssertion(r) = codec::decode(&msg, &mut scratch).unwrap() else {
        panic!()
    };
    assert_eq!(r.options.resident_key, Some(false));
    assert_eq!(r.allow_list.unwrap()[0].id, &[7; 32]);
    assert!(r.options.user_presence);
    assert!(r.hmac_secret.is_none());
    let msg = assertion(vec![(u(3), a(vec![]))]);
    let mut scratch = Scratch::new();
    let Request::GetAssertion(r) = codec::decode(&msg, &mut scratch).unwrap() else {
        panic!()
    };
    assert!(r.allow_list.unwrap().is_empty());
}

#[test]
fn pin_commands_decode_the_selected_subcommands_and_validate_ec2_points() {
    let point = public_key();
    for sub in [1, 2, 3, 4, 9] {
        let msg = wire(
            6,
            m(vec![
                (u(1), u(2)),
                (u(2), u(sub)),
                (u(3), cose(2, -25, 1, &point)),
                (u(4), b(&[8; 32])),
                (u(5), b(&[9; 80])),
                (u(6), b(&[10; 32])),
                (u(9), u(3)),
                (u(10), t("example.com")),
            ]),
        );
        let mut scratch = Scratch::new();
        let Request::ClientPin(r) = codec::decode(&msg, &mut scratch).unwrap() else {
            panic!()
        };
        assert_eq!(r.subcommand(), sub as u8);
        if let pin_uv::Request::GetTokenWithPermissions {
            key_agreement,
            permissions,
            rp_id,
            ..
        } = r
        {
            assert_eq!(key_agreement, &point);
            assert_eq!(permissions.bits(), 3);
            assert_eq!(rp_id, Some("example.com"));
        }
    }
    assert_eq!(
        error(&wire(6, m(vec![(u(2), u(7))]))),
        Status::InvalidSubcommand
    );
    for (kty, alg, curve) in [(1, -25, 1), (2, -7, 1), (2, -25, 2)] {
        let msg = wire(
            6,
            m(vec![
                (u(1), u(2)),
                (u(2), u(3)),
                (u(3), cose(kty, alg, curve, &point)),
            ]),
        );
        assert_eq!(error(&msg), Status::InvalidParameter);
    }
    let zero = [0; 65];
    let msg = wire(
        6,
        m(vec![
            (u(1), u(2)),
            (u(2), u(3)),
            (u(3), cose(2, -25, 1, &zero)),
        ]),
    );
    assert_eq!(error(&msg), Status::InvalidParameter);
}

#[test]
fn hmac_secret_uses_four_levels_and_retains_absent_protocol_for_backend_policy() {
    let point = public_key();
    let msg = assertion(vec![(
        u(4),
        m(vec![(
            t("hmac-secret"),
            m(vec![
                (u(1), cose(2, -25, 1, &point)),
                (u(2), b(&[1; 48])),
                (u(3), b(&[2; 32])),
            ]),
        )]),
    )]);
    let mut scratch = Scratch::new();
    let Request::GetAssertion(r) = codec::decode(&msg, &mut scratch).unwrap() else {
        panic!()
    };
    let h = r.hmac_secret.unwrap();
    assert_eq!(h.key_agreement, &point);
    assert_eq!(h.salt_enc, &[1; 48]);
    assert!(h.protocol.is_none());
}

#[test]
fn credential_management_preserves_exact_canonical_mac_input_including_unknown_members() {
    let subparams = encode(m(vec![
        (u(1), b(&[8; 32])),
        (u(2), descriptor()),
        (u(3), user()),
        (u(99), t("future")),
    ]));
    let mut msg = vec![10, 0xa4, 1, 7, 2];
    msg.extend(&subparams);
    msg.extend([3, 2, 4, 0x58, 32]);
    msg.extend([7; 32]);
    let mut scratch = Scratch::new();
    let Request::CredentialManagement(r) = codec::decode(&msg, &mut scratch).unwrap() else {
        panic!()
    };
    assert_eq!(
        r.subcommand,
        credential_management::Subcommand::UpdateUserInformation
    );
    assert_eq!(r.encoded_subcommand_params, Some(subparams.as_slice()));
    assert_eq!(r.rp_id_hash, Some(&[8; 32]));
    assert_eq!(r.credential.unwrap().id, &[7; 32]);
    assert_eq!(r.user.unwrap().id, &[1]);
}

#[test]
fn no_argument_commands_unknown_commands_and_structural_type_errors_are_distinct() {
    for command in [4, 7, 8, 11] {
        let mut s = Scratch::new();
        assert!(codec::decode(&[command], &mut s).is_ok());
        assert_eq!(error(&[command, 0xa0]), Status::InvalidLength);
    }
    assert_eq!(error(&[]), Status::InvalidLength);
    assert_eq!(error(&[0xff, 0xff]), Status::InvalidCommand);
    assert_eq!(error(&[1]), Status::MissingParameter);
    assert_eq!(error(&[1, 0xa0]), Status::MissingParameter);
    assert_eq!(error(&[1, 0xf6]), Status::CborUnexpectedType);
    let msg = wire(
        1,
        m(vec![
            (u(1), b(&[0; 32])),
            (u(2), m(vec![])),
            (u(3), user()),
            (u(4), params()),
        ]),
    );
    assert_eq!(error(&msg), Status::CborUnexpectedType);
    let msg = wire(1, m(vec![(u(1), b(&[0; 31]))]));
    assert_eq!(error(&msg), Status::InvalidParameter);
    assert_eq!(
        error(&assertion(vec![(u(5), m(vec![(t("up"), u(1))]))])),
        Status::CborUnexpectedType
    );
}

#[test]
fn canonical_rules_reject_duplicates_wrong_order_nonminimal_tags_indefinite_and_invalid_utf8() {
    for bytes in [
        vec![0xa2, 1, 0, 1, 1],
        vec![0xa2, 2, 0, 1, 0],
        vec![0x18, 0],
        vec![0x38, 0],
        vec![0x78, 1, b'a'],
        vec![0xbf, 0xff],
        vec![0x9f, 0xff],
        vec![0xc0, 0xa0],
        vec![0x61, 0xff],
        vec![0xf8, 24],
        vec![0xff],
        vec![0xa1, 0x80, 0],
    ] {
        assert_eq!(cbor_error(&bytes), Status::InvalidCbor, "{bytes:02x?}");
    }
    // CTAP sorts by major type BEFORE length, unlike length-first deterministic CBOR.
    assert!(cbor::decode(&[0xa2, 0x18, 24, 0, 0x20, 0]).is_ok());
    assert_eq!(
        cbor_error(&[0xa2, 0x20, 0, 0x18, 24, 0]),
        Status::InvalidCbor
    );
    // Float widths do not have to be minimized in CTAP's canonical encoding.
    assert!(cbor::decode(&[0xf9, 0, 0]).is_ok());
    assert!(cbor::decode(&[0xfa, 0, 0, 0, 0]).is_ok());
    assert_eq!(
        cbor::decode(&[0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
            .unwrap()
            .integer(),
        Err(Status::CborUnexpectedType)
    );
}

#[test]
fn depth_collection_node_and_message_limits_are_enforced_without_allocations_from_lengths() {
    assert!(cbor::decode(&[0x81, 0x81, 0x81, 0x81, 0]).is_ok());
    assert_eq!(
        cbor_error(&[0x81, 0x81, 0x81, 0x81, 0x81, 0]),
        Status::InvalidCbor
    );
    let mut too_many = vec![0x98, 33];
    too_many.extend([0; 33]);
    assert_eq!(cbor_error(&too_many), Status::RequestTooLarge);
    let nodes = encode(a((0..32)
        .map(|_| a((0..8).map(|_| u(0)).collect()))
        .collect()));
    assert_eq!(cbor_error(&nodes), Status::RequestTooLarge);
    assert_eq!(cbor_error(&vec![0; 1025]), Status::RequestTooLarge);
    for bytes in [
        vec![0x5b, 255, 255, 255, 255, 255, 255, 255, 255],
        vec![0x5a, 255, 255, 255, 255],
        vec![0x58, 32, 0],
    ] {
        assert_eq!(cbor_error(&bytes), Status::InvalidCbor);
    }
    let list = a((0..9).map(|_| descriptor()).collect());
    assert_eq!(
        error(&assertion(vec![(u(3), list)])),
        Status::RequestTooLarge
    );
    let params = a((0..17)
        .map(|_| m(vec![(t("alg"), C::I(-7)), (t("type"), t("public-key"))]))
        .collect());
    let msg = wire(
        1,
        m(vec![
            (u(1), b(&[0; 32])),
            (u(2), rp()),
            (u(3), user()),
            (u(4), params),
        ]),
    );
    assert_eq!(error(&msg), Status::RequestTooLarge);
}

#[test]
fn malformed_unknown_fields_cannot_bypass_validation_and_all_truncations_fail() {
    let mut msg = assertion(vec![(u(99), u(1))]);
    msg.pop();
    msg.extend([0xc0, 0]);
    assert_eq!(error(&msg), Status::InvalidCbor);
    let msg = make(vec![]);
    for len in 0..msg.len() {
        let mut s = Scratch::new();
        assert!(codec::decode(&msg[..len], &mut s).is_err());
    }
    let mut msg = msg;
    msg.push(0);
    assert_eq!(error(&msg), Status::InvalidCbor);
}

#[test]
fn get_info_matches_independent_golden_bytes_and_clears_every_short_output() {
    let expected = hex_literal::hex!(
        "a5 01 81 68 4649444f5f325f30 03 50 444f4f4849434b45592d444556303031
        04 a3 62 726b f4 62 7570 f4 64 706c6174 f4 05 19 0400 09 81 63 757362"
    );
    let mut output = [0xa5; 512];
    let n = ctap::info::encode(&mut output).unwrap();
    assert_eq!(&output[..n], &expected);
    let map = cbor::decode(&output[..n]).unwrap();
    assert_eq!(map.get_int(5).unwrap().unwrap().unsigned().unwrap(), 1024);
    assert!(map.get_int(6).unwrap().is_none());
    assert!(map.get_int(10).unwrap().is_none());
    let options = map.get_int(4).unwrap().unwrap();
    assert!(options.get_text("clientPin").unwrap().is_none());
    assert!(options.get_text("uv").unwrap().is_none());
    assert!(!options.get_text("up").unwrap().unwrap().boolean().unwrap());
    for capacity in 0..expected.len() {
        let mut output = vec![0xa5; capacity];
        assert_eq!(ctap::info::encode(&mut output), Err(Status::Other));
        assert!(output.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn deterministic_arbitrary_inputs_never_panic() {
    let mut state = 0x1234_5678_9abc_def0u64;
    for case in 0..10_000 {
        let len = case % 1025;
        let mut data = vec![0; len];
        for b in &mut data {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = state as u8;
        }
        if let Some(first) = data.first_mut() {
            *first = [1, 2, 4, 6, 7, 8, 10, 11][case % 8];
        }
        let mut scratch = Scratch::new();
        let _ = codec::decode(&data, &mut scratch);
    }
}
