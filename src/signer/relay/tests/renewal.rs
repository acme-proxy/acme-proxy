use super::*;

#[test]
fn upstream_errors_map_to_the_right_signer_error() {
    let bad_csr = UpstreamError::Problem {
        status: 403,
        typ: "urn:ietf:params:acme:error:badCSR".to_string(),
        detail: String::new(),
    };
    assert!(matches!(
        upstream_to_signer_error(bad_csr),
        SignerError::BadCsr
    ));

    // Everything else is this server's problem, not the client's.
    assert!(matches!(
        upstream_to_signer_error(UpstreamError::Transport("down".into())),
        SignerError::Internal(_)
    ));
}

/// The upstream's own window must win over any local estimate, and the
/// certID it is asked about must be the one derived from the certificate.
#[tokio::test(flavor = "multi_thread")]
async fn renewal_info_uses_the_upstream_window() {
    let upstream = testsrv::start(Script {
        renewal_window: Some((
            "2026-08-01T00:00:00Z".to_string(),
            "2026-08-08T00:00:00Z".to_string(),
        )),
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let queue = test_queue(database().await);
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        database().await,
        no_notifiers(),
        crate::testutil::outbound_with(test_resolver()),
        queue.clone(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);

    let leaf = ca_signed_leaf_with_aki();
    let window = signer.renewal_info(&leaf).await.unwrap();

    let expected_start = 1785542400; // 2026-08-01T00:00:00Z
    let expected_end = 1786147200; // 2026-08-08T00:00:00Z
    assert_eq!(
        window,
        Some(RenewalWindow::new(expected_start, expected_end))
    );
    assert_eq!(upstream.ari_requests(), 1);
    assert_eq!(
        upstream.last_cert_id(),
        Some(crate::cert::ari_cert_id(&leaf).unwrap())
    );
}

/// An upstream predating RFC 9773 advertises no `renewalInfo`. That is not
/// an error — the handler simply keeps its local estimate.
#[tokio::test(flavor = "multi_thread")]
async fn no_upstream_renewal_info_means_no_opinion() {
    let upstream = testsrv::start(Script {
        no_renewal_info: true,
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let queue = test_queue(database().await);
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        database().await,
        no_notifiers(),
        crate::testutil::outbound_with(test_resolver()),
        queue.clone(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);

    assert_eq!(
        signer
            .renewal_info(&ca_signed_leaf_with_aki())
            .await
            .unwrap(),
        None
    );
    assert_eq!(upstream.ari_requests(), 0, "nothing should have been asked");
}

/// A certificate with no AKI has no certID, so there is nothing to ask
/// about. It must fall back rather than fail the client's ARI request.
#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_without_an_aki_yields_no_opinion() {
    let upstream = testsrv::start(Script::default()).await;
    let dir = TempDir::new("upstream");
    let queue = test_queue(database().await);
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        database().await,
        no_notifiers(),
        crate::testutil::outbound_with(test_resolver()),
        queue.clone(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);

    // Self-signed: no Authority Key Identifier extension.
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
    let der = params.self_signed(&key_pair).unwrap().der().to_vec();

    assert_eq!(signer.renewal_info(&der).await.unwrap(), None);
    assert_eq!(upstream.ari_requests(), 0);
}

/// A window this server cannot parse is a real protocol error, not a
/// silent fallback — otherwise a broken upstream looks healthy forever.
#[tokio::test(flavor = "multi_thread")]
async fn an_unparsable_window_is_an_error() {
    let upstream = testsrv::start(Script {
        renewal_window: Some(("not a date".to_string(), "nor this".to_string())),
        ..Script::default()
    })
    .await;
    let dir = TempDir::new("upstream");
    let queue = test_queue(database().await);
    let signer = RelaySigner::from_config(
        &config(&upstream, &dir),
        vec!["default".to_string()],
        database().await,
        no_notifiers(),
        crate::testutil::outbound_with(test_resolver()),
        queue.clone(),
    )
    .unwrap();
    let _runner = TestRunner::start(queue, &signer);

    let error = signer
        .renewal_info(&ca_signed_leaf_with_aki())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, SignerError::Internal(detail) if detail.contains("RFC3339")),
        "{error:?}"
    );
}
