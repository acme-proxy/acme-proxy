use std::sync::Arc;

use acme_proxy::audit::ClientContext;
use acme_proxy::cli::Palette;
use acme_proxy::cli::account::{AccountCommand, run_account_command};
use acme_proxy::cli::eab::{EabCommand, run_eab_command};
use acme_proxy::cli::nonce::{NonceCommand, run_nonce_command};
use acme_proxy::cli::order::{OrderCommand, run_order_command};
use acme_proxy::cli::window::DEFAULT_LIMIT;
use acme_proxy::config::Config;
use acme_proxy::sqlite::account::Account;
use acme_proxy::sqlite::db::Database;
use acme_proxy::sqlite::order::{Identifier, Order};

#[tokio::test]
async fn account_cli_list_and_show() {
    let db = Arc::new(Database::connect_in_memory().await.unwrap());
    let config = Config::default();
    let (account, _) = Account::find_or_create(
        "default",
        &[1, 2, 3],
        vec!["mailto:admin@example.com".to_string()],
        &ClientContext::default(),
        &db,
    )
    .await
    .unwrap();

    let mut reader: &[u8] = &[];
    run_account_command(
        AccountCommand::List {
            profile: None,
            limit: DEFAULT_LIMIT,
            offset: 0,
            json: false,
        },
        false,
        Palette::plain(),
        &mut reader,
        &config,
        db.clone(),
    )
    .await
    .unwrap();
    run_account_command(
        AccountCommand::List {
            profile: None,
            limit: DEFAULT_LIMIT,
            offset: 0,
            json: true,
        },
        false,
        Palette::plain(),
        &mut reader,
        &config,
        db.clone(),
    )
    .await
    .unwrap();
    run_account_command(
        AccountCommand::Show {
            id: account.id.to_string(),
            json: false,
        },
        false,
        Palette::plain(),
        &mut reader,
        &config,
        db.clone(),
    )
    .await
    .unwrap();
    run_account_command(
        AccountCommand::Show {
            id: account.id.to_string(),
            json: true,
        },
        false,
        Palette::plain(),
        &mut reader,
        &config,
        db.clone(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn account_cli_update_deactivate_delete() {
    let db = Arc::new(Database::connect_in_memory().await.unwrap());
    let config = Config::default();
    let (account, _) = Account::find_or_create(
        "default",
        &[1, 2, 3],
        vec![],
        &ClientContext::default(),
        &db,
    )
    .await
    .unwrap();

    let mut reader: &[u8] = &[];
    run_account_command(
        AccountCommand::UpdateContact {
            id: account.id.to_string(),
            contact: vec!["mailto:updated@example.com".to_string()],
        },
        false,
        Palette::plain(),
        &mut reader,
        &config,
        db.clone(),
    )
    .await
    .unwrap();

    run_account_command(
        AccountCommand::Deactivate {
            id: account.id.to_string(),
        },
        false,
        Palette::plain(),
        &mut reader,
        &config,
        db.clone(),
    )
    .await
    .unwrap();

    let mut reader = b"no\n".as_slice();
    run_account_command(
        AccountCommand::Delete {
            id: account.id.to_string(),
        },
        false,
        Palette::plain(),
        &mut reader,
        &config,
        db.clone(),
    )
    .await
    .unwrap();

    let mut reader: &[u8] = &[];
    run_account_command(
        AccountCommand::Delete {
            id: account.id.to_string(),
        },
        true,
        Palette::plain(),
        &mut reader,
        &config,
        db.clone(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn order_cli_list_show_delete() {
    let db = Arc::new(Database::connect_in_memory().await.unwrap());
    let config = Config::default();
    let (account, _) = Account::find_or_create(
        "default",
        &[1, 2, 3],
        vec![],
        &ClientContext::default(),
        &db,
    )
    .await
    .unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let order = Order::create(
        "default",
        account.id,
        vec![Identifier::dns("example.com")],
        now + 3600,
        None,
        None,
        &db,
    )
    .await
    .unwrap();

    let mut reader: &[u8] = &[];
    run_order_command(
        OrderCommand::List {
            profile: None,
            account_id: Some(account.id.to_string()),
            status: Some("pending".to_string()),
            expiring_in: None,
            hide_superseded: false,
            limit: DEFAULT_LIMIT,
            offset: 0,
            json: false,
        },
        false,
        Palette::plain(),
        &mut reader,
        &config,
        db.clone(),
    )
    .await
    .unwrap();

    run_order_command(
        OrderCommand::List {
            profile: None,
            account_id: None,
            status: None,
            expiring_in: None,
            hide_superseded: false,
            limit: DEFAULT_LIMIT,
            offset: 0,
            json: true,
        },
        false,
        Palette::plain(),
        &mut reader,
        &config,
        db.clone(),
    )
    .await
    .unwrap();

    run_order_command(
        OrderCommand::Show {
            id: order.id.to_string(),
            json: false,
        },
        false,
        Palette::plain(),
        &mut reader,
        &config,
        db.clone(),
    )
    .await
    .unwrap();

    run_order_command(
        OrderCommand::Show {
            id: order.id.to_string(),
            json: true,
        },
        false,
        Palette::plain(),
        &mut reader,
        &config,
        db.clone(),
    )
    .await
    .unwrap();

    let mut reader = b"no\n".as_slice();
    run_order_command(
        OrderCommand::Delete {
            id: order.id.to_string(),
        },
        false,
        Palette::plain(),
        &mut reader,
        &config,
        db.clone(),
    )
    .await
    .unwrap();

    let mut reader: &[u8] = &[];
    run_order_command(
        OrderCommand::Delete {
            id: order.id.to_string(),
        },
        true,
        Palette::plain(),
        &mut reader,
        &config,
        db.clone(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn nonce_cli_cleanup() {
    let db = Arc::new(Database::connect_in_memory().await.unwrap());
    let config = Config::default();

    let mut reader = b"no\n".as_slice();
    run_nonce_command(
        NonceCommand::Cleanup {
            ttl_seconds: Some(60),
        },
        false,
        &mut reader,
        &config,
        db.clone(),
    )
    .await
    .unwrap();

    let mut reader: &[u8] = &[];
    run_nonce_command(
        NonceCommand::Cleanup { ttl_seconds: None },
        true,
        &mut reader,
        &config,
        db.clone(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn eab_cli_create_list_show_revoke() {
    let db = Arc::new(Database::connect_in_memory().await.unwrap());

    run_eab_command(
        EabCommand::Create {
            profile: None,
            label: Some("test-label".to_string()),
            json: false,
        },
        Palette::plain(),
        db.clone(),
    )
    .await
    .unwrap();

    run_eab_command(
        EabCommand::Create {
            profile: None,
            label: None,
            json: true,
        },
        Palette::plain(),
        db.clone(),
    )
    .await
    .unwrap();

    run_eab_command(
        EabCommand::List { json: false },
        Palette::plain(),
        db.clone(),
    )
    .await
    .unwrap();
    run_eab_command(
        EabCommand::List { json: true },
        Palette::plain(),
        db.clone(),
    )
    .await
    .unwrap();

    let keys = acme_proxy::sqlite::eab::Eab::list_all(&db).await.unwrap();
    let kid = keys[0].kid;

    run_eab_command(
        EabCommand::Show {
            kid: kid.to_string(),
            json: false,
        },
        Palette::plain(),
        db.clone(),
    )
    .await
    .unwrap();

    run_eab_command(
        EabCommand::Show {
            kid: kid.to_string(),
            json: true,
        },
        Palette::plain(),
        db.clone(),
    )
    .await
    .unwrap();

    run_eab_command(
        EabCommand::Revoke {
            kid: kid.to_string(),
        },
        Palette::plain(),
        db.clone(),
    )
    .await
    .unwrap();
}

/// `order list --expiring-in <days>`, both output branches, over a listing
/// where one row has a successor and one does not.
///
/// The annotation itself is tested in `src/admin/ops.rs` over really-signed
/// rows; what this pins is that the CLI arm reaches it, that `--json` and the
/// human rendering are both driven, and that `--hide-superseded` narrows the
/// answer rather than erroring.
#[tokio::test]
async fn order_cli_lists_what_is_expiring() {
    const DAY: i64 = 24 * 60 * 60;

    let db = Arc::new(Database::connect_in_memory().await.unwrap());
    let config = Config::default();
    let (account, _) = Account::find_or_create(
        "default",
        &[9, 9, 9],
        vec![],
        &ClientContext::default(),
        &db,
    )
    .await
    .unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    for (name, days) in [
        ("soon.example.com", 3),
        ("mid.example.com", 20),
        // Renews the first: one row carries the annotation, one does not.
        ("soon.example.com", 300),
    ] {
        let mut order = Order::create(
            "default",
            account.id,
            vec![Identifier::dns(name)],
            now + 3600,
            None,
            None,
            &db,
        )
        .await
        .unwrap();
        order
            .finalize(
                "-----BEGIN CERTIFICATE-----\nplaceholder\n".to_string(),
                format!("serial-{}", &order.id.to_string()[..8]),
                vec![1],
                Some(now + days * DAY),
                &db,
            )
            .await
            .unwrap();
    }

    let mut reader: &[u8] = &[];
    for (hide_superseded, json) in [(false, false), (false, true), (true, false), (true, true)] {
        run_order_command(
            OrderCommand::List {
                profile: None,
                account_id: None,
                status: None,
                expiring_in: Some(30),
                hide_superseded,
                limit: DEFAULT_LIMIT,
                offset: 0,
                json,
            },
            false,
            Palette::plain(),
            &mut reader,
            &config,
            db.clone(),
        )
        .await
        .unwrap();
    }

    // The window is a filter, and an empty one is not an error.
    run_order_command(
        OrderCommand::List {
            profile: Some("default".to_string()),
            account_id: None,
            status: None,
            expiring_in: Some(1),
            hide_superseded: false,
            limit: DEFAULT_LIMIT,
            offset: 0,
            json: true,
        },
        false,
        Palette::plain(),
        &mut reader,
        &config,
        db,
    )
    .await
    .unwrap();
}
