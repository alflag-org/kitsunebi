use kitsunebi_gameap_process_manager_plugin::{
    ProcessManager, ProcessManagerEvidence, parse_process_manager,
};

#[test]
fn documented_managers_are_closed_and_unknown_is_fail_closed() {
    assert_eq!(
        parse_process_manager("process_manager:\n  name: systemd\n"),
        ProcessManager::Systemd
    );
    assert_eq!(
        parse_process_manager("process_manager:\n  name: docker\n"),
        ProcessManager::Docker
    );
    assert_eq!(
        parse_process_manager("process_manager:\n  name: podman\n"),
        ProcessManager::Podman
    );
    assert_eq!(
        parse_process_manager("process_manager:\n  name: tmux\n"),
        ProcessManager::Unknown
    );
    assert_eq!(
        parse_process_manager("other: systemd\n"),
        ProcessManager::Unknown
    );
    assert_eq!(
        parse_process_manager("process_manager: podman # node default\n"),
        ProcessManager::Podman
    );
    assert_eq!(
        parse_process_manager("process_manager: {name: \"docker\"}\n"),
        ProcessManager::Docker
    );
}

#[test]
fn evidence_serializes_only_the_public_contract() {
    let evidence = ProcessManagerEvidence {
        node_id: 42,
        process_manager: ProcessManager::Unknown,
        evidence_hash: "a".repeat(64),
        version: "1".into(),
        timestamp: 1,
    };
    let value: serde_json::Value = serde_json::to_value(evidence).expect("json");
    assert_eq!(value.as_object().expect("object").len(), 5);
    assert!(!value.to_string().contains("daemon"));
    assert!(!value.to_string().contains("config"));
}
