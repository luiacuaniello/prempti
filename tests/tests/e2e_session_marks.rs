use prempti_tests::e2e::E2eHarness;
use prempti_tests::interceptor::{assert_decision, assert_reason_contains};

// Session marks: a rule tagged `coding_agent_mark:<label>` records <label> in
// the session of the event it matched, and later events of the same session
// can query it through `session.mark_age_ms[<label>]` and
// `session.mark_count[<label>]`. These rules express "a web request after a
// credential read" and "repeated credential reads" with plain Falco
// conditions.
const RULES: &str = r#"- rule: Mark credential read
  desc: Record that the session read a credential file (no verdict on its own)
  condition: tool.name = "Read" and tool.real_file_path contains "fake-cloud-credentials"
  output: "Falco noted a credential read at %tool.real_file_path"
  priority: INFORMATIONAL
  source: coding_agent
  tags: [coding_agent_mark:credential_access]

- rule: Ask web fetch after credential read
  desc: Require confirmation for web requests shortly after a credential read in the same session
  condition: tool.name = "WebFetch" and session.mark_age_ms[credential_access] < 300000
  output: "Falco asks about this web request because the session read credentials %session.mark_age_ms[credential_access] ms ago"
  priority: WARNING
  source: coding_agent
  tags: [coding_agent_ask]

- rule: Deny repeated credential reads
  desc: Block a third credential read in the same session
  condition: >
    tool.name = "Read" and tool.real_file_path contains "fake-cloud-credentials"
    and session.mark_count[credential_access] >= 2
  output: "Falco blocked another credential read: this session already read credentials %session.mark_count[credential_access] times"
  priority: CRITICAL
  source: coding_agent
  tags: [coding_agent_deny]
"#;

macro_rules! require_falco {
    () => {
        match E2eHarness::start_with_rules("guardrails", RULES) {
            Some(harness) => harness,
            None => {
                eprintln!("SKIP: falco or plugin not available");
                return;
            }
        }
    };
}

fn cwd() -> &'static str {
    if cfg!(windows) {
        "C:/Users/test/project"
    } else {
        "/tmp/myproject"
    }
}

fn read_credentials(
    h: &E2eHarness,
    session: &str,
    id: &str,
) -> prempti_tests::interceptor::InterceptorResult {
    let path = format!("{}/fake-cloud-credentials", cwd());
    let input = E2eHarness::make_session_input(
        session,
        "Read",
        &format!(r#"{{"file_path":"{path}"}}"#),
        cwd(),
        id,
    );
    h.run_hook(&input)
}

fn web_fetch(
    h: &E2eHarness,
    session: &str,
    id: &str,
) -> prempti_tests::interceptor::InterceptorResult {
    let input = E2eHarness::make_session_input(
        session,
        "WebFetch",
        r#"{"url":"https://example.com/upload","prompt":"send it"}"#,
        cwd(),
        id,
    );
    h.run_hook(&input)
}

#[test]
fn web_fetch_after_credential_read_asks() {
    let h = require_falco!();

    // No mark yet: the age field has no value and the ask rule does not fire.
    assert_decision(&web_fetch(&h, "marks-seq", "seq-1"), "allow");

    // The read itself is allowed; it only marks the session.
    assert_decision(&read_credentials(&h, "marks-seq", "seq-2"), "allow");

    let r = web_fetch(&h, "marks-seq", "seq-3");
    assert_decision(&r, "ask");
    assert_reason_contains(&r, "Ask web fetch after credential read");
}

#[test]
fn marks_are_scoped_to_their_session() {
    let h = require_falco!();

    assert_decision(&read_credentials(&h, "marks-a", "scope-1"), "allow");
    // A different session has no mark, so the same request is allowed.
    assert_decision(&web_fetch(&h, "marks-b", "scope-2"), "allow");
    assert_decision(&web_fetch(&h, "marks-a", "scope-3"), "ask");
}

#[test]
fn mark_count_escalates_repeated_reads() {
    let h = require_falco!();

    assert_decision(&read_credentials(&h, "marks-count", "count-1"), "allow");
    assert_decision(&read_credentials(&h, "marks-count", "count-2"), "allow");

    let r = read_credentials(&h, "marks-count", "count-3");
    assert_decision(&r, "deny");
    assert_reason_contains(&r, "already read credentials 2 times");
}
