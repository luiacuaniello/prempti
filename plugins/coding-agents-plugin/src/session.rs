use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Maximum number of sessions tracked at once. When a new session would
/// exceed it, the least recently active session is evicted.
const MAX_SESSIONS: usize = 1024;

/// Maximum number of distinct mark labels per session. Labels come from rule
/// tags, so real rulesets stay far below this; the cap only bounds memory if
/// a ruleset misbehaves. When exceeded, the least recently set label is
/// evicted.
const MAX_MARKS_PER_SESSION: usize = 64;

/// Per-session marks recorded by rules and queried by later tool calls.
///
/// A rule tagged `<mark_tag_prefix><label>` (default prefix
/// `coding_agent_mark:`) records `<label>` in the session of the event it
/// matched. Later tool calls of the same session can query it through the
/// `session.mark_age_ms[<label>]` and `session.mark_count[<label>]` fields,
/// which lets ordinary Falco rules express sequences such as "a web request
/// after a credential read" without any new rule syntax.
///
/// Marks are written by the HTTP alert receiver while Falco may still be
/// evaluating later rules of the same event, so each mark remembers the
/// correlation ID of the tool call that set it and that tool call is served
/// the state from before its own mark. A rule therefore never observes a mark
/// set by its own tool call, whatever the alert timing, and the count is the
/// number of tool calls that set the mark. State is in-memory only and is lost
/// when Falco restarts.
pub struct SessionMarks {
    sessions: Mutex<HashMap<String, Session>>,
}

struct Session {
    marks: HashMap<String, Mark>,
    last_active: Instant,
}

struct Mark {
    /// Correlation ID of the tool call that last set this mark.
    set_by: u64,
    last_set: Instant,
    count: u64,
    /// `last_set` before `set_by` marked it (`None` if `set_by` created it).
    prev_last_set: Option<Instant>,
    /// `count` before `set_by` marked it.
    prev_count: u64,
}

impl Mark {
    /// The mark as observed by the tool call `correlation_id`: tool calls
    /// other than `set_by` see the current state, `set_by` sees the state
    /// from before its own mark.
    fn observed_by(&self, correlation_id: u64) -> (Option<Instant>, u64) {
        if correlation_id == self.set_by {
            (self.prev_last_set, self.prev_count)
        } else {
            (Some(self.last_set), self.count)
        }
    }
}

impl SessionMarks {
    pub fn new() -> Self {
        SessionMarks {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Record `label` in `session_id` on behalf of the tool call
    /// `correlation_id`. A tool call counts once per label, even if several
    /// rules (or several Codex apply_patch events) mark it. Events without a
    /// session ID cannot be correlated, so empty IDs and labels are ignored.
    pub fn record(&self, session_id: &str, label: &str, correlation_id: u64) {
        self.record_at(session_id, label, correlation_id, Instant::now());
    }

    /// Time elapsed since `label` was last recorded in `session_id`, as
    /// observed by the tool call `correlation_id`, or `None` if it never was.
    pub fn age(&self, session_id: &str, label: &str, correlation_id: u64) -> Option<Duration> {
        self.age_at(session_id, label, correlation_id, Instant::now())
    }

    /// Number of tool calls that recorded `label` in `session_id`, as
    /// observed by the tool call `correlation_id` (0 if none).
    pub fn count(&self, session_id: &str, label: &str, correlation_id: u64) -> u64 {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions
            .get(session_id)
            .and_then(|session| session.marks.get(label))
            .map_or(0, |mark| mark.observed_by(correlation_id).1)
    }

    fn record_at(&self, session_id: &str, label: &str, correlation_id: u64, now: Instant) {
        if session_id.is_empty() || label.is_empty() {
            return;
        }
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if !sessions.contains_key(session_id) && sessions.len() >= MAX_SESSIONS {
            evict_oldest(&mut sessions, |session| session.last_active);
        }
        let session = sessions
            .entry(session_id.to_string())
            .or_insert_with(|| Session {
                marks: HashMap::new(),
                last_active: now,
            });
        session.last_active = now;

        if let Some(mark) = session.marks.get_mut(label) {
            if mark.set_by != correlation_id {
                mark.prev_last_set = Some(mark.last_set);
                mark.prev_count = mark.count;
                mark.set_by = correlation_id;
                mark.last_set = now;
                mark.count = mark.count.saturating_add(1);
            }
            return;
        }
        if session.marks.len() >= MAX_MARKS_PER_SESSION {
            evict_oldest(&mut session.marks, |mark| mark.last_set);
        }
        session.marks.insert(
            label.to_string(),
            Mark {
                set_by: correlation_id,
                last_set: now,
                count: 1,
                prev_last_set: None,
                prev_count: 0,
            },
        );
    }

    fn age_at(
        &self,
        session_id: &str,
        label: &str,
        correlation_id: u64,
        now: Instant,
    ) -> Option<Duration> {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let mark = sessions.get(session_id)?.marks.get(label)?;
        let (last_set, _) = mark.observed_by(correlation_id);
        Some(now.saturating_duration_since(last_set?))
    }
}

/// Remove the entry whose `stamp` is the oldest.
fn evict_oldest<V>(map: &mut HashMap<String, V>, stamp: impl Fn(&V) -> Instant) {
    let oldest = map
        .iter()
        .min_by_key(|(_, value)| stamp(value))
        .map(|(key, _)| key.clone());
    if let Some(key) = oldest {
        map.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Correlation ID of a tool call that set no mark.
    const OTHER: u64 = 999;

    #[test]
    fn unknown_session_or_label_has_no_age_and_zero_count() {
        let marks = SessionMarks::new();
        marks.record("s1", "credential_access", 1);
        assert_eq!(marks.age("s2", "credential_access", OTHER), None);
        assert_eq!(marks.age("s1", "other", OTHER), None);
        assert_eq!(marks.count("s2", "credential_access", OTHER), 0);
        assert_eq!(marks.count("s1", "other", OTHER), 0);
    }

    #[test]
    fn age_is_measured_from_the_latest_record() {
        let marks = SessionMarks::new();
        let t0 = Instant::now();
        marks.record_at("s1", "credential_access", 1, t0);
        marks.record_at("s1", "credential_access", 2, t0 + Duration::from_secs(10));
        assert_eq!(
            marks.age_at(
                "s1",
                "credential_access",
                OTHER,
                t0 + Duration::from_secs(25)
            ),
            Some(Duration::from_secs(15))
        );
    }

    #[test]
    fn count_accumulates_per_label_and_tool_call() {
        let marks = SessionMarks::new();
        marks.record("s1", "credential_access", 1);
        marks.record("s1", "credential_access", 2);
        marks.record("s1", "network_egress", 2);
        assert_eq!(marks.count("s1", "credential_access", OTHER), 2);
        assert_eq!(marks.count("s1", "network_egress", OTHER), 1);
    }

    #[test]
    fn a_tool_call_counts_once_per_label() {
        // Two rules (or two Codex apply_patch events) of one tool call.
        let marks = SessionMarks::new();
        marks.record("s1", "credential_access", 1);
        marks.record("s1", "credential_access", 1);
        assert_eq!(marks.count("s1", "credential_access", OTHER), 1);
    }

    #[test]
    fn a_tool_call_does_not_observe_its_own_mark() {
        let marks = SessionMarks::new();
        let t0 = Instant::now();
        let later = t0 + Duration::from_secs(5);

        // First mark: the setter sees no mark at all.
        marks.record_at("s1", "credential_access", 1, t0);
        assert_eq!(marks.age_at("s1", "credential_access", 1, later), None);
        assert_eq!(marks.count("s1", "credential_access", 1), 0);

        // Re-mark: the setter sees the state from before its own mark.
        marks.record_at("s1", "credential_access", 2, t0 + Duration::from_secs(3));
        assert_eq!(
            marks.age_at("s1", "credential_access", 2, later),
            Some(Duration::from_secs(5))
        );
        assert_eq!(marks.count("s1", "credential_access", 2), 1);

        // Any other tool call sees the current state.
        assert_eq!(
            marks.age_at("s1", "credential_access", OTHER, later),
            Some(Duration::from_secs(2))
        );
        assert_eq!(marks.count("s1", "credential_access", OTHER), 2);
    }

    #[test]
    fn marks_are_scoped_to_their_session() {
        let marks = SessionMarks::new();
        marks.record("s1", "credential_access", 1);
        assert!(marks.age("s1", "credential_access", OTHER).is_some());
        assert!(marks.age("s2", "credential_access", OTHER).is_none());
    }

    #[test]
    fn empty_session_or_label_is_ignored() {
        let marks = SessionMarks::new();
        marks.record("", "credential_access", 1);
        marks.record("s1", "", 1);
        assert_eq!(marks.age("", "credential_access", OTHER), None);
        assert_eq!(marks.count("s1", "", OTHER), 0);
    }

    #[test]
    fn least_recently_active_session_is_evicted_at_capacity() {
        let marks = SessionMarks::new();
        let t0 = Instant::now();
        for i in 0..MAX_SESSIONS {
            marks.record_at(
                &format!("s{i}"),
                "m",
                1,
                t0 + Duration::from_millis(i as u64),
            );
        }
        // Touch s0 so s1 becomes the least recently active session.
        marks.record_at("s0", "m", 2, t0 + Duration::from_secs(60));
        marks.record_at("new", "m", 3, t0 + Duration::from_secs(61));

        assert_eq!(marks.count("s0", "m", OTHER), 2);
        assert_eq!(marks.count("s1", "m", OTHER), 0);
        assert_eq!(marks.count("new", "m", OTHER), 1);
    }

    #[test]
    fn least_recently_set_label_is_evicted_at_capacity() {
        let marks = SessionMarks::new();
        let t0 = Instant::now();
        for i in 0..MAX_MARKS_PER_SESSION {
            marks.record_at(
                "s1",
                &format!("m{i}"),
                1,
                t0 + Duration::from_millis(i as u64),
            );
        }
        marks.record_at("s1", "overflow", 2, t0 + Duration::from_secs(60));

        assert_eq!(marks.count("s1", "m0", OTHER), 0);
        assert_eq!(marks.count("s1", "m1", OTHER), 1);
        assert_eq!(marks.count("s1", "overflow", OTHER), 1);
    }
}
