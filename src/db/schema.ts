// The table definitions live in Rust (src-tauri/src/db.rs), which owns the
// database. This module keeps the value types the page stores.

export type Tier = 'guided' | 'standard' | 'pro';
export type AnswerValue = 'yes' | 'no' | 'partially' | 'not_applicable' | 'deferred';
