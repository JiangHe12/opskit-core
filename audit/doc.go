// Package audit provides tamper-evident audit persistence, compatible logical
// queries, authenticated verification, and checkpoint-aware rotation pruning.
// New records use a fixed v2 envelope; legacy plaintext and base64-age rows
// remain readable before v2 history. Destructive authorization remains the
// responsibility of the consumer before it confirms a prune operation.
package audit
