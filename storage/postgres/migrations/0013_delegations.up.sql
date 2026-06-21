-- 0013: placeholder for delegation grants (v2.0 phase 4).
--
-- Phase 1 + 2 ships only the OAuth 2.1 authorization server, DCR, and JWKS.
-- Delegation grants and the audit_events.actor_agent_id column land
-- alongside phase 4's RFC 8693 token exchange. We reserve migration 0013
-- here so the migration sequence stays predictable; phase 4 replaces this
-- file with the full delegation_grants schema and the audit column add.

-- intentionally empty in phase 1 + 2 -- see /Users/gdsks/G-Development/GLINRV5/docs-local/2026-06-20-theauth-go-v2.0-design.md section 4.3
SELECT 1;
