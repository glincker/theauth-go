-- 0012: placeholder for the agents and agent_credentials tables (v2.0 phase 3).
--
-- Phase 1 + 2 ships only the OAuth 2.1 authorization server, DCR, and JWKS.
-- The agents identity primitives and their storage land alongside phase 3's
-- client credentials grant. We reserve migration 0012 here so the migration
-- number sequence stays predictable across the v2.0 release train; phase 3
-- replaces this file with the full agents + agent_credentials schema.

-- intentionally empty in phase 1 + 2 -- see /Users/gdsks/G-Development/GLINRV5/docs-local/2026-06-20-theauth-go-v2.0-design.md section 4.2
SELECT 1;
