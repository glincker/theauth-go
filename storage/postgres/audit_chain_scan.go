package postgres

import (
	"encoding/json"
	"net/netip"
	"reflect"

	"github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// scanChainRow reads one chained row (column order fixed by VerifyAuditChain).
func scanChainRow(rows pgx.Rows) (audit.ChainRow, error) {
	var (
		r                             audit.ChainRow
		p                             = &r.Payload
		id, org, actorUser, actorSess pgtype.UUID
		metaNative                    []byte
		ipNative                      string
		created                       pgtype.Timestamptz
	)
	if err := rows.Scan(&id, &org, &actorUser, &actorSess, &p.Action,
		&p.TargetType, &p.TargetID, &p.Metadata, &metaNative,
		&p.IP, &ipNative, &p.UserAgent, &created,
		&r.RawSubject, &r.RawActor, &p.PolicyVersion, &r.RawApprover, &p.DelegationChain, &p.InputProvenance,
		&p.ActorUserPseudo, &p.SubjectPseudo, &p.ActorPseudo, &p.ApproverPseudo,
		&p.ActorSession, &p.ChainKey, &p.Seq, &p.Prev, &r.Hash); err != nil {
		return r, err
	}
	p.ID = pgUUIDToULID(id).String()
	p.Org = p.ChainKey
	p.CreatedAt = tsToTime(created).UnixMicro()
	if org.Valid {
		r.RawOrg = pgUUIDToULID(org).String()
	}
	if actorUser.Valid {
		r.RawActorUser = pgUUIDToULID(actorUser).String()
	}
	if actorSess.Valid {
		r.RawSession = pgUUIDToULID(actorSess).String()
	}
	if !jsonEqual(p.Metadata, metaNative) || !ipEqual(p.IP, ipNative) {
		r.ExtraBreak = "hash_mismatch"
	}
	return r, nil
}

// jsonEqual reports whether the hashed text and the jsonb column hold the same
// JSON value (jsonb reorders keys and normalises whitespace).
func jsonEqual(text string, native []byte) bool {
	var a, b any
	if json.Unmarshal([]byte(text), &a) != nil || json.Unmarshal(native, &b) != nil {
		return false
	}
	return reflect.DeepEqual(a, b)
}

// ipEqual compares the hashed text to the inet column. An address that did not
// parse at write time is stored as NULL, so an empty native value matches
// anything unparseable.
func ipEqual(text, native string) bool {
	want, err := netip.ParseAddr(text)
	if err != nil {
		return native == ""
	}
	got, err := netip.ParseAddr(native)
	return err == nil && want.Unmap() == got.Unmap()
}
