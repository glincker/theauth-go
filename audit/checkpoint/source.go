package checkpoint

import (
	"context"
	"fmt"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// EventQuerier is implemented by audit stores (sqlite, postgres, mysql, memory).
type EventQuerier interface {
	QueryAuditEvents(ctx context.Context, q models.AuditQuery) (events []models.AuditEvent, nextCursor string, err error)
}

// EventSource reads every chained audit event from a store as rows of hash version
// GoChainHashVersion. Unchained events are skipped.
type EventSource struct {
	Store EventQuerier
	// PageSize is the query page size. Zero means 500.
	PageSize int
}

// Rows implements Source.
func (s EventSource) Rows(ctx context.Context) ([]Row, error) {
	size := s.PageSize
	if size <= 0 {
		size = 500
	}
	var rows []Row
	after := ""
	for {
		events, next, err := s.Store.QueryAuditEvents(ctx, models.AuditQuery{Limit: size, After: after})
		if err != nil {
			return nil, err
		}
		for _, e := range events {
			if e.Hash == "" {
				continue
			}
			rows = append(rows, RowFromEvent(e))
		}
		if next == "" || next == after || len(events) == 0 {
			return rows, nil
		}
		after = next
		if len(rows) > 1<<31 {
			return nil, fmt.Errorf("checkpoint: too many rows")
		}
	}
}

// RowFromEvent converts a chained audit event into a log row.
func RowFromEvent(e models.AuditEvent) Row {
	org := any(nil)
	if e.OrganizationID != nil {
		org = e.OrganizationID.String()
	}
	var metadata, provenance, chain any
	if e.Metadata != nil {
		metadata = e.Metadata
	} else {
		metadata = map[string]any{}
	}
	if e.InputProvenance != nil {
		provenance = e.InputProvenance
	} else {
		provenance = map[string]any{}
	}
	list := make([]any, len(e.DelegationChain))
	for i, d := range e.DelegationChain {
		list[i] = d
	}
	chain = list
	created := e.CreatedAt.UTC()
	return Row{
		ID: e.ID.String(), Hash: e.Hash, HashVersion: GoChainHashVersion, TimestampMs: created.UnixMilli(),
		Fields: map[string]any{
			"id": e.ID.String(), "organizationId": org, "action": e.Action, "targetType": e.TargetType,
			"targetId": e.TargetID, "metadata": metadata, "ip": e.IP, "userAgent": e.UserAgent,
			"createdAtMicro": created.UnixMicro(), "policyVersion": e.PolicyVersion,
			"delegationChain": chain, "inputProvenance": provenance,
			"chainSeq": e.ChainSeq, "prevHash": e.PrevHash,
		},
	}
}

// StaticSource serves a fixed list of rows.
type StaticSource []Row

// Rows implements Source.
func (s StaticSource) Rows(context.Context) ([]Row, error) { return append([]Row(nil), s...), nil }
