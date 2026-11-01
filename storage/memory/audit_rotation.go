package memory

import (
	"context"
	"maps"
	"slices"
	"time"

	"github.com/glincker/theauth-go/v2/internal/audit"
)

// AuditProvenanceSupported declares that AuditQuery.Provenance is served.
func (s *Store) AuditProvenanceSupported() bool { return true }

// SetAuditPseudonymRotation turns on rotating audit pseudonyms (theauth.AuditPseudonymRotator).
// Rows already in the ring keep their stable pseudonym.
func (s *Store) SetAuditPseudonymRotation(r audit.Rotation) error {
	v := s.auditState()
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.auditRotation.Set(&r)
}

// ShredAuditPseudonyms deletes the period secrets outside the retention window and returns the
// periods removed (theauth.AuditPseudonymRotator).
func (s *Store) ShredAuditPseudonyms(ctx context.Context) ([]int64, error) {
	v := s.auditState()
	v.mu.Lock()
	defer v.mu.Unlock()
	rot := v.auditRotation.Get()
	if rot == nil {
		return nil, nil
	}
	return audit.ShredStalePeriods(ctx, memPeriods{v}, audit.PeriodOf(time.Now(), rot.PeriodDays), rot.RetainPeriods)
}

// memPeriods is the period secret store over the ring state. The caller holds v.mu.
type memPeriods struct{ v *v10State }

func (m memPeriods) GetOrCreate(_ context.Context, period int64) ([]byte, error) {
	if sec, ok := m.v.auditPeriods[period]; ok {
		return sec, nil
	}
	sec, err := audit.NewPeriodSecret()
	if err != nil {
		return nil, err
	}
	if m.v.auditPeriods == nil {
		m.v.auditPeriods = map[int64][]byte{}
	}
	m.v.auditPeriods[period] = sec
	return sec, nil
}

func (m memPeriods) Periods(context.Context) ([]int64, error) {
	out := make([]int64, 0, len(m.v.auditPeriods))
	for p := range m.v.auditPeriods {
		out = append(out, p)
	}
	return out, nil
}

func (m memPeriods) Delete(_ context.Context, periods []int64) error {
	for _, p := range periods {
		delete(m.v.auditPeriods, p)
	}
	return nil
}

// cloneJSONMap deep copies a JSON shaped map (nested maps and slices), so nothing the caller keeps
// aliases a stored row. The chain rehashes the live event, so a later edit through an alias would
// read as tampering.
func cloneJSONMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneJSONValue(v)
	}
	return out
}

func cloneJSONValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return cloneJSONMap(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = cloneJSONValue(e)
		}
		return out
	case []string:
		return slices.Clone(x)
	case map[string]string:
		return maps.Clone(x)
	default:
		return v
	}
}
