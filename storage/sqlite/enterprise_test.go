package sqlite_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sqlitestore "github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storagetest"
)

// TestFullContract runs the whole storagetest.Run suite, including the
// organization, SAML, SCIM and RBAC capabilities, against a temp-file WAL database.
func TestFullContract(t *testing.T) {
	t.Parallel()
	storagetest.Run(t, newStore(t))
}

func TestFullContractCustomPrefix(t *testing.T) {
	t.Parallel()
	storagetest.Run(t, newStore(t, sqlitestore.WithTablePrefix("auth_x_")))
}

func TestEnterpriseConstraints(t *testing.T) {
	t.Parallel()
	storagetest.RunEnterpriseConstraints(t, newStore(t))
}

// TestCapabilitiesNeverMissing is the negative control: every enterprise
// capability must be present and must never answer ErrStorageMissingCapability.
func TestCapabilitiesNeverMissing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t)

	var (
		_ theauth.OrganizationStorage  = s
		_ theauth.SAMLStorage          = s
		_ theauth.SCIMStorage          = s
		_ theauth.RBACStorage          = s
		_ theauth.AccountStateStorage  = s
		_ theauth.AccountDeleteStorage = s
		_ theauth.TrustedDeviceStorage = s
	)

	probes := map[string]func() error{
		"OrganizationBySlug":  func() error { _, err := s.OrganizationBySlug(ctx, "nope"); return err },
		"SAMLConnectionByID":  func() error { _, err := s.SAMLConnectionByID(ctx, newID()); return err },
		"SCIMTokenByHash":     func() error { _, err := s.SCIMTokenByHash(ctx, []byte("nope")); return err },
		"PermissionByName":    func() error { _, err := s.PermissionByName(ctx, "nope"); return err },
		"GroupByID":           func() error { _, err := s.GroupByID(ctx, newID()); return err },
		"RolesByOrganization": func() error { _, err := s.RolesByOrganization(ctx, nil); return err },
	}
	for name, probe := range probes {
		err := probe()
		if errors.Is(err, theauth.ErrStorageMissingCapability) {
			t.Fatalf("%s reported a missing capability", name)
		}
	}

	a, err := theauth.New(theauth.Config{
		Storage:       s,
		BaseURL:       "https://sp.example.test",
		Organizations: &theauth.OrganizationsConfig{},
		SCIM:          &theauth.SCIMConfig{},
		RBAC:          &theauth.RBACConfig{},
	})
	if errors.Is(err, theauth.ErrStorageMissingCapability) {
		t.Fatalf("enterprise config rejected: %v", err)
	}
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.Close()
}

func TestEnterpriseConcurrency(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newStore(t)
	const workers = 24

	run := func(fn func(i int)) {
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); fn(i) }()
		}
		wg.Wait()
	}

	t.Run("OneSlugWins", func(t *testing.T) {
		var wins, taken atomic.Int32
		run(func(i int) {
			_, err := s.InsertOrganization(ctx, theauth.Organization{ID: newID(), Name: "n", Slug: fmt.Sprintf("Race-%d", 0), CreatedAt: time.Now()})
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, theauth.ErrSlugTaken):
				taken.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		})
		if wins.Load() != 1 || taken.Load() != workers-1 {
			t.Fatalf("wins=%d taken=%d", wins.Load(), taken.Load())
		}
	})

	org, err := s.InsertOrganization(ctx, theauth.Organization{ID: newID(), Name: "o", Slug: "conc", CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("OneSCIMTokenHashWins", func(t *testing.T) {
		var wins atomic.Int32
		run(func(i int) {
			_, err := s.InsertSCIMToken(ctx, theauth.SCIMToken{ID: newID(), OrganizationID: org.ID, TokenHash: []byte("same-hash"), CreatedAt: time.Now()})
			if err == nil {
				wins.Add(1)
			}
		})
		if wins.Load() != 1 {
			t.Fatalf("token wins = %d, want 1", wins.Load())
		}
	})

	t.Run("PermissionInsertConverges", func(t *testing.T) {
		ids := make([]theauth.ULID, workers)
		run(func(i int) {
			p, err := s.InsertPermission(ctx, theauth.Permission{ID: newID(), Name: "conc:perm", CreatedAt: time.Now()})
			if err != nil {
				t.Errorf("InsertPermission: %v", err)
				return
			}
			ids[i] = p.ID
		})
		for _, id := range ids {
			if id != ids[0] {
				t.Fatalf("permission ids diverged: %v vs %v", id, ids[0])
			}
		}
	})

	t.Run("SetGroupMembersIsAtomic", func(t *testing.T) {
		g, err := s.InsertGroup(ctx, theauth.Group{ID: newID(), OrganizationID: org.ID, DisplayName: "g", CreatedAt: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		users := make([]theauth.ULID, 4)
		for i := range users {
			users[i] = mkUser(t, s, fmt.Sprintf("conc-g-%d@example.com", i)).ID
		}
		run(func(i int) {
			set := users[:2]
			if i%2 == 1 {
				set = users[2:]
			}
			if err := s.SetGroupMembers(ctx, g.ID, set); err != nil {
				t.Errorf("SetGroupMembers: %v", err)
			}
		})
		members, err := s.GroupMembers(ctx, g.ID)
		if err != nil || len(members) != 2 {
			t.Fatalf("members = %v, %v; want exactly one of the two sets", members, err)
		}
	})

	t.Run("MemberUpsertAndRoleGrant", func(t *testing.T) {
		u := mkUser(t, s, "conc-member@example.com")
		role, err := s.InsertRole(ctx, theauth.Role{ID: newID(), OrganizationID: &org.ID, Name: "r", CreatedAt: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		run(func(i int) {
			if err := s.UpsertOrganizationMember(ctx, theauth.OrganizationMember{OrganizationID: org.ID, UserID: u.ID, Role: "member", JoinedAt: time.Now()}); err != nil {
				t.Errorf("upsert member: %v", err)
			}
			if err := s.GrantUserRole(ctx, theauth.UserRole{UserID: u.ID, RoleID: role.ID, GrantedAt: time.Now()}); err != nil {
				t.Errorf("grant: %v", err)
			}
		})
		members, _ := s.OrganizationMembersByOrg(ctx, org.ID)
		if len(members) != 1 {
			t.Fatalf("members = %d, want 1", len(members))
		}
		if roles, _ := s.RolesForUser(ctx, u.ID, &org.ID); len(roles) != 1 {
			t.Fatalf("roles = %d, want 1", len(roles))
		}
	})
}

func TestSweepExpiredCoversTrustedDevicesAndLinks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openDB(t)
	if err := sqlitestore.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	s, err := sqlitestore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	u := mkUser(t, s, "sweep@example.com")
	now := time.Now()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	for i, exp := range []time.Time{past, future} {
		if _, err := db.ExecContext(ctx, `INSERT INTO theauth_trusted_devices
(id, user_id, token_hash, label, user_agent, ip, created_at, last_used_at, expires_at)
VALUES (?, ?, ?, '', '', '', ?, ?, ?)`,
			newID().String(), u.ID.String(), []byte(fmt.Sprintf("h%d", i)), now.UnixMicro(), now.UnixMicro(), exp.UnixMicro()); err != nil {
			t.Fatal(err)
		}
	}
	res, err := s.SweepExpired(ctx, now)
	if err != nil {
		t.Fatalf("SweepExpired: %v", err)
	}
	if res.TrustedDevices != 1 {
		t.Fatalf("TrustedDevices swept = %d, want 1", res.TrustedDevices)
	}
	if n := rowCount(t, db, "theauth_trusted_devices"); n != 1 {
		t.Fatalf("remaining trusted devices = %d, want 1", n)
	}
}

// TestPreOrganizationSchema pins that hosts which upgraded the library but
// have not run migrations 0013 to 0016 keep working: session reads and the
// sweep must not require the new tables.
func TestPreOrganizationSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openDB(t)
	migs, err := sqlitestore.RenderMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migs {
		if m.Version >= "0013" {
			continue
		}
		if _, err := db.ExecContext(ctx, m.SQL); err != nil {
			t.Fatalf("apply %s: %v", m.Version, err)
		}
	}
	s, err := sqlitestore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	u := mkUser(t, s, "legacy@example.com")
	sess, err := s.CreateSession(ctx, theauth.Session{ID: newID(), UserID: u.ID, TokenHash: []byte("legacy"), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.SessionByID(ctx, sess.ID)
	if err != nil || got.ActiveOrganizationID != nil {
		t.Fatalf("SessionByID = %+v, %v", got, err)
	}
	if _, err := s.ListUserSessions(ctx, u.ID); err != nil {
		t.Fatalf("ListUserSessions: %v", err)
	}
	if _, err := s.SweepExpired(ctx, time.Now()); err != nil {
		t.Fatalf("SweepExpired: %v", err)
	}
	if _, err := s.OrganizationBySlug(ctx, "x"); err == nil || errors.Is(err, theauth.ErrStorageNotFound) {
		t.Fatalf("organization lookup without migration 0013 must fail loudly, got %v", err)
	}
}
