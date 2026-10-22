package drive

import (
	"context"
	"time"

	"s3drive/internal/store"
)

// reserveDaily atomically reserves daily upload bytes for an account so
// concurrent writes cannot all pass the same quota check. The returned release
// function must be called when the upload finishes or fails. Google currently
// caps uploads at roughly 750 GB/day per user; the exact value is configurable.
func (s *Service) reserveDaily(ctx context.Context, acct *store.Account, need int64) (func(), error) {
	noop := func() {}
	if s.DailyUploadBytes <= 0 || need <= 0 {
		return noop, nil
	}
	s.dailyMu.Lock()
	defer s.dailyMu.Unlock()
	used, err := s.Store.UploadUsageToday(ctx, acct.ID)
	if err != nil {
		return nil, err
	}
	if used+s.dailyReserved[acct.ID]+need > s.DailyUploadBytes {
		return nil, newError("SlowDown",
			"daily upload quota exceeded for this account (%s used of %s)",
			FormatBytes(used+s.dailyReserved[acct.ID]), FormatBytes(s.DailyUploadBytes))
	}
	s.dailyReserved[acct.ID] += need
	return func() {
		s.dailyMu.Lock()
		s.dailyReserved[acct.ID] -= need
		if s.dailyReserved[acct.ID] <= 0 {
			delete(s.dailyReserved, acct.ID)
		}
		s.dailyMu.Unlock()
	}, nil
}

func (s *Service) acquireUploadSlot(ctx context.Context, acct *store.Account) (func(), error) {
	if s.MaxUploadsPerAcct <= 0 {
		return func() {}, nil
	}
	s.mu.Lock()
	ch := s.uploadSlots[acct.ID]
	if ch == nil {
		ch = make(chan struct{}, s.MaxUploadsPerAcct)
		s.uploadSlots[acct.ID] = ch
	}
	s.mu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Service) addReservation(accountID string, delta int64) {
	s.mu.Lock()
	s.reserved[accountID] += delta
	if s.reserved[accountID] < 0 {
		s.reserved[accountID] = 0
	}
	s.mu.Unlock()
}

func (s *Service) reservedFor(accountID string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reserved[accountID]
}

// CheckSpool exposes the disk reserve check to the multipart staging path.
func (s *Service) CheckSpool() error { return s.checkSpoolCapacity() }

// checkSpoolCapacity refuses a write when the spool filesystem is too full.
func (s *Service) checkSpoolCapacity() error {
	if s.DiskReserveBytes <= 0 {
		return nil
	}
	free, err := availableDisk(s.SpoolDir)
	if err != nil {
		s.Log.Warn("disk free space check failed", "err", err)
		return nil
	}
	if free < s.DiskReserveBytes {
		return newError("InsufficientStorage",
			"server disk is full (only %s free, reserve is %s)", FormatBytes(free), FormatBytes(s.DiskReserveBytes))
	}
	return nil
}

// QuotaSnapshot is a small value used by the UI and diagnostics.
type QuotaSnapshot struct {
	DailyUsed  int64
	DailyLimit int64
	Reserved   int64
	At         time.Time
}

// QuotaSnapshot returns today's upload accounting for an account.
func (s *Service) QuotaSnapshot(ctx context.Context, accountID string) (QuotaSnapshot, error) {
	used, err := s.Store.UploadUsageToday(ctx, accountID)
	if err != nil {
		return QuotaSnapshot{}, err
	}
	return QuotaSnapshot{DailyUsed: used, DailyLimit: s.DailyUploadBytes, Reserved: s.reservedFor(accountID), At: time.Now()}, nil
}
