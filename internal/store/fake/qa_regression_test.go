package fake_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/store"
	"github.com/ObservexINC/Observex_managed/internal/store/fake"
)

func TestQADeleteMustNotExistIsInvalidForMissingKey(t *testing.T) {
	s := fake.NewConfigStore()
	defer func() { _ = s.Close() }()
	if err := s.Delete(context.Background(), "absent", store.MustNotExist); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("Delete(absent, MustNotExist) = %v; interface contract requires ErrInvalid", err)
	}
}
