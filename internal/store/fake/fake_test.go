package fake_test

import (
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/store"
	"github.com/ObservexINC/Observex_managed/internal/store/fake"
	"github.com/ObservexINC/Observex_managed/internal/store/storetest"
)

// Every fake must pass the same contract suite as the real adapters.

func TestMetricStoreContract(t *testing.T) {
	storetest.MetricStore(t, func(*testing.T) store.MetricStore { return fake.NewMetricStore() })
}

func TestSearchStoreContract(t *testing.T) {
	storetest.SearchStore(t, func(*testing.T) store.SearchStore { return fake.NewSearchStore() })
}

func TestTraceStoreContract(t *testing.T) {
	storetest.TraceStore(t, func(*testing.T) store.TraceStore { return fake.NewTraceStore() })
}

func TestConfigStoreContract(t *testing.T) {
	storetest.ConfigStore(t, func(*testing.T) store.ConfigStore { return fake.NewConfigStore() })
}

func TestHistoryStoreContract(t *testing.T) {
	storetest.HistoryStore(t, func(*testing.T) store.HistoryStore { return fake.NewHistoryStore() })
}

func TestBaselineStoreContract(t *testing.T) {
	storetest.BaselineStore(t, func(*testing.T) store.BaselineStore { return fake.NewBaselineStore() })
}
