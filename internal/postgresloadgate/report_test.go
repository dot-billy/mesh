package postgresloadgate

import "testing"

func TestOperationLedgerRejectsRetryAndDuplicate(t *testing.T) {
	ledger := newOperationLedger()
	if err := ledger.add(OperationRecord{ID: "load.control.001", Attempts: 1}); err != nil {
		t.Fatal(err)
	}
	if err := ledger.add(OperationRecord{ID: "load.control.001", Attempts: 1}); err == nil {
		t.Fatal("duplicate logical operation was accepted")
	}
	if err := ledger.add(OperationRecord{ID: "load.control.002", Attempts: 2}); err == nil {
		t.Fatal("client retry was accepted")
	}
}
