package windows

import (
	"context"
	"fmt"

	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/sysnet-windows/internal/reconcile"
)

type lifecycleState uint8

const (
	lifecycleNew lifecycleState = iota
	lifecycleReady
	lifecycleApplying
	lifecycleActive
	lifecycleClosing
	lifecycleClosed
	lifecycleRecoveryRequired
)

func (s lifecycleState) String() string {
	switch s {
	case lifecycleNew:
		return "new"
	case lifecycleReady:
		return "ready"
	case lifecycleApplying:
		return "applying"
	case lifecycleActive:
		return "active"
	case lifecycleClosing:
		return "closing"
	case lifecycleClosed:
		return "closed"
	case lifecycleRecoveryRequired:
		return "recovery-required"
	default:
		return "invalid"
	}
}

func validLifecycleTransition(from, to lifecycleState) bool {
	switch from {
	case lifecycleNew:
		return to == lifecycleReady || to == lifecycleClosing
	case lifecycleReady:
		return to == lifecycleApplying || to == lifecycleClosing ||
			to == lifecycleRecoveryRequired
	case lifecycleApplying:
		return to == lifecycleReady || to == lifecycleActive ||
			to == lifecycleRecoveryRequired || to == lifecycleClosing
	case lifecycleActive:
		return to == lifecycleApplying || to == lifecycleClosing ||
			to == lifecycleRecoveryRequired
	case lifecycleRecoveryRequired:
		return to == lifecycleApplying || to == lifecycleClosing
	case lifecycleClosing:
		return to == lifecycleClosed || to == lifecycleRecoveryRequired
	case lifecycleClosed:
		return false
	default:
		return false
	}
}

func (s *System) transitionLocked(next lifecycleState) error {
	if s.state == next {
		return nil
	}
	if !validLifecycleTransition(s.state, next) {
		return fmt.Errorf("lifecycle transition %s to %s: %w", s.state, next, sysnet.ErrUnavailable)
	}
	s.state = next
	return nil
}

func (s *System) rebuildCapabilitiesLocked() {
	s.capabilities.replace(buildCapabilityReport(s.config, s.support, s.probeFacts, s.state))
}

func (s *System) beginApply() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.acceptingWorkLocked(); err != nil {
		return err
	}
	if s.worker == nil {
		s.worker = reconcile.NewWorker(context.Background(), s.journal, nil, s.handleReconcileFailure)
	}
	if err := s.transitionLocked(lifecycleApplying); err != nil {
		return err
	}
	s.rebuildCapabilitiesLocked()
	return nil
}

func (s *System) finishApply(active bool, recoveryRequired bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := lifecycleReady
	if active {
		next = lifecycleActive
	}
	if recoveryRequired || s.state == lifecycleRecoveryRequired {
		next = lifecycleRecoveryRequired
	}
	if err := s.transitionLocked(next); err != nil {
		return err
	}
	s.rebuildCapabilitiesLocked()
	return nil
}

func (s *System) acceptingWorkLocked() error {
	switch s.state {
	case lifecycleReady, lifecycleActive:
		return nil
	case lifecycleRecoveryRequired:
		return stateValidationError(sysnet.ReasonRecoveryRequired, "system recovery is required")
	case lifecycleClosing, lifecycleClosed:
		return stateValidationError(sysnet.ReasonSystemClosed, "system is closing or closed")
	case lifecycleNew, lifecycleApplying:
		return stateValidationError(sysnet.ReasonResourceBusy, "system is not ready for new work")
	default:
		return stateValidationError(sysnet.ReasonProbeFailed, "system lifecycle state is not valid")
	}
}

func stateValidationError(reason sysnet.CapabilityReason, detail string) error {
	return validationError(validationIssue(
		"System.Lifecycle",
		sysnet.CapabilityUnavailable,
		reason,
		detail,
		sysnet.ErrUnavailable,
	))
}
