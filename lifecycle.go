package windows

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
