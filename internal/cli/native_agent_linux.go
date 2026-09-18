//go:build linux

package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"

	"ztap/internal/enforcer"
	"ztap/internal/policy"
)

const (
	nativeAgentRetryInterval = time.Second
	nativeAgentRetryMax      = time.Minute
	nativeAgentCacheSyncMax  = time.Minute
	nativeAgentDebounce      = 50 * time.Millisecond
)

type nativeSnapshotTelemetry struct {
	classificationObservedAt    map[uint64]time.Time
	unresolvedRunningContainers int
	valid                       bool
}

type nativeAgentReconcileFunc func() (policy.CompileResult, int, nativeSnapshotTelemetry, error)

// runNativeKubernetesAgent owns one informer-cache snapshot and one
// instance-owned engine for the life of the process. Every event causes a
// complete candidate to be compiled before it is handed to Engine.Apply.
func runNativeKubernetesAgent(ctx context.Context, client kubernetes.Interface, options NativeAgentOptions) (returnErr error) {
	if ctx == nil {
		return errors.New("native agent context is nil")
	}
	if client == nil {
		return errors.New("native agent kubernetes client is nil")
	}
	if strings.TrimSpace(options.NodeName) == "" {
		return errors.New("native agent node name is required")
	}
	if strings.TrimSpace(options.CgroupRoot) == "" {
		options.CgroupRoot = "/sys/fs/cgroup"
	}
	if strings.TrimSpace(options.BPFFSRoot) == "" {
		options.BPFFSRoot = "/sys/fs/bpf"
	}
	if strings.TrimSpace(options.RunDir) == "" {
		options.RunDir = "/run/ztap"
	}
	unlock, err := acquireNativeAgentLock(options.RunDir)
	if err != nil {
		return err
	}
	defer func() {
		if unlockErr := unlock(); unlockErr != nil && returnErr == nil {
			returnErr = unlockErr
		}
	}()
	status, err := startNativeAgentHTTP(options.Listen)
	if err != nil {
		return err
	}
	slog.Default().Warn("native agent cannot detect every other NetworkPolicy enforcer; coexistence is unsupported", "node", options.NodeName)
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := status.close(shutdownCtx); shutdownErr != nil && returnErr == nil {
			returnErr = fmt.Errorf("close native agent status server: %w", shutdownErr)
		}
	}()

	factory := informers.NewSharedInformerFactory(client, 0)
	// Keep the cluster-wide policy, Pod, and Namespace views, but constrain the
	// Node informer to the one object this agent can reconcile. This avoids
	// retaining unrelated node state while preserving relist-driven updates.
	nodeFactory := informers.NewSharedInformerFactoryWithOptions(client, 0, informers.WithTweakListOptions(func(listOptions *metav1.ListOptions) {
		listOptions.FieldSelector = fields.OneTermEqualSelector("metadata.name", strings.TrimSpace(options.NodeName)).String()
	}))
	informerCtx, stopInformers := context.WithCancel(ctx)
	defer func() {
		// Shutdown waits for every informer goroutine. A startup error or cache
		// sync timeout does not cancel the caller's context, so stop our own
		// informer context before waiting for those goroutines to exit.
		stopInformers()
		nodeFactory.Shutdown()
		factory.Shutdown()
	}()
	policyInformer := factory.Networking().V1().NetworkPolicies()
	podInformer := factory.Core().V1().Pods()
	namespaceInformer := factory.Core().V1().Namespaces()
	nodeInformer := nodeFactory.Core().V1().Nodes()
	dirty := make(chan struct{}, 1)
	// The informer callbacks never block cache workers, even during a slow
	// apply; bursts collapse into one pending reconciliation.
	for name, informer := range map[string]cache.SharedIndexInformer{
		"network policy": policyInformer.Informer(),
		"pod":            podInformer.Informer(),
		"namespace":      namespaceInformer.Informer(),
		"node":           nodeInformer.Informer(),
	} {
		if err := replaceNativeAgentHandler(informer, dirty); err != nil {
			return fmt.Errorf("register %s dirty signal: %w", name, err)
		}
	}

	factory.Start(informerCtx.Done())
	nodeFactory.Start(informerCtx.Done())
	if err := waitForNativeAgentCacheSync(ctx, nativeAgentCacheSyncMax,
		policyInformer.Informer().HasSynced,
		podInformer.Informer().HasSynced,
		namespaceInformer.Informer().HasSynced,
		nodeInformer.Informer().HasSynced,
	); err != nil {
		if err := ctx.Err(); err != nil {
			return nil
		}
		return err
	}

	resolver := newK8sSubjectResolver(client, options.CgroupRoot).(*k8sSubjectResolver)
	var engine enforcer.Engine
	if options.DryRun {
		engine = nativeDryRunEngine{}
	} else {
		engine, err = enforcer.NewLinuxEngine(ctx, enforcer.LinuxEngineOptions{
			CgroupRoot:        options.CgroupRoot,
			BPFFSRoot:         options.BPFFSRoot,
			ResolveCgroupPath: resolver.ResolveCgroupPath,
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("create linux enforcement engine: %w", err)
		}
	}
	defer func() {
		status.markStopping()
		if closeErr := engine.Close(); closeErr != nil && returnErr == nil {
			returnErr = fmt.Errorf("close native enforcement engine: %w", closeErr)
		}
	}()
	if provider, ok := engine.(enforcer.MetricsProvider); ok {
		status.setEngineMetricsProvider(provider)
		defer status.setEngineMetricsProvider(nil)
		stopMetrics := status.startEngineMetricsPolling(ctx)
		defer stopMetrics()
	}

	reconcile := func() (policy.CompileResult, int, nativeSnapshotTelemetry, error) {
		policies, input, telemetry, err := nativePolicySnapshot(options.NodeName, policyInformer.Lister(), podInformer.Lister(), namespaceInformer.Lister(), nodeInformer.Lister(), resolver)
		if err != nil {
			return policy.CompileResult{}, 0, telemetry, err
		}
		result, err := enforcer.ReconcileNativePolicySnapshot(ctx, engine, policies, input)
		return result, len(policies), telemetry, err
	}
	return runNativeAgentReconciliation(ctx, dirty, status.errorsCh(), status, options, reconcile)
}

func waitForNativeAgentCacheSync(ctx context.Context, timeout time.Duration, synced ...cache.InformerSynced) error {
	if ctx == nil {
		return errors.New("native agent cache sync context is nil")
	}
	if timeout <= 0 {
		return errors.New("native agent cache sync timeout must be positive")
	}
	syncCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if cache.WaitForCacheSync(syncCtx.Done(), synced...) {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := syncCtx.Err(); err != nil {
		return fmt.Errorf("kubernetes informer caches failed to sync within %s: %w", timeout, err)
	}
	return errors.New("kubernetes informer caches failed to sync")
}

// runNativeAgentReconciliation owns the single-consumer event loop after the
// informer caches and engine have been initialized. Keeping this boundary
// independent from client-go makes startup, rejection recovery, retries, and
// shutdown testable without a Kubernetes API server or privileged eBPF maps.
func runNativeAgentReconciliation(ctx context.Context, dirty <-chan struct{}, statusErrors <-chan error, status *nativeAgentHTTP, options NativeAgentOptions, reconcile nativeAgentReconcileFunc) error {
	if ctx == nil {
		return errors.New("native agent reconciliation context is nil")
	}
	if dirty == nil {
		return errors.New("native agent dirty queue is nil")
	}
	if status == nil {
		return errors.New("native agent status is nil")
	}
	if reconcile == nil {
		return errors.New("native agent reconcile function is nil")
	}

	var reconcileSequence uint64
	diagnosticState := newNativeDiagnosticLogState()
	nextReconcileID := func() string {
		return fmt.Sprintf("reconcile-%d", atomic.AddUint64(&reconcileSequence, 1))
	}

	var retryTimer *time.Timer
	var retryC <-chan time.Time
	retryDelay := time.Duration(0)
	scheduleRetry := func() {
		retryDelay = nextNativeAgentRetryDelay(retryDelay)
		if retryTimer == nil {
			retryTimer = time.NewTimer(retryDelay)
			retryC = retryTimer.C
			return
		}
		if !retryTimer.Stop() {
			select {
			case <-retryTimer.C:
			default:
			}
		}
		retryTimer.Reset(retryDelay)
	}
	stopRetry := func() {
		if retryTimer != nil {
			if !retryTimer.Stop() {
				select {
				case <-retryTimer.C:
				default:
				}
			}
			retryTimer = nil
		}
		retryC = nil
		retryDelay = 0
	}
	defer stopRetry()

	reconcileOnce := func(initial bool) error {
		operationID := nextReconcileID()
		reconcileStart := time.Now()
		result, observedPolicies, telemetry, err := reconcile()
		reconcileDuration := time.Since(reconcileStart)
		if telemetry.valid {
			status.recordResolutionTelemetry(telemetry.unresolvedRunningContainers)
		}
		status.recordReconciliation(observedPolicies, result, err, reconcileDuration, options.DryRun)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if initial {
				status.markApplyFailure()
				logNativeReconcileFailure(options, operationID, observedPolicies, reconcileDuration, result, telemetry.unresolvedRunningContainers, err, true, diagnosticState)
				return fmt.Errorf("initial native policy reconciliation: %w", err)
			}
			status.markApplyFailure()
			logNativeReconcileFailure(options, operationID, observedPolicies, reconcileDuration, result, telemetry.unresolvedRunningContainers, err, false, diagnosticState)
			scheduleRetry()
			return nil
		}

		stopRetry()
		status.markApplied(result, options.DryRun)
		classification := status.recordClassification(telemetry.classificationObservedAt, result.PolicySet, time.Now(), options.DryRun)
		status.refreshEngineMetrics()
		logNativeReconcile(options, operationID, observedPolicies, reconcileDuration, result, telemetry.unresolvedRunningContainers, classification, diagnosticState)
		return nil
	}

	if err := reconcileOnce(true); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err, ok := <-statusErrors:
			if !ok {
				statusErrors = nil
				continue
			}
			return fmt.Errorf("native agent status server: %w", err)
		case <-dirty:
			if !waitNativeAgentDebounce(ctx, dirty) {
				return nil
			}
			if err := reconcileOnce(false); err != nil {
				return err
			}
		case <-retryC:
			retryTimer = nil
			retryC = nil
			if err := reconcileOnce(false); err != nil {
				return err
			}
		}
	}
}

func nextNativeAgentRetryDelay(previous time.Duration) time.Duration {
	if previous <= 0 {
		return nativeAgentRetryInterval
	}
	if previous >= nativeAgentRetryMax/2 {
		return nativeAgentRetryMax
	}
	return previous * 2
}

func waitNativeAgentDebounce(ctx context.Context, dirty <-chan struct{}) bool {
	timer := time.NewTimer(nativeAgentDebounce)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-dirty:
			// Drain events in one fixed window. Resetting the timer for every
			// event could postpone reconciliation indefinitely under churn.
		case <-timer.C:
			return true
		}
	}
}

// replaceNativeAgentHandler keeps event handlers tiny and non-blocking. The
// bounded channel is attached directly to each informer.
func replaceNativeAgentHandler(informer cache.SharedIndexInformer, dirty chan<- struct{}) error {
	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { signalNativeAgentDirty(dirty) },
		UpdateFunc: func(any, any) { signalNativeAgentDirty(dirty) },
		DeleteFunc: func(any) { signalNativeAgentDirty(dirty) },
	})
	return err
}

func signalNativeAgentDirty(dirty chan<- struct{}) {
	if dirty == nil {
		return
	}
	select {
	case dirty <- struct{}{}:
	default:
	}
}

func nativePolicySnapshot(nodeName string, policyLister networkinglisters.NetworkPolicyLister, podLister corelisters.PodLister, namespaceLister corelisters.NamespaceLister, nodeLister corelisters.NodeLister, resolver *k8sSubjectResolver) ([]policy.NativeNetworkPolicy, policy.ResolutionInput, nativeSnapshotTelemetry, error) {
	if resolver == nil {
		return nil, policy.ResolutionInput{}, nativeSnapshotTelemetry{}, errors.New("native policy snapshot resolver is required")
	}
	node, err := nodeLister.Get(nodeName)
	if err != nil {
		return nil, policy.ResolutionInput{}, nativeSnapshotTelemetry{}, fmt.Errorf("get local node %q: %w", nodeName, err)
	}
	namespaces, err := namespaceLister.List(labels.Everything())
	if err != nil {
		return nil, policy.ResolutionInput{}, nativeSnapshotTelemetry{}, fmt.Errorf("list namespaces: %w", err)
	}
	pods, err := podLister.List(labels.Everything())
	if err != nil {
		return nil, policy.ResolutionInput{}, nativeSnapshotTelemetry{}, fmt.Errorf("list pods: %w", err)
	}
	objects, err := policyLister.List(labels.Everything())
	if err != nil {
		return nil, policy.ResolutionInput{}, nativeSnapshotTelemetry{}, fmt.Errorf("list network policies: %w", err)
	}
	nativePolicies := make([]policy.NativeNetworkPolicy, 0, len(objects))
	for _, object := range objects {
		native, err := nativeNetworkPolicyFromKube(object)
		if err != nil {
			return nil, policy.ResolutionInput{}, nativeSnapshotTelemetry{}, err
		}
		nativePolicies = append(nativePolicies, native)
	}
	sort.Slice(nativePolicies, func(i, j int) bool {
		left, right := nativePolicies[i].Metadata, nativePolicies[j].Metadata
		if left.Namespace != right.Namespace {
			return left.Namespace < right.Namespace
		}
		return left.Name < right.Name
	})

	nodeCopy := *node.DeepCopy()
	namespaceCopies := make([]corev1.Namespace, 0, len(namespaces))
	for _, object := range namespaces {
		namespaceCopies = append(namespaceCopies, *object.DeepCopy())
	}
	podCopies := make([]corev1.Pod, 0, len(pods))
	for _, object := range pods {
		podCopies = append(podCopies, *object.DeepCopy())
	}
	input, err := resolver.BuildResolutionSnapshot(nodeName, &nodeCopy, namespaceCopies, podCopies)
	if err != nil {
		return nil, policy.ResolutionInput{}, nativeSnapshotTelemetry{}, fmt.Errorf("build Kubernetes resolution snapshot: %w", err)
	}
	observedAt, unresolved := resolver.classificationObservations()
	return nativePolicies, input, nativeSnapshotTelemetry{
		classificationObservedAt:    observedAt,
		unresolvedRunningContainers: unresolved,
		valid:                       true,
	}, nil
}

type nativeClassificationReport struct {
	count    int
	maxDelay time.Duration
}

type nativeDiagnosticIdentity struct {
	Document   int
	Namespace  string
	Name       string
	Generation int64
	// Field and Message are only part of the identity for offline or synthetic
	// diagnostics that have no Kubernetes generation. Live resources are
	// deduplicated strictly by resource identity and generation.
	Field   string
	Message string
}

type nativeDiagnosticLogState struct {
	seen map[nativeDiagnosticIdentity]struct{}
}

func newNativeDiagnosticLogState() *nativeDiagnosticLogState {
	return &nativeDiagnosticLogState{seen: make(map[nativeDiagnosticIdentity]struct{})}
}

// logNew emits each rejected-policy diagnostic once while its resource
// generation remains present in the current snapshot. A retry with the same
// generation is therefore quiet, while a corrected or recreated resource can
// produce a fresh diagnostic. Failed snapshots retain the previous set until
// a successful snapshot proves which resources are still present.
func (s *nativeDiagnosticLogState) logNew(options NativeAgentOptions, operationID string, rejected []policy.RejectedPolicy, prune bool) {
	if s == nil {
		return
	}
	current := make(map[nativeDiagnosticIdentity]struct{}, len(rejected))
	for _, diagnostic := range rejected {
		key := nativeDiagnosticIdentity{
			Document:   diagnostic.Document,
			Namespace:  diagnostic.Namespace,
			Name:       diagnostic.Name,
			Generation: diagnostic.Generation,
		}
		if diagnostic.Generation <= 0 {
			key.Field = diagnostic.Field
			key.Message = diagnostic.Message
		}
		current[key] = struct{}{}
		if _, exists := s.seen[key]; exists {
			continue
		}
		slog.Default().Warn("native policy rejected",
			"operation_id", operationID,
			"node", options.NodeName,
			"document", diagnostic.Document,
			"namespace", diagnostic.Namespace,
			"name", diagnostic.Name,
			"generation", diagnostic.Generation,
			"field", diagnostic.Field,
			"message", diagnostic.Message,
		)
	}
	if prune {
		s.seen = current
	} else {
		if s.seen == nil {
			s.seen = make(map[nativeDiagnosticIdentity]struct{}, len(current))
		}
		for key := range current {
			s.seen[key] = struct{}{}
		}
	}
}

func logNativeReconcile(options NativeAgentOptions, operationID string, observed int, duration time.Duration, result policy.CompileResult, unresolved int, classification nativeClassificationReport, diagnosticState ...*nativeDiagnosticLogState) {
	if len(diagnosticState) > 0 && diagnosticState[0] != nil {
		diagnosticState[0].logNew(options, operationID, result.Rejected, true)
	}
	accepted := observed - len(result.Rejected)
	if accepted < 0 {
		accepted = 0
	}
	quarantined := 0
	for _, subject := range result.PolicySet.Subjects {
		if subject.Quarantined != 0 {
			quarantined++
		}
	}
	attrs := []any{
		"operation_id", operationID,
		"node", options.NodeName,
		"observed_policies", observed,
		"accepted_policies", accepted,
		"rejected_policies", len(result.Rejected),
		"subjects", len(result.PolicySet.Subjects),
		"quarantined_cgroups", quarantined,
		"rules", len(result.PolicySet.Rules),
		"duration_seconds", duration.Seconds(),
		"dry_run", options.DryRun,
		"new_classifications", classification.count,
		"max_classification_delay_seconds", classification.maxDelay.Seconds(),
		"unresolved_running_containers", unresolved,
	}
	if len(result.Rejected) == 0 {
		slog.Default().Info("native policy snapshot applied", attrs...)
		return
	}
	slog.Default().Warn("native policy snapshot applied with quarantined policies", attrs...)
}

func logNativeReconcileFailure(options NativeAgentOptions, operationID string, observed int, duration time.Duration, result policy.CompileResult, unresolved int, err error, initial bool, diagnosticState ...*nativeDiagnosticLogState) {
	if len(diagnosticState) > 0 && diagnosticState[0] != nil {
		diagnosticState[0].logNew(options, operationID, result.Rejected, false)
	}
	message := "native policy reconciliation failed; retaining the last applied candidate"
	if initial {
		message = "initial native policy reconciliation failed"
	}
	accepted := observed - len(result.Rejected)
	if accepted < 0 {
		accepted = 0
	}
	quarantined := 0
	for _, subject := range result.PolicySet.Subjects {
		if subject.Quarantined != 0 {
			quarantined++
		}
	}
	slog.Default().Warn(message,
		"operation_id", operationID,
		"node", options.NodeName,
		"observed_policies", observed,
		"accepted_policies", accepted,
		"rejected_policies", len(result.Rejected),
		"subjects", len(result.PolicySet.Subjects),
		"quarantined_cgroups", quarantined,
		"rules", len(result.PolicySet.Rules),
		"duration_seconds", duration.Seconds(),
		"dry_run", options.DryRun,
		"unresolved_running_containers", unresolved,
		"error", err,
	)
}

type nativeDryRunEngine struct{}

func (nativeDryRunEngine) Apply(ctx context.Context, _ policy.PolicySet) error {
	if ctx == nil {
		return errors.New("dry-run engine context is nil")
	}
	return ctx.Err()
}

func (nativeDryRunEngine) Close() error { return nil }

func acquireNativeAgentLock(runDir string) (func() error, error) {
	runDir = strings.TrimSpace(runDir)
	if runDir == "" {
		runDir = "/run/ztap"
	}
	if err := os.MkdirAll(runDir, 0o750); err != nil {
		return nil, fmt.Errorf("create agent run directory %q: %w", runDir, err)
	}
	lockPath := filepath.Join(runDir, "agent.lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open agent lock %q: %w", lockPath, err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("another ZTAP agent already holds %s", lockPath)
		}
		return nil, fmt.Errorf("lock agent run %q: %w", lockPath, err)
	}
	var once sync.Once
	var unlockErr error
	return func() error {
		once.Do(func() {
			unlockErr = errors.Join(
				unix.Flock(int(file.Fd()), unix.LOCK_UN),
				file.Close(),
			)
		})
		return unlockErr
	}, nil
}

func nativeNetworkPolicyFromKube(object *networkingv1.NetworkPolicy) (policy.NativeNetworkPolicy, error) {
	if object == nil {
		return policy.NativeNetworkPolicy{}, errors.New("network policy informer returned a nil object")
	}
	metadata := &policy.NativeObjectMeta{
		Name:        object.Name,
		Namespace:   object.Namespace,
		Generation:  object.Generation,
		Labels:      copyStringMap(object.Labels),
		Annotations: copyStringMap(object.Annotations),
	}
	spec := &policy.NativeNetworkPolicySpec{
		PodSelector: nativeLabelSelector(object.Spec.PodSelector),
		Ingress:     make([]policy.NativeIngressRule, 0, len(object.Spec.Ingress)),
		Egress:      make([]policy.NativeEgressRule, 0, len(object.Spec.Egress)),
	}
	if object.Spec.PolicyTypes != nil {
		types := make([]string, 0, len(object.Spec.PolicyTypes))
		for _, policyType := range object.Spec.PolicyTypes {
			types = append(types, string(policyType))
		}
		spec.PolicyTypes = &types
	}
	for _, ingress := range object.Spec.Ingress {
		rule := policy.NativeIngressRule{From: make([]policy.NativePeer, 0, len(ingress.From)), Ports: nativePorts(ingress.Ports)}
		for _, peer := range ingress.From {
			rule.From = append(rule.From, nativePeer(peer))
		}
		spec.Ingress = append(spec.Ingress, rule)
	}
	for _, egress := range object.Spec.Egress {
		rule := policy.NativeEgressRule{To: make([]policy.NativePeer, 0, len(egress.To)), Ports: nativePorts(egress.Ports)}
		for _, peer := range egress.To {
			rule.To = append(rule.To, nativePeer(peer))
		}
		spec.Egress = append(spec.Egress, rule)
	}
	return policy.NativeNetworkPolicy{
		APIVersion:     policy.NativeNetworkPolicyAPIVersion,
		Kind:           policy.NativeNetworkPolicyKind,
		Metadata:       metadata,
		Spec:           spec,
		SourceDocument: 1,
	}, nil
}

func nativeLabelSelector(selector metav1.LabelSelector) *policy.NativeLabelSelector {
	result := &policy.NativeLabelSelector{MatchLabels: copyStringMap(selector.MatchLabels), MatchExpressions: make([]policy.NativeLabelSelectorRequirement, 0, len(selector.MatchExpressions))}
	for _, expression := range selector.MatchExpressions {
		result.MatchExpressions = append(result.MatchExpressions, policy.NativeLabelSelectorRequirement{
			Key:      expression.Key,
			Operator: string(expression.Operator),
			Values:   append([]string(nil), expression.Values...),
		})
	}
	return result
}

func nativePeer(peer networkingv1.NetworkPolicyPeer) policy.NativePeer {
	result := policy.NativePeer{}
	if peer.PodSelector != nil {
		result.PodSelector = nativeLabelSelector(*peer.PodSelector)
	}
	if peer.NamespaceSelector != nil {
		result.NamespaceSelector = nativeLabelSelector(*peer.NamespaceSelector)
	}
	if peer.IPBlock != nil {
		result.IPBlock = &policy.NativeIPBlock{CIDR: peer.IPBlock.CIDR, Except: append([]string(nil), peer.IPBlock.Except...)}
	}
	return result
}

func nativePorts(ports []networkingv1.NetworkPolicyPort) []policy.NativePort {
	result := make([]policy.NativePort, 0, len(ports))
	for _, port := range ports {
		protocol := string(corev1.ProtocolTCP)
		if port.Protocol != nil && strings.TrimSpace(string(*port.Protocol)) != "" {
			protocol = string(*port.Protocol)
		}
		native := policy.NativePort{Protocol: protocol}
		if port.Port != nil {
			switch port.Port.Type {
			case intstr.Int:
				native.Port = int(port.Port.IntVal)
			case intstr.String:
				native.PortName = port.Port.StrVal
			}
		}
		native.HasEndPort = port.EndPort != nil
		result = append(result, native)
	}
	return result
}
