package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/spf13/cobra"
	authv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	authclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func newPreflightCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "preflight",
		Short: "Check Kubernetes and node prerequisites before installation",
	}
	cmd.AddCommand(newClusterPreflightCmd(), newNodePreflightCmd())
	return cmd
}

type preflightReport struct {
	out    io.Writer
	failed bool
}

func (r *preflightReport) check(name string, err error) {
	if err != nil {
		r.failed = true
		_, _ = fmt.Fprintf(r.out, "FAIL %s: %v\n", name, err)
		return
	}
	_, _ = fmt.Fprintf(r.out, "PASS %s\n", name)
}

func (r *preflightReport) result() error {
	if r.failed {
		return errors.New("preflight found unmet or unverified requirements")
	}
	return nil
}

func newClusterPreflightCmd() *cobra.Command {
	var kubeconfig, kubeContext string
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Audit the Kubernetes API, Linux nodes, live Pods, and installer permissions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rules := clientcmd.NewDefaultClientConfigLoadingRules()
			rules.ExplicitPath = kubeconfig
			config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{
				CurrentContext: kubeContext,
			}).ClientConfig()
			if err != nil {
				return fmt.Errorf("load Kubernetes config: %w", err)
			}
			config.Timeout = 10 * time.Second
			config.QPS, config.Burst = 20, 20
			client, err := newNativeKubernetesClient(config)
			if err != nil {
				return err
			}
			auth, err := authclient.NewForConfig(config)
			if err != nil {
				return err
			}
			discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
			if err != nil {
				return err
			}
			r := preflightReport{out: cmd.OutOrStdout()}
			ctx := cmd.Context()
			resources, err := discoveryClient.ServerResourcesForGroupVersionWithContext(ctx, "admissionregistration.k8s.io/v1")
			if err == nil {
				for _, name := range []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"} {
					found := false
					for _, resource := range resources.APIResources {
						found = found || resource.Name == name
					}
					if !found {
						err = errors.Join(err, fmt.Errorf("API resource %s is missing", name))
					}
				}
			}
			r.check("ValidatingAdmissionPolicy API", err)
			r.check("IPv4 Kubernetes API Service", checkAPIService(ctx, client))
			checkClusterInventory(ctx, &r, client)
			checkInstallPermissions(ctx, &r, discoveryClient.RESTClient(), auth.SelfSubjectAccessReviews())
			return r.result()
		},
	}
	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig (default uses standard kubeconfig loading)")
	cmd.Flags().StringVar(&kubeContext, "context", "", "Kubernetes context (default uses the current context)")
	return cmd
}

func checkAPIService(ctx context.Context, client nativeCoreClient) error {
	service, err := client.CoreV1().Services("default").Get(ctx, "kubernetes", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("read Service default/kubernetes: %w", err)
	}
	if ip, err := netip.ParseAddr(service.Spec.ClusterIP); err != nil || !ip.Is4() {
		return fmt.Errorf("node bootstrap requires a primary IPv4 ClusterIP for Service default/kubernetes, found %q", service.Spec.ClusterIP)
	}
	return nil
}

func checkClusterInventory(ctx context.Context, r *preflightReport, client nativeCoreClient) {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		r.check("list Nodes", err)
	} else {
		linux := 0
		for _, node := range nodes.Items {
			if node.Labels["kubernetes.io/os"] != "linux" {
				continue
			}
			linux++
			info := node.Status.NodeInfo
			var runtimeErr error
			if info.OperatingSystem != "linux" || (info.Architecture != "amd64" && info.Architecture != "arm64") {
				runtimeErr = fmt.Errorf("unsupported OS/architecture %s/%s", info.OperatingSystem, info.Architecture)
			}
			runtimeName, version, ok := strings.Cut(info.ContainerRuntimeVersion, "://")
			if !ok || runtimeName != "containerd" || version == "" {
				runtimeErr = errors.Join(runtimeErr, fmt.Errorf("require containerd, found %q", info.ContainerRuntimeVersion))
			}
			r.check(fmt.Sprintf("node %s (%s, kernel %s)", node.Name, info.ContainerRuntimeVersion, info.KernelVersion), runtimeErr)
		}
		if linux == 0 {
			r.check("Linux nodes", errors.New("no nodes match the agent's kubernetes.io/os=linux selector"))
		}
	}

	unsafe := false
	options := metav1.ListOptions{Limit: 500}
	for {
		pods, err := client.CoreV1().Pods("").List(ctx, options)
		if err != nil {
			r.check("list Pods cluster-wide", err)
			break
		}
		for i := range pods.Items {
			if err := validatePacketSocketPod(&pods.Items[i]); err != nil {
				unsafe = true
				r.check("workload security", err)
			}
		}
		if pods.Continue == "" {
			if !unsafe {
				r.check("workload security", nil)
			}
			break
		}
		options.Continue = pods.Continue
	}
}

type installResource struct {
	group, resource, namespace, name string
}

func (resource installResource) access(verb string) authv1.ResourceAttributes {
	return authv1.ResourceAttributes{
		Verb: verb, Group: resource.group, Resource: resource.resource,
		Namespace: resource.namespace, Name: resource.name,
	}
}

// applyVerb follows client-side kubectl apply: read first, then create or patch.
func (resource installResource) applyVerb(ctx context.Context, client rest.Interface) (string, error) {
	segments := []string{"api", "v1"}
	if resource.group != "" {
		segments = []string{"apis", resource.group, "v1"}
	}
	if resource.namespace != "" {
		segments = append(segments, "namespaces", resource.namespace)
	}
	err := client.Get().AbsPath(append(segments, resource.resource, resource.name)...).Do(ctx).Error()
	switch {
	case apierrors.IsNotFound(err):
		return "create", nil
	case err != nil:
		return "", err
	default:
		return "patch", nil
	}
}

func reviewAccess(ctx context.Context, reviewer authclient.SelfSubjectAccessReviewInterface, access authv1.ResourceAttributes) error {
	review, err := reviewer.Create(ctx, &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &access},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	if review.Status.Allowed && !review.Status.Denied {
		return nil
	}
	if review.Status.EvaluationError != "" {
		return errors.New(review.Status.EvaluationError)
	}
	return errors.New("denied for the current kubeconfig identity")
}

func checkInstallPermissions(ctx context.Context, r *preflightReport, client rest.Interface, reviewer authclient.SelfSubjectAccessReviewInterface) {
	permissions := preflightReport{out: r.out}
	const rbac = "rbac.authorization.k8s.io"
	const admission = "admissionregistration.k8s.io"
	clusterRole := installResource{rbac, "clusterroles", "", "ztap-agent"}
	apiRole := installResource{rbac, "roles", "default", "ztap-bootstrap-api"}
	writeVerbs := make(map[installResource]string)
	for _, resource := range []installResource{
		{admission, "validatingadmissionpolicies", "", "ztap-packet-socket-isolation"},
		{admission, "validatingadmissionpolicybindings", "", "ztap-packet-socket-isolation"},
		{"", "namespaces", "", "ztap-system"},
		{"", "serviceaccounts", "ztap-system", "ztap-agent"},
		clusterRole,
		{rbac, "clusterrolebindings", "", "ztap-agent"},
		apiRole,
		{rbac, "rolebindings", "default", "ztap-bootstrap-api"},
		{"apps", "daemonsets", "ztap-system", "ztap-agent"},
		{"apps", "daemonsets", "ztap-system", "ztap-node-init"},
	} {
		name := resource.name
		if resource.namespace != "" {
			name = resource.namespace + "/" + name
		}
		verb, err := resource.applyVerb(ctx, client)
		if err != nil {
			permissions.check(fmt.Sprintf("installer can get %s %s", resource.resource, name), err)
			continue
		}
		writeVerbs[resource] = verb
		access := resource.access(verb)
		if verb == "create" {
			access.Name = "" // Kubernetes cannot authorize create by resource name.
		}
		if err := reviewAccess(ctx, reviewer, access); err != nil {
			permissions.check(fmt.Sprintf("installer can %s %s %s", verb, resource.resource, name), err)
		}
	}

	var agentGrants []authv1.ResourceAttributes
	for _, resource := range []installResource{
		{"", "nodes", "", ""}, {"", "namespaces", "", ""}, {"", "pods", "", ""},
		{"networking.k8s.io", "networkpolicies", "", ""},
	} {
		for _, verb := range []string{"get", "list", "watch"} {
			agentGrants = append(agentGrants, resource.access(verb))
		}
	}
	endpoints := installResource{"", "endpoints", "default", "kubernetes"}
	for _, role := range []struct {
		resource installResource
		grants   []authv1.ResourceAttributes
	}{
		{clusterRole, agentGrants},
		{apiRole, []authv1.ResourceAttributes{endpoints.access("get")}},
	} {
		var missing error
		for _, access := range role.grants {
			if err := reviewAccess(ctx, reviewer, access); err != nil {
				missing = errors.Join(missing, fmt.Errorf("%s %s: %w", access.Verb, access.Resource, err))
			}
		}
		if missing != nil {
			checks := []authv1.ResourceAttributes{role.resource.access("bind")}
			if verb := writeVerbs[role.resource]; verb != "" {
				escalate := role.resource.access("escalate")
				if verb == "create" {
					escalate.Name = ""
				}
				checks = append(checks, escalate)
			}
			for _, access := range checks {
				if err := reviewAccess(ctx, reviewer, access); err != nil {
					permissions.check(fmt.Sprintf("installer can %s %s (or already holds its grants)", access.Verb, role.resource.name), errors.Join(err, missing))
				}
			}
		}
	}
	if permissions.failed {
		r.failed = true
	} else {
		r.check("installer permissions for the shipped manifest", nil)
	}
}
