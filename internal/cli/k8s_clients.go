package cli

import (
	"errors"

	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	networkingclient "k8s.io/client-go/kubernetes/typed/networking/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

// Fake clientsets satisfy the same small interface in integration tests. The
// shipped binary constructs only the two API clients it actually uses.
type nativeCoreClient interface {
	CoreV1() coreclient.CoreV1Interface
}

type nativeKubernetesClient interface {
	nativeCoreClient
	NetworkingV1() networkingclient.NetworkingV1Interface
}

type nativeClients struct {
	core       coreclient.CoreV1Interface
	networking networkingclient.NetworkingV1Interface
}

func (c *nativeClients) CoreV1() coreclient.CoreV1Interface                   { return c.core }
func (c *nativeClients) NetworkingV1() networkingclient.NetworkingV1Interface { return c.networking }

func newNativeKubernetesClient(config *rest.Config) (*nativeClients, error) {
	if config == nil {
		return nil, errors.New("kubernetes config is nil")
	}
	config = rest.CopyConfig(config)
	// Preserve the clientset's shared throttle when QPS is explicitly set.
	if config.RateLimiter == nil && config.QPS > 0 {
		if config.Burst <= 0 {
			return nil, errors.New("burst must be positive when QPS is set")
		}
		config.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(config.QPS, config.Burst)
	}
	// Keep client-go's authentication, TLS, proxy and transport handling.
	httpClient, err := rest.HTTPClientFor(config)
	if err != nil {
		return nil, err
	}
	core, err := coreclient.NewForConfigAndClient(config, httpClient)
	if err != nil {
		return nil, err
	}
	networking, err := networkingclient.NewForConfigAndClient(config, httpClient)
	if err != nil {
		return nil, err
	}
	return &nativeClients{core: core, networking: networking}, nil
}
