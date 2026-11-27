package telemetry

import (
	"strconv"
	"strings"

	"github.com/saadshabir/ZTAP/internal/flow"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

const decisionEventName = "ztap.policy.decision"

// AgentResource identifies the agent that observed the local packet decision.
type AgentResource struct {
	Version, InstanceID, NodeName, ClusterName string
}

func (a AgentResource) resource() *resourcepb.Resource {
	attributes := []*commonpb.KeyValue{
		stringAttribute("service.name", "ztap-agent"),
		stringAttribute("service.version", a.Version),
		stringAttribute("k8s.node.name", a.NodeName),
	}
	if a.InstanceID != "" {
		attributes = append(attributes, stringAttribute("service.instance.id", a.InstanceID))
	}
	if a.ClusterName != "" {
		attributes = append(attributes, stringAttribute("k8s.cluster.name", a.ClusterName))
	}
	return &resourcepb.Resource{Attributes: attributes}
}

type PodIdentity struct {
	UID, Namespace, Name string
}

func decisionRecord(event flow.FlowEvent, subject PodIdentity) *logspb.LogRecord {
	record := &logspb.LogRecord{
		EventName:      decisionEventName,
		Body:           stringValue(decisionEventName),
		SeverityNumber: logspb.SeverityNumber_SEVERITY_NUMBER_INFO,
		TimeUnixNano:   uint64(max(event.Timestamp.UnixNano(), 0)), // #nosec G115 -- value is clamped to nonnegative
		Attributes:     make([]*commonpb.KeyValue, 0, 15),
	}
	if observed := event.ObservedAt; !observed.IsZero() && observed.UnixNano() > 0 {
		record.ObservedTimeUnixNano = uint64(observed.UnixNano()) // #nosec G115 -- value is positive
	}
	record.Attributes = append(record.Attributes,
		stringAttribute("ztap.decision.action", event.Action),
		stringAttribute("ztap.decision.reason", event.Reason),
		stringAttribute("ztap.decision.direction", event.Direction),
		stringAttribute("ztap.policy.epoch", strconv.FormatUint(event.PolicyEpoch, 10)),
		stringAttribute("ztap.subject.cgroup.id", strconv.FormatUint(event.CgroupID, 10)),
		intAttribute("ztap.flow.schema.version", int64(event.SchemaVersion)),
	)
	if subject.UID == "" {
		record.Attributes = append(record.Attributes, stringAttribute("ztap.subject.identity.status", "unresolved"))
	} else {
		record.Attributes = append(record.Attributes,
			stringAttribute("ztap.subject.identity.status", "resolved"),
			stringAttribute("ztap.subject.k8s.pod.uid", subject.UID),
			stringAttribute("ztap.subject.k8s.namespace.name", subject.Namespace),
			stringAttribute("ztap.subject.k8s.pod.name", subject.Name),
		)
	}
	if event.AddressFamily == 4 || event.AddressFamily == 6 {
		if event.SourceIP != nil {
			record.Attributes = append(record.Attributes, stringAttribute("source.address", event.SourceIP.String()))
		}
		if event.DestIP != nil {
			record.Attributes = append(record.Attributes, stringAttribute("destination.address", event.DestIP.String()))
		}
	}
	switch event.Protocol {
	case "TCP", "UDP", "ICMP":
		record.Attributes = append(record.Attributes, stringAttribute("network.transport", strings.ToLower(event.Protocol)))
	}
	// Zero is also the kernel's sentinel for a port that couldn't be parsed.
	if event.SourcePort != 0 {
		record.Attributes = append(record.Attributes, intAttribute("source.port", int64(event.SourcePort)))
	}
	if event.DestPort != 0 {
		record.Attributes = append(record.Attributes, intAttribute("destination.port", int64(event.DestPort)))
	}
	return record
}

func stringValue(value string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}}
}

func stringAttribute(name, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: name, Value: stringValue(value)}
}

func intAttribute(name string, value int64) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: name, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: value}}}
}
