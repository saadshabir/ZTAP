package enforcer

import (
	"errors"
	"fmt"
	"testing"
)

func phase5MapCapacityBytes(mapType string, maxEntries, keySize, valueSize uint32, cpus int) (uint64, error) {
	if mapType == "CGroupStorage" {
		if maxEntries != 0 {
			return 0, errors.New("cgroup-storage map has bounded entries")
		}
		return 0, nil
	}
	if maxEntries == 0 {
		return 0, errors.New("bounded map has zero entries")
	}
	if mapType == "RingBuf" {
		return uint64(maxEntries), nil
	}
	switch mapType {
	case "Array", "ArrayOfMaps", "Hash", "LPMTrie", "LRUHash", "PerCPUHash", "PerCPUArray", "LRUCPUHash":
	default:
		return 0, fmt.Errorf("unknown map type %q", mapType)
	}
	if cpus <= 0 {
		return 0, fmt.Errorf("map CPU count must be positive, got %d", cpus)
	}
	if keySize == 0 || valueSize == 0 {
		return 0, errors.New("bounded map has zero key or value size")
	}
	unitBytes := uint64(keySize) + uint64(valueSize)
	capacity := uint64(maxEntries)
	switch mapType {
	case "PerCPUHash", "PerCPUArray", "LRUCPUHash", "PerCPUCGroupStorage":
		if uint64(cpus) > ^uint64(0)/capacity {
			return 0, errors.New("per-CPU entry count overflows capacity calculation")
		}
		capacity *= uint64(cpus)
	}
	if unitBytes != 0 && capacity > ^uint64(0)/unitBytes {
		return 0, errors.New("map entry size overflows capacity calculation")
	}
	return capacity * unitBytes, nil
}

func TestPhase5MapCapacityBytes(t *testing.T) {
	tests := []struct {
		name    string
		mapType string
		max     uint32
		key     uint32
		value   uint32
		cpus    int
		want    uint64
		wantErr bool
	}{
		{name: "bounded hash", mapType: "Hash", max: 2, key: 4, value: 8, cpus: 2, want: 24},
		{name: "per CPU array", mapType: "PerCPUArray", max: 2, key: 4, value: 8, cpus: 2, want: 48},
		{name: "ring buffer", mapType: "RingBuf", max: 1024, cpus: 0, want: 1024},
		{name: "unbounded cgroup storage", mapType: "CGroupStorage", key: 16, value: 8, cpus: 0, want: 0},
		{name: "invalid CPU count", mapType: "PerCPUArray", max: 1, key: 4, value: 8, cpus: 0, wantErr: true},
		{name: "byte overflow", mapType: "Hash", max: ^uint32(0), key: ^uint32(0), value: ^uint32(0), cpus: 1, wantErr: true},
		{name: "unknown map type", mapType: "Unknown", max: 1, key: 4, value: 8, cpus: 1, wantErr: true},
		{name: "bounded cgroup storage", mapType: "CGroupStorage", max: 1, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := phase5MapCapacityBytes(test.mapType, test.max, test.key, test.value, test.cpus)
			if test.wantErr {
				if err == nil {
					t.Fatalf("phase5MapCapacityBytes accepted invalid metadata, got %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("phase5MapCapacityBytes rejected valid metadata: %v", err)
			}
			if got != test.want {
				t.Fatalf("phase5MapCapacityBytes = %d, want %d", got, test.want)
			}
		})
	}
}
