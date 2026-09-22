package enforcer

import "errors"

func sumCounterValues(values []uint64) (uint64, error) {
	var total uint64
	for _, value := range values {
		if value > ^uint64(0)-total {
			return 0, errors.New("counter sum overflows uint64")
		}
		total += value
	}
	return total, nil
}
