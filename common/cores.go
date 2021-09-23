package common

import "runtime"

// MaxCores returns the number of cores in the current system
func MaxCores() int {
	maxProcs := runtime.GOMAXPROCS(0)
	numCPU := runtime.NumCPU()

	if maxProcs < numCPU {
		return maxProcs
	}

	return numCPU
}
