package pool

import (
	"crypto/rand"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/minvws/nl-covid19-coronacheck-idemix/common"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
)

type MemoryPool struct {
	primes []big.Int // Buffer with our new primes
	size   uint64    // Maximum size of the buffer

	mu  sync.Mutex // Mutex to guard index
	idx uint64     // Current index to the next available prime

	start  uint // Minimum bit length for generating primes
	length uint // Bit length of generated primes

	lwm        uint64 // Low water mark for notifications
	hwm        uint64 // High water mark for notifications
	depleted   bool   // Depleted
	depletions uint   // Number of times the buffer has been depleted
}

func NewMemoryPool(size, lwm, hwm uint64, start, length uint, maxCores int) *MemoryPool {
	log.Printf("Starting memory pool of size %d\n", size)

	s := &MemoryPool{
		primes: make([]big.Int, size),
		size:   size,
		idx:    0,
		start:  start,
		length: length,
		lwm:    lwm,
		hwm:    hwm,
	}

	// Check how many cores we are allowed to use (-1 for all)
	cores := common.MaxCores()
	if maxCores > 0 && maxCores < cores {
		cores = maxCores
	}

	// Use all core to generate primes
	for i := 0; i < cores; i++ {
		log.Printf("Starting prime generator on core %d\n", i)
		// Separate goroutine to fill buffer. When full, it will back off for one second
		go func() {
			for {
				// Buffer is full, sleep a while before trying again
				if s.idx == s.size-1 {
					time.Sleep(1 * time.Second)
					continue
				}

				s.AddNewPrimeToBuffer()
			}
		}()
	}

	return s
}

// Fetch a new prime directly from our in-memory buffer
func (s *MemoryPool) Fetch(_, _ uint) (*big.Int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Warn if depleted
	if s.idx < s.lwm && !s.depleted {
		s.depleted = true
		s.depletions++

		log.Printf("warning: the buffer has been depleted (size: %d, depletions: %d, lwm: %d, hwm: %d)\n", s.size, s.depletions, s.lwm, s.hwm)
	}
	if s.idx == 0 {
		// @TODO: check if we need to return a failure so we can do a 429 status return?
		return gabi.RandomPrimeInRange(rand.Reader, s.start, s.length)
	}

	p := s.primes[s.idx - 1]
	s.idx--

	return &p, nil
}

func (s *MemoryPool) IsFull() bool {
	return s.idx == s.size - 1
}

func (s *MemoryPool) StatsJSON() ([]byte, error) {
	type Stats struct {
		Name       string
		Size       uint64
		Index      uint64
		Hwm        uint64
		Lwm        uint64
		Depleted   bool
		Depletions uint
		BitStart   uint
		BitLength  uint
		Primes     []big.Int
	}

	stats := Stats{
		Name:       "in-memory",
		Size:       s.size,
		Index:      s.idx,
		Hwm:        s.hwm,
		Lwm:        s.lwm,
		Depleted:   s.depleted,
		Depletions: s.depletions,

		BitStart: s.start,
		BitLength: s.length,

		Primes: s.primes[:10],
	}

	return json.Marshal(stats)
}

// AddNewPrimeToBuffer will generate a new prime and add it to the buffer if not already full
func (s *MemoryPool) AddNewPrimeToBuffer() {
	if s.idx == s.size-1 {
		return
	}

	p, err := gabi.RandomPrimeInRange(rand.Reader, s.start, s.length)
	if err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Sanity check to see if the pool is full
	if s.idx == s.size-1 {
		return
	}

	s.primes[s.idx] = *p
	s.idx++

	// Reset notification when above high water mark
	if s.idx > s.hwm {
		s.depleted = false
	}
}
