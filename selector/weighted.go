package selector

import (
	"math/rand"
	"time"
)

type randomWeightedItem[T any] struct {
	item   T
	weight int
}

// RandomWeighted is a weighted random selector.
// Items are selected randomly with probability proportional to their weight.
type RandomWeighted[T any] struct {
	items []randomWeightedItem[T]
	sum   int
	r     *rand.Rand
}

// NewRandomWeighted creates a new RandomWeighted selector.
func NewRandomWeighted[T any]() *RandomWeighted[T] {
	return &RandomWeighted[T]{
		r: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Add adds an item with the given weight to the selector.
func (rw *RandomWeighted[T]) Add(item T, weight int) {
	rw.items = append(rw.items, randomWeightedItem[T]{item: item, weight: weight})
	rw.sum += weight
}

// Next selects an item randomly based on weights.
// Returns the zero value if no items are added.
func (rw *RandomWeighted[T]) Next() (v T) {
	if len(rw.items) == 0 {
		return
	}
	if rw.sum <= 0 {
		return
	}
	weight := rw.r.Intn(rw.sum) + 1
	for i := range rw.items {
		weight -= rw.items[i].weight
		if weight <= 0 {
			return rw.items[i].item
		}
	}

	return rw.items[len(rw.items)-1].item
}

// Reset clears all items and weights.
func (rw *RandomWeighted[T]) Reset() {
	rw.items = rw.items[:0]
	rw.sum = 0
}
