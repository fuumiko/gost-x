package selector

import (
	"math/rand"
	"time"
)

type randomWeightedItem[T any] struct {
	item   T
	weight int
}

type RandomWeighted[T any] struct {
	items []randomWeightedItem[T]
	sum   int
	r     *rand.Rand
}

func NewRandomWeighted[T any]() *RandomWeighted[T] {
	return &RandomWeighted[T]{
		r: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (rw *RandomWeighted[T]) Add(item T, weight int) {
	rw.items = append(rw.items, randomWeightedItem[T]{item: item, weight: weight})
	rw.sum += weight
}

func (rw *RandomWeighted[T]) Next() (v T) {
	if len(rw.items) == 0 {
		return
	}
	if rw.sum <= 0 {
		return rw.items[0].item
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

func (rw *RandomWeighted[T]) Reset() {
	rw.items = rw.items[:0]
	rw.sum = 0
}
