// Package array는 Package slices 에서 지원하지 않는 각종 유틸 함수들을 제공한다.
package array

import "slices"

// ContainsAll 첫 번째 인자에 두 번째 인자의 모든 요소가 포함 되어 있는지 여부를 반환한다.
func ContainsAll[S ~[]E, E comparable](s S, e []E) bool {
	for _, v := range e {
		if !slices.Contains(s, v) {
			return false
		}
	}
	return true
}

// FilterFunc 첫 번째 인자에 있는 요소들 중 함수를 이용해 ture가 반환된 요소들만 선택하여 반환한다.
func FilterFunc[S ~[]E, E comparable](s S, f func(E) bool) S {
	var res S
	for _, v := range s {
		if f(v) {
			res = append(res, v)
		}
	}
	return res
}

func Map[S ~[]E, E any, R any](s S, f func(E) R) []R {
	var res []R
	for _, v := range s {
		res = append(res, f(v))
	}
	return res
}
