package period

import "time"

// Range 시작시간 부터 종료시간까지의 시간 범위를 나타내는 구조체
type Range struct {
	start, end time.Time
}

func (r *Range) Start() time.Time {
	return r.start
}

func (r *Range) End() time.Time {
	return r.end
}

// New 새로운 시간 범위 인스턴스를 생성한다.
//
// expires 매개변수로 지정된 유효 기간을 현재 시간에 더하여 종료 시간을 계산한다.
func New(expires time.Duration) Range {
	now := time.Now()
	return Range{
		start: now,
		end:   time.Now().Add(expires),
	}
}

// NewWithStartEnd 시작과 종료일을 받아 새로운 시간 범위 인스턴스를 생성한다.
func NewWithStartEnd(start, end time.Time) Range {
	return Range{
		start: start,
		end:   end,
	}
}

// Available 현재 시각 기준으로 시간 범위가 유효한지 검사한다.
// 종료시간이 현재 시간보다 미래인 경우 true를 반환한다.
func (r *Range) Available() bool {
	return r.end.After(time.Now())
}

// ExpiresIn 현재 시간부터 종료 시간까지 남은 시간을 초단위
func (r *Range) ExpiresIn() uint {
	if r.Available() {
		now := time.Now()
		return uint(r.end.Sub(now) / time.Second)
	}
	return 0
}

// StartedAt 시작 시간을 유닉스 타임 형태로 반환한다.
func (r *Range) StartedAt() uint {
	return uint(r.start.Unix())
}
