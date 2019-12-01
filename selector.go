package main

import (
    "fmt"
    "time"
)

const (
	SelectAll = iota
	CountBasedSampling
	TimeBasedSampling
)

type Selector struct {
	Name                       string
	SelectionProcessName       string
	CacheName                  string
	Interval                   uint32
	Space                      uint32
	TotalPacketCount           uint64
	NextSampleStartPacketCount uint64
	NextSampleEndPacketCount   uint64
	NextSampleStartTime        time.Time
	NextSampleEndTime          time.Time
	LastPacketTime             time.Time
	cachePointer               *Cache
	Algorithm                  uint16
}

func (selector Selector) String() string {
	s := fmt.Sprintf("Name: %s, SelectorocessName: %s, Algorithm: %d, Interval: %d, Space: %d, cachePointer: %p\n", selector.Name, selector.SelectionProcessName, selector.Algorithm, selector.Interval, selector.Space, selector.cachePointer)
	return s
}

func (selector *Selector) associateCache(caches []Cache) {
	for i := 0; i < len(caches); i++ {
		if selector.CacheName == caches[i].Name {
			selector.cachePointer = &caches[i]
			break
		}
	}
}

func (s *Selector) selectPacket(packetTime time.Time) bool {
	if s.Algorithm == SelectAll {
		return true
	} else if s.Algorithm == CountBasedSampling {
		if s.TotalPacketCount == 0 {
			s.NextSampleStartPacketCount = 1
			s.NextSampleEndPacketCount = s.NextSampleStartPacketCount + uint64(s.Interval)
		}
		s.TotalPacketCount++
		if s.NextSampleStartPacketCount <= s.TotalPacketCount && s.TotalPacketCount < s.NextSampleEndPacketCount {
			return true
		} else {
			if s.NextSampleEndPacketCount <= s.TotalPacketCount {
				s.NextSampleStartPacketCount = s.NextSampleEndPacketCount + uint64(s.Space)
				s.NextSampleEndPacketCount = s.NextSampleStartPacketCount + uint64(s.Interval)
			}
			return false
		}
	} else if s.Algorithm == TimeBasedSampling {
		if s.TotalPacketCount == 0 {
			s.NextSampleStartTime = packetTime
			s.NextSampleEndTime = s.NextSampleStartTime.Add(time.Duration(s.Interval))
		}
		s.TotalPacketCount++
		s.LastPacketTime = packetTime
		if s.NextSampleStartTime.Equal(s.LastPacketTime) || (s.NextSampleStartTime.After(s.LastPacketTime) && s.NextSampleEndTime.Before(s.LastPacketTime)) {
			return true
		} else {
			if s.NextSampleEndTime.Equal(s.LastPacketTime) || s.NextSampleEndTime.After(s.LastPacketTime) {
				s.NextSampleStartTime = s.NextSampleEndTime.Add(time.Duration(s.Space))
				s.NextSampleEndTime = s.NextSampleStartTime.Add(time.Duration(s.Interval))
			}
			return false
		}
	}
	return false
}
