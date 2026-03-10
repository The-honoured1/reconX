package infrastructure

import (
	"fmt"
	"net"
	"reconx/models"
	"sync"
	"time"
)

// Scanner handles port scanning and infrastructure analysis.
type Scanner struct {
	Ports []int
}

// NewScanner creates a new infrastructure scanner.
func NewScanner() *Scanner {
	return &Scanner{
		Ports: []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443},
	}
}

// ScanPorts performs a TCP port scan on a host.
func (s *Scanner) ScanPorts(host *models.Host) {
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, port := range s.Ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", host.Hostname, p)
			conn, err := net.DialTimeout("tcp", address, 2*time.Second)
			if err != nil {
				return
			}
			conn.Close()

			mu.Lock()
			host.Ports = append(host.Ports, models.Port{
				Number:   p,
				Protocol: "TCP",
				State:    "OPEN",
			})
			mu.Unlock()
		}(port)
	}

	wg.Wait()
}

// MultiScan runs port scanning on multiple hosts.
func (s *Scanner) MultiScan(hosts []models.Host) {
	var wg sync.WaitGroup
	for i := range hosts {
		wg.Add(1)
		go func(h *models.Host) {
			defer wg.Done()
			s.ScanPorts(h)
		}(&hosts[i])
	}
	wg.Wait()
}
