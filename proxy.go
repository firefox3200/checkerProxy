package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/proxy"
)

const (
	// ProxyTypeRoundRobin is a type of proxy manager that gives proxies in a round-robin fashion.
	ProxyTypeRoundRobin = "round-robin"
	// ProxyTypeRandom is a type of proxy manager that gives proxies in a random fashion.
	ProxyTypeRandom = "random"
)

type Manager interface {
	GetProxy() (ProxySOCKS5, error)
	AddProxy(*ProxySOCKS5)
	RemoveProxy(*ProxySOCKS5)
}

type ProxyManager struct {
	Proxies         []ProxySOCKS5
	TypeGivingProxy string
}

func NewProxyManager(proxies []ProxySOCKS5, typeGivingProxy string) *ProxyManager {
	os.Mkdir("fingerprints", 0755)
	return &ProxyManager{
		Proxies:         proxies,
		TypeGivingProxy: typeGivingProxy,
	}
}

type ProxySOCKS5 struct {
	Host     string
	User     string
	Password string
}

func parseProxySOCKS5(proxyURL string) (*ProxySOCKS5, error) {
	parts := strings.Split(proxyURL, "@")
	if len(parts) == 2 {
		userPass := strings.Split(parts[0], ":")
		if len(userPass) != 2 {
			return nil, fmt.Errorf("invalid proxy URL: %s", proxyURL)
		}
		return &ProxySOCKS5{
			Host:     parts[1],
			User:     userPass[0],
			Password: userPass[1],
		}, nil
	} else if len(parts) == 1 {
		return &ProxySOCKS5{
			Host: parts[0],
		}, nil
	} else {
		return nil, fmt.Errorf("invalid proxy URL: %s", proxyURL)
	}
}

func (p *ProxySOCKS5) String() string {
	if p.User != "" {
		return fmt.Sprintf("%s:%s@%s", p.User, p.Password, p.Host)
	}
	return p.Host
}

func checkProxy(p *ProxySOCKS5) (proxy.Dialer, error) {
	if p.String() != "" {
		auth := proxy.Auth{}
		if p.User != "" {
			auth.User = p.User
			auth.Password = p.Password
		}
		proxyDialer, err := proxy.SOCKS5("tcp", p.Host, &auth, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("[%s] failed to create proxy dialer: %v", p.String(), err)
		}
		return proxyDialer, nil
	}
	return proxy.Direct, nil
}

func checkHttpProxy(p string) bool {
	data := strings.Split(p, "@")
	creds := strings.Split(data[0], ":")
	cl := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{
				Scheme: "http",
				Host:   data[1],
				User:   url.UserPassword(creds[0], creds[1]),
			}),
		},
	}
	resp, err := cl.Get("http://fingerprints.bablosoft.com/prepare?version=5&tags=Microsoft%20Windows%2CChrome&returnpc=true")
	if err != nil {
		log.Println(err)
		return false
	}
	cryptoRand, _ := rand.Int(rand.Reader, big.NewInt(10000000))
	f, err := os.OpenFile("fingerprints/"+"fingerprint_"+cryptoRand.String()+".txt", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()
	fingerprint, _ := io.ReadAll(resp.Body)
	f.WriteString(string(fingerprint))
	defer resp.Body.Close()
	return true
}

func testProxy(p *ProxySOCKS5) error {
	proxyDialer, err := checkProxy(p)
	if err != nil {
		return err
	}
	c := http.Client{
		Transport: &http.Transport{
			Dial: proxyDialer.Dial,
		},
	}

	resp, err := c.Get("http://fingerprints.bablosoft.com/prepare?version=5&tags=Microsoft%20Windows%2CChrome&returnpc=true")
	if err != nil {
		log.Println(err)
		return fmt.Errorf("[%s] failed to get IP: %v", p.String(), err)
	}
	cryptoRand, _ := rand.Int(rand.Reader, big.NewInt(10000000))
	f, err := os.OpenFile("fingerprints/"+"fingerprint_"+cryptoRand.String()+".txt", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()
	fingerprint, _ := io.ReadAll(resp.Body)
	f.WriteString(string(fingerprint))
	defer resp.Body.Close()
	return nil
}

func (pm *ProxyManager) GetProxy() (ProxySOCKS5, error) {
	switch pm.TypeGivingProxy {
	case "round-robin":
		return pm.getRoundRobinProxy()
	case "random":
		return pm.getRandomProxy()
	default:
		return ProxySOCKS5{}, fmt.Errorf("unknown proxy type: %s", pm.TypeGivingProxy)
	}
}

func (pm *ProxyManager) getRoundRobinProxy() (ProxySOCKS5, error) {
	if len(pm.Proxies) == 0 {
		return ProxySOCKS5{}, fmt.Errorf("no proxies available")
	}
	proxy := pm.Proxies[0]
	pm.Proxies = append(pm.Proxies[1:], pm.Proxies[0])
	return proxy, nil
}

func (pm *ProxyManager) getRandomProxy() (ProxySOCKS5, error) {
	if len(pm.Proxies) == 0 {
		return ProxySOCKS5{}, fmt.Errorf("no proxies available")
	}

	cryptoRand, err := rand.Int(rand.Reader, big.NewInt(int64(len(pm.Proxies))))
	if err != nil {
		return ProxySOCKS5{}, fmt.Errorf("failed to get random index: %v", err)
	}

	return pm.Proxies[cryptoRand.Int64()], nil
}

func (pm *ProxyManager) AddProxy(p *ProxySOCKS5) {
	pm.Proxies = append(pm.Proxies, *p)
}

func (pm *ProxyManager) RemoveProxy(p *ProxySOCKS5) {
	for i, proxy := range pm.Proxies {
		if proxy == *p {
			pm.Proxies = append(pm.Proxies[:i], pm.Proxies[i+1:]...)
			return
		}
	}
}
