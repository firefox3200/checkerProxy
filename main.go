package main

import (
	"bufio"
	"log"
	"os"
	"sync"
)

var pm ProxyManager = *NewProxyManager([]ProxySOCKS5{}, ProxyTypeRandom)

func main() {
	file, err := os.OpenFile("proxy.txt", os.O_RDONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var wgCheck sync.WaitGroup
	for scanner.Scan() {
		wgCheck.Add(1)
		p, err := parseProxySOCKS5(scanner.Text())
		go func(p *ProxySOCKS5, err error) {
			defer wgCheck.Done()

			if err != nil {
				log.Fatal(err)
			}
			if err := testProxy(p); err != nil {
				log.Println(err)
				return
			}
			pm.AddProxy(p)
			log.Println("GOOD Proxy:", p.String())
		}(p, err)
		wgCheck.Wait()
	}
	log.Println("Loaded ", len(pm.Proxies), "proxies")
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	//Write GOOD proxy in good_proxy.txt
	file, err = os.OpenFile("good_proxy.txt", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	for i := range pm.Proxies {
		_, err := file.WriteString(pm.Proxies[i].String() + "\n")
		if err != nil {
			log.Fatal(err)
		}
	}
}
