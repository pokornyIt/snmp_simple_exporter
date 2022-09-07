// Simple SNMP exporter - With just a basic YAML file, you can connect any SNMP device to Prometheus
//
// Written by Paul Schou  github@paulschou.com  December 2020
// Update by pokornyIt.cz September 2022
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	g "github.com/gosnmp/gosnmp"
)

var version = "0.1.1"
var Reset = "\033[0m"
var Red = "\033[31m"
var Green = "\033[32m"
var Yellow = "\033[33m"
var Blue = "\033[34m"
var Purple = "\033[35m"
var Cyan = "\033[36m"
var Gray = "\033[37m"
var White = "\033[97m"

type Config struct {
	Push     string `yaml:"push"`
	Interval string `yaml:"interval"`
	Devices  []struct {
		Name         string             `yaml:"name"`
		Host         string             `yaml:"host"`
		Port         uint16             `yaml:"port"`
		Protocol     string             `yaml:"protocol"`
		Community    string             `yaml:"community"`
		UserName     string             `yaml:"username"`
		AuthProto    string             `yaml:"auth-protocol"`
		AuthPassword string             `yaml:"auth-password"`
		PrivProto    string             `yaml:"priv-protocol"`
		PrivPassword string             `yaml:"priv-password"`
		Version      string             `yaml:"version"`
		Interval     string             `yaml:"interval"`
		Enabled      bool               `yaml:"enabled" default:true`
		CopyFrom     string             `yaml:"copy-oids-from"`
		Labels       map[string]string  `yaml:"labels"`
		Status       map[string]string  `yaml:"status"`
		StaticLabels map[string]string  `yaml:"static-labels"`
		StaticStatus map[string]float64 `yaml:"static-status"`
		Groupings    []ConfigGroup      `yaml:"groupings"`
		nextRun      int64
		latency      int64
		running      bool
		groupData    [][]g.SnmpPDU
		//group_string   []string
	} `yaml:"devices"`
}
type ConfigGroup struct {
	Group        string             `yaml:"group"`
	OidIndex     string             `yaml:"index"`
	Priority     bool               `yaml:"priority"`
	QueryMetrics bool               `yaml:"query-metrics"`
	Labels       map[string]string  `yaml:"labels"`
	Status       map[string]string  `yaml:"status"`
	StaticLabels map[string]string  `yaml:"static-labels"`
	StaticStatus map[string]float64 `yaml:"static-status"`
	Interval     string             `yaml:"interval"`
}

var deviceMetrics []string
var config Config

var keyFile = ""
var certFile = ""
var keypair *tls.Certificate
var keypairCount = 0
var keypairMutex sync.RWMutex
var rootFile = ""
var rootCount = 0
var rootPool *x509.CertPool
var certsLoaded = make(map[string]bool, 0)
var debug = false
var maxRepetitions = uint8(50)
var timeout = 5

func main() {
	flag.Usage = func() {
		_, file := filepath.Split(os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "Simple SNMP prometheus exporter (%s),\n    written by Paul Schou github@paulschou.com in December 2020,\n    extend pokornyIt (https://github.com/pokornyIt) in September 2022\n    Prsonal use only, provided AS-IS -- not responsible for loss.\nUsage implies agreement.\n\nUsage of %s:\n", version, file)
		flag.PrintDefaults()
	}

	var listenPortFlag = flag.String("listenPortFlag", ":9070", "Listen address for forwarder")
	var configFileFlag = flag.String("config", "config.yml", "YML configuration file")
	var certFileFlag = flag.String("cert", "/etc/pki/server.pem", "File to load with CERT - automatically reloaded every minute")
	var keyFileFlag = flag.String("key", "/etc/pki/server.pem", "File to load with KEY - automatically reloaded every minute")
	var rootFileFlag = flag.String("ca", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "File to load with ROOT CAs - reloaded every minute by adding any new entries")
	var verifyClientFlag = flag.Bool("verify-client", true, "Verify or disable client certificate check")
	var verifyServerFlag = flag.Bool("verify-server", true, "Verify or disable server certificate check")
	var secureClientFlag = flag.Bool("secure-client", true, "Enforce TLS 1.2 on client side")
	var secureServerFlag = flag.Bool("secure-server", true, "Enforce TLS 1.2 on server side")
	var tlsEnabledFlag = flag.Bool("tls", false, "Enable listener TLS (use -tls=true)")
	var verbose = flag.Bool("debug", false, "Verbose output")
	var maxRep = flag.Int("maxrep", 50, "Max Repetitions")
	var Timeout = flag.Int("timeout", 5, "Per query timeout")
	flag.Parse()

	var err error
	debug = *verbose
	maxRepetitions = uint8(*maxRep)
	timeout = *Timeout

	keyFile = *keyFileFlag
	certFile = *certFileFlag
	rootFile = *rootFileFlag

	if *tlsEnabledFlag {
		rootPool = x509.NewCertPool()
		loadKeys()
		go func() {
			ticker := time.NewTicker(time.Minute)
			for {
				select {
				case <-ticker.C:
					loadKeys()
				}
			}
		}()
	}

	yamlFile, err := ioutil.ReadFile(*configFileFlag)
	if err != nil {
		log.Fatalf("Cannot read config file %s with error: %s", *configFileFlag, err)
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatal("Invalid config file format ", err)
	}
	if config.Interval == "" {
		config.Interval = "1m"
	}

	var minInterval time.Duration
	passed := true
	for i, dev := range config.Devices {
		if dev.Enabled == false {
			continue
		}
		if dev.CopyFrom != "" {
			srcIterator := 0
			for src, srcDevice := range config.Devices {
				if srcDevice.Name == dev.CopyFrom {
					srcIterator = src
					break
				}
			}
			if srcIterator >= 0 {
				config.Devices[i].StaticLabels = config.Devices[srcIterator].StaticLabels
				config.Devices[i].StaticStatus = config.Devices[srcIterator].StaticStatus
				config.Devices[i].Labels = config.Devices[srcIterator].Labels
				config.Devices[i].Status = config.Devices[srcIterator].Status
				config.Devices[i].Groupings = config.Devices[srcIterator].Groupings
			} else {
				log.Println("Warning: copy-from source device", dev.CopyFrom, "missing for", dev.Name)
			}
		}

		if dev.Interval == "" {
			config.Devices[i].Interval = config.Interval
		}

		if minInterval == 0 {
			interval, err := time.ParseDuration(config.Devices[i].Interval)
			if err == nil {
				minInterval = interval
			}
		} else {
			interval, err := time.ParseDuration(config.Devices[i].Interval)
			if err == nil {
				if minInterval.Nanoseconds() > interval.Nanoseconds() {
					minInterval = interval
				}
			}
		}

		passed = passed && checkLabels(config.Devices[i].StaticLabels)
		passed = passed && checkLabelN(config.Devices[i].StaticStatus)
		passed = passed && checkLabels(config.Devices[i].Labels)
		passed = passed && checkLabels(config.Devices[i].Status)
		for _, grp := range config.Devices[i].Groupings {
			passed = passed && checkLabels(grp.StaticLabels)
			passed = passed && checkLabelN(grp.StaticStatus)
			passed = passed && checkLabels(grp.Labels)
			passed = passed && checkLabels(grp.Status)
			config.Devices[i].groupData = make([][]g.SnmpPDU, len(config.Devices[i].Groupings))
			config.Devices[i].running = false
		}

		if debug {
			log.Println(fmt.Sprintf("#conf %s: %+v\r\n", dev.Name, config.Devices[i]))
		}

	}
	if passed == false {
		log.Fatal("Failed config checks")
	}

	var l net.Listener
	if *tlsEnabledFlag {
		log.Println("Setup TLS")
		var config tls.Config
		if *secureServerFlag {
			config = tls.Config{RootCAs: rootPool,
				Certificates: []tls.Certificate{},
				ClientCAs:    rootPool, InsecureSkipVerify: *verifyServerFlag == false,
				MinVersion:               tls.VersionTLS12,
				CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
			}
		} else {
			config = tls.Config{RootCAs: rootPool,
				ClientCAs: rootPool, InsecureSkipVerify: *verifyServerFlag == false}
		}
		config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if debug {
				log.Println("  Get Cert Returning keypair")
			}
			return keypair, nil
		}

		config.Rand = rand.Reader
		if debug {
			fmt.Println("TLS Listening on", *listenPortFlag)
		}
		if l, err = tls.Listen("tcp", *listenPortFlag, &config); err != nil {
			log.Fatal(err)
		}
	} else {
		var err error
		if debug {
			fmt.Println("Listening on", *listenPortFlag)
		}
		if l, err = net.Listen("tcp", *listenPortFlag); err != nil {
			log.Fatal(err)
		}
	}

	// Expose prometheus endpoint for querying metrics for debugging
	http.HandleFunc("/metrics", ServeMetrics)
	//go func() {
	log.Println("Server start in go routine")
	err = http.Serve(l, nil)
	if err != nil {
		log.Fatal(err)
	}
	//}()

	// make the query interval be unique to each device
	// Collect metrics from snmp endpoints
	deviceMetrics = make([]string, len(config.Devices))
	for i, dev := range config.Devices {
		if dev.Enabled {

			interval, err := time.ParseDuration(dev.Interval)
			if err != nil {
				log.Fatal("Device "+dev.Name+": Query interval not a valid time", err)
			}
			go func(i int, interval time.Duration) {
				runInterval := interval.Nanoseconds()
				config.Devices[i].nextRun = ((time.Now().UnixNano()+2e9)/runInterval + 1) * runInterval
				time.Sleep(time.Duration(config.Devices[i].nextRun-time.Now().UnixNano()-1.2e9) * time.Nanosecond)
				if debug {
					log.Println(" Next run for device "+config.Devices[i].Name+":", time.Unix(config.Devices[i].nextRun/1e9, 0))
				}
				go collectDev(i)
				for range time.Tick(interval) {
					config.Devices[i].nextRun = ((time.Now().UnixNano()+2e9)/runInterval + 1) * runInterval
					if debug {
						log.Println(" Next run for device "+config.Devices[i].Name+":", time.Unix(config.Devices[i].nextRun/1e9, 0))
					}
					go collectDev(i)
				}
			}(i, interval)
		}
	}

	// Push metrics if a push endpoint has been defined
	if config.Push != "" {
		ticker := time.NewTicker(minInterval)
		for {
			select {
			case <-ticker.C:

				func() {
					var buffer bytes.Buffer
					for _, data := range deviceMetrics {
						buffer.WriteString(data)
					}
					s := buffer.String()
					if len(s) < 3 {
						return
					}
					parts := strings.Split(config.Push, " ")
					for _, url := range parts {
						tlsClient := false
						if strings.HasPrefix(url, "https://") {
							tlsClient = true
						}
						var tlsConfig *tls.Config
						if tlsClient {
							if *secureClientFlag {
								tlsConfig = &tls.Config{RootCAs: rootPool,
									ClientCAs: rootPool, InsecureSkipVerify: *verifyClientFlag == false,
									MinVersion:               tls.VersionTLS12,
									CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
									PreferServerCipherSuites: true,
									CipherSuites: []uint16{
										tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
										tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
										tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
										tls.TLS_RSA_WITH_AES_256_CBC_SHA,
									},
								}
							} else {
								tlsConfig = &tls.Config{RootCAs: rootPool,
									ClientCAs: rootPool, InsecureSkipVerify: *verifyClientFlag == false}
							}
							if &keypair == nil {
								tlsConfig.Certificates = []tls.Certificate{*keypair}
							}
						}

						tr := &http.Transport{
							TLSClientConfig: tlsConfig,
						}
						client := &http.Client{Transport: tr}

						log.Println("Posting metrics to", url, len(s))

						response, err := client.Post(url, "text/plain", bytes.NewBuffer([]byte(s)))
						if err != nil {
							fmt.Println(err)
							continue
						}
						defer func(Body io.ReadCloser) {
							_ = Body.Close()
						}(response.Body)

						content, _ := ioutil.ReadAll(response.Body)
						s := strings.TrimSpace(string(content))

						// If there is any reply, return it
						if len(s) > 0 {
							fmt.Println(s)
						}

					}
				}()
			}
		}
	}
	// End of Main function
}

func getSNMP(i int) *g.GoSNMP {
	params := &g.GoSNMP{
		Port:               161,
		Transport:          "udp",
		Community:          "public",
		Version:            g.Version2c,
		Timeout:            time.Duration(timeout) * time.Second,
		Retries:            0,
		ExponentialTimeout: false,
		MaxOids:            50,
		MaxRepetitions:     uint32(maxRepetitions),
		Target:             config.Devices[i].Host,
		Context:            context.TODO(),
	}
	if debug {
		params.Logger = g.NewLogger(log.New(os.Stdout, "", 0))
	}
	switch ver := config.Devices[i].Version; ver {
	case "1":
		params.Version = g.Version1
	case "2c":
		params.Version = g.Version2c
	case "3":
		params.Version = g.Version3

		if config.Devices[i].UserName != "" {
			params.SecurityModel = g.UserSecurityModel
			if config.Devices[i].AuthPassword == "" {
				params.MsgFlags = g.NoAuthNoPriv
			} else {
				if config.Devices[i].PrivPassword == "" {
					params.MsgFlags = g.AuthNoPriv
				} else {
					params.MsgFlags = g.AuthPriv
				}
				sec := &g.UsmSecurityParameters{
					UserName:                 config.Devices[i].UserName,
					AuthenticationProtocol:   g.SHA,
					AuthenticationPassphrase: config.Devices[i].AuthPassword,
					PrivacyProtocol:          g.AES,
					PrivacyPassphrase:        config.Devices[i].PrivPassword,
				}

				switch p := strings.ToLower(config.Devices[i].AuthProto); p {
				case "none":
					sec.AuthenticationProtocol = g.NoAuth
				case "md5":
					sec.AuthenticationProtocol = g.MD5
				case "sha":
					sec.AuthenticationProtocol = g.SHA
				case "sha224":
					sec.AuthenticationProtocol = g.SHA224
				case "sha256":
					sec.AuthenticationProtocol = g.SHA256
				case "sha384":
					sec.AuthenticationProtocol = g.SHA384
				case "sha512":
					sec.AuthenticationProtocol = g.SHA512
				}

				switch p := strings.ToLower(config.Devices[i].PrivProto); p {
				case "none":
					sec.PrivacyProtocol = g.NoPriv
				case "des":
					sec.PrivacyProtocol = g.DES
				case "aes":
					sec.PrivacyProtocol = g.AES
				case "aes192":
					sec.PrivacyProtocol = g.AES192
				case "aes192c":
					sec.PrivacyProtocol = g.AES192C
				case "aes256":
					sec.PrivacyProtocol = g.AES256
				case "aes256c":
					sec.PrivacyProtocol = g.AES256C
				}
				params.SecurityParameters = sec
			}
		}

	}
	if config.Devices[i].Community != "" {
		params.Community = config.Devices[i].Community
	}
	if config.Devices[i].Port > 0 {
		params.Port = config.Devices[i].Port
	}
	if config.Devices[i].Protocol != "" {
		params.Transport = config.Devices[i].Protocol
	}

	err := params.Connect()
	if err != nil {
		log.Fatalf("Connect failed on device "+config.Devices[i].Name+", err: %v", err)
	}
	return params
}

func loadKeys() {
	keypairMutex.RLock()
	defer keypairMutex.RUnlock()

	tmpKey, errTmpKey := tls.LoadX509KeyPair(certFile, keyFile)
	if errTmpKey != nil {
		if keypair == nil {
			log.Fatalf("failed to loadkey pair: %s %s %s", certFile, keyFile, errTmpKey)
		}
		keypairCount++
		log.Println("WARNING: Cannot load keypair (cert/key)", certFile, keyFile, "attempt:", keypairCount)
		if keypairCount > 10 {
			log.Fatalf("failed to refresh pair: %s %s %s", certFile, keyFile, errTmpKey)
		}
	} else {
		if debug {
			log.Println("Loaded keypair", certFile, keyFile)
		}
		keypair = &tmpKey
		keypairCount = 0
	}

	errRead := LoadCertificateFromFile(rootFile)
	if errRead != nil {
		if rootPool == nil {
			log.Fatalf("failed to load CA: %s %s", rootFile, errRead)
		}
		rootCount++
		log.Println("WARNING: Cannot load CA file", rootFile, "attempt:", rootCount)
		if rootCount > 10 {
			log.Fatalf("failed refresh CA: %s %s", rootFile, errRead)
		}
	} else {
		if debug {
			log.Println("Loaded CA", rootFile)
		}
		rootCount = 0
	}
}

func LoadCertificateFromFile(path string) error {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				fmt.Println("warning: error parsing CA cert", err)
				continue
			}
			t := fmt.Sprintf("%v%v", cert.SerialNumber, cert.Subject)
			if _, ok := certsLoaded[t]; !ok {
				if debug {
					fmt.Println(" Adding CA:", cert.Subject)
				}
				rootPool.AddCert(cert)
				certsLoaded[t] = true
			}
		}
		raw = rest
	}

	return nil
}

func ServeMetrics(w http.ResponseWriter, r *http.Request) {
	log.Println("One request on /metric")
	w.Header().Set("Server", "SNMP-Prom Exporter - Written by PaulSchou.com; CopyRight 2020 see license file for more details")
	w.Header().Add("Cache-Control:", "no-store, no-cache")
	w.Header().Add("X-Content-Type-Options", "nosniff")
	w.Header().Add("X-XSS-Protection", "1; mode=block")

	count := 0
	for i, dev := range config.Devices {
		if dev.Enabled {
			count++
			_, _ = fmt.Fprintf(w, "# Device %s (%s)\n", config.Devices[i].Name, config.Devices[i].Host)
			if len(deviceMetrics[i]) == 0 {
				_, _ = fmt.Fprintf(w, "# ...waiting for next query interval mark\n")
			} else {
				_, _ = fmt.Fprintf(w, "%s\n", deviceMetrics[i])
			}
		}
	}
	if count == 0 {
		_, _ = fmt.Fprintf(w, "# No devices have been configured or enabled\n")
	}

}

func mkList(oids []string, devOids map[string]string) []string {
	for _, v := range devOids {
		found := false
		for _, t := range oids {
			if t == v {
				found = true
			}
		}
		if found == false {
			v = strings.SplitN(v, " ", 2)[0]
			oids = append(oids, v)
		}
	}
	return oids
}

func collectDev(idev int) {
	if config.Devices[idev].running {
		return
	}
	config.Devices[idev].running = true
	defer func() { config.Devices[idev].running = false }()

	queryChannel := make(chan []g.SnmpPDU) // preallocate channels for parallelism

	for i, group := range config.Devices[idev].Groupings {
		if group.Priority {
			snmp := getSNMP(idev)
			defer snmp.Conn.Close()
			if debug {
				fmt.Println("#", config.Devices[idev].Name, "setting up query for", group.Group)
			}
			if config.Devices[idev].latency == 0 {
				// zero latency is impossible, so let's put something as a temporary placeholder
				config.Devices[idev].latency = 200000
			}

			go func(idev int, i int) {
				oids := mkList([]string{}, config.Devices[idev].Groupings[i].Status)
				oids = mkList(oids, config.Devices[idev].Groupings[i].Labels)
				if debug {
					fmt.Println("#", config.Devices[idev].Name, "waiting", config.Devices[idev].nextRun-time.Now().UnixNano(), "net latency adjustment", config.Devices[idev].latency)
					fmt.Println("to send query for", config.Devices[idev].Groupings[i].Group)
				}
				time.Sleep(time.Duration(config.Devices[idev].nextRun-time.Now().UnixNano()-config.Devices[idev].latency/2) * time.Nanosecond)

				data := make([]g.SnmpPDU, 0)
				var err error
				for _, oid := range config.Devices[idev].Groupings[i].Status {
					result, err := snmp.WalkAll(oid)
					if err == nil {
						data = append(data, result...)
					} else {
						break
					}
				}

				for _, oid := range config.Devices[idev].Groupings[i].Labels {
					result, err := snmp.WalkAll(oid)
					if err == nil {
						data = append(data, result...)
					} else {
						break
					}
				}

				if len(data) == 0 {
					log.Println(Cyan+"Empty reply during oid fetch for priority group:", config.Devices[idev].Groupings[i].Group, " name:", config.Devices[idev].Name, "host:", config.Devices[idev].Host, err, Reset)
				}

				queryChannel <- data
			}(idev, i)
		}
	}
	for i, _ := range config.Devices[idev].Groupings {
		if config.Devices[idev].Groupings[i].Priority {
			config.Devices[idev].groupData[i] = <-queryChannel
			if len(config.Devices[idev].groupData[i]) == 0 {
				return
			}
		}
	}

	snmp := getSNMP(idev)
	defer snmp.Conn.Close()
	snmp.Retries = 3

	// Setup output details / target
	runTime := config.Devices[idev].nextRun / 1e6
	outData := bytes.Buffer{}
	defer func(idev int, outData *bytes.Buffer) {
		deviceMetrics[idev] = outData.String()
	}(idev, &outData)

	//dev_query := make(chan *g.SnmpPacket)
	//func() {
	//time.Sleep(80 * time.Millisecond) // * time.Nanosecond)
	oids := mkList([]string{}, config.Devices[idev].Status)
	oids = mkList(oids, config.Devices[idev].Labels)
	var sent time.Time
	snmp.OnSent = func(x *g.GoSNMP) {
		sent = time.Now()
	}
	snmp.OnRecv = func(x *g.GoSNMP) {
		config.Devices[idev].latency = time.Since(sent).Nanoseconds()
	}
	deviceData, err := snmp.Get(oids) // Get() accepts up to g.MAX_OIDS
	snmp.OnSent = nil
	snmp.OnRecv = nil
	if err != nil {
		log.Println("Error during oid fetch for device status host:", config.Devices[idev].Host, err)
		return
	}
	//dev_query <- result
	//}()
	//deviceData := <-dev_query
	if deviceData == nil {
		log.Println("No data returned for dev query, skipping host", config.Devices[idev].Host, err)
		return
	}

	// PARSE Labels for device
	deviceLabels := make(map[string]string)
	deviceLabels["device_host"] = config.Devices[idev].Host
	deviceLabels["device_name"] = config.Devices[idev].Name
	for lbl, value := range config.Devices[idev].StaticLabels {
		deviceLabels[lbl] = fmt.Sprintf("%v", value)
	}
	for lbl, oid := range config.Devices[idev].Labels {
		oidDot, oidType := dotEnd(oid)
		for _, variable := range deviceData.Variables {
			if oidDot == variable.Name+"." {
				deviceLabels[lbl] = fmt.Sprintf("%s", printPDU(variable, oidType))
			}
		}
	}

	// PARSE Stats for device
	for lbl, value := range config.Devices[idev].StaticStatus {
		outData.WriteString(fmt.Sprintf("snmp_%s{%s} %v %d\n", lbl, promLabels(deviceLabels), value, runTime))
	}
	for stat, oid := range config.Devices[idev].Status {
		oidDot, oidType := dotEnd(oid)
		for _, variable := range deviceData.Variables {
			if oidDot == variable.Name+"." {
				outData.WriteString(fmt.Sprintf("snmp_%s{%s} %v %d\n", stat, promLabels(deviceLabels), printPDU(variable, oidType), runTime))
			}
		}
	}

	// Loop over the rest of the non priority groups
	for i, group := range config.Devices[idev].Groupings {
		//time.Sleep(80 * time.Millisecond)
		if !group.Priority {
			if debug {
				fmt.Println("#", config.Devices[idev].Name, "setting up query for", group.Group)
			}

			if debug {
				fmt.Println("#", config.Devices[idev].Name, "sending query for", config.Devices[idev].Groupings[i].Group, oids)
			}

			data := make([]g.SnmpPDU, 0)
			var err error
			for _, oid := range config.Devices[idev].Groupings[i].Status {
				result, err := snmp.WalkAll(oid)
				if err == nil {
					data = append(data, result...)
				} else {
					break
				}
			}

			for _, oid := range config.Devices[idev].Groupings[i].Labels {
				result, err := snmp.WalkAll(oid)
				if err == nil {
					data = append(data, result...)
				} else {
					break
				}
			}

			if len(data) == 0 {
				log.Println(Cyan+"Empty reply during oid fetch for group:", config.Devices[idev].Groupings[i].Group, " name:", config.Devices[idev].Name, "host:", config.Devices[idev].Host, err, Reset)
			}

			config.Devices[idev].groupData[i] = data
		}
	}

	for i, grp := range config.Devices[idev].Groupings {
		parse(deviceLabels, grp, config.Devices[idev].groupData[i], runTime, &outData)
	}

	if config.Devices[idev].latency > 0 {
		outData.WriteString(fmt.Sprintf("snmp_latency_seconds{%s} %v %d\n", promLabels(deviceLabels), float64(config.Devices[idev].latency)/1e9, runTime))
	}
}

func dotEnd(str string) (string, string) {
	temp := strings.SplitN(str, " ", 2)
	if len(temp) == 1 {
		return strings.TrimSuffix(temp[0], ".") + ".", ""
	} else {
		return strings.TrimSuffix(temp[0], ".") + ".", temp[1]
	}
}
func printPDU(pdu g.SnmpPDU, oid_type string) string {
	switch pdu.Type {
	case g.OctetString:
		b := pdu.Value.([]byte)
		if strings.TrimSpace(oid_type) == "" {
			return fmt.Sprintf("%s", string(b))
		}
		return byteStr(b, strings.TrimSpace(oid_type))
	case g.Counter64:
		return fmt.Sprintf("%v", g.ToBigInt(pdu.Value))
	default:
		return fmt.Sprintf("%v", pdu.Value)
	}
}

func parse(devLabels map[string]string, group ConfigGroup, data []g.SnmpPDU, runTime int64, outData *bytes.Buffer) {
	if len(data) == 0 {
		if debug {
			log.Println(Yellow+"Empty SNMP reply on", devLabels["device_name"], "- Cannot parse data for group", group.Group, Reset)
		}
		return
	}
	// PARSE Labels for Group
	commonLabels := make(map[string]string)
	for lbl, value := range group.StaticLabels {
		commonLabels[lbl] = fmt.Sprintf("%v", value)
	}
	groupLabels := make(map[string]map[string]string)
	for lbl, oid := range group.Labels {
		oidDot, oidType := dotEnd(oid)
		for _, variable := range data {
			if strings.HasPrefix(variable.Name, oidDot) {
				t := variable.Name[(len(oidDot)):]
				//fmt.Println("oid=", oid, "name=", variable.Name, "t=", t, "lbl=", lbl, fmt.Sprintf("%v", variable.Value), index)
				if _, ok := groupLabels[t]; !ok {
					groupLabels[t] = make(map[string]string)
				}
				groupLabels[t][lbl] = printPDU(variable, oidType)
			}
		}
	}

	// PARSE Stats for Group
	for t, _ := range groupLabels {
		for lbl, value := range group.StaticStatus {
			outData.WriteString(fmt.Sprintf("snmp_%s_%s{%s} %v %d\n", group.Group, lbl, promLabels(devLabels, commonLabels, groupLabels[t]), value, runTime))
		}
	}
	//index := make(map[string]int)
	for stat, oid := range group.Status {
		oidDot, oidType := dotEnd(oid)
		for _, variable := range data {
			if strings.HasPrefix(variable.Name, oidDot) {
				t := variable.Name[len(oidDot):]
				if _, ok := groupLabels[t]; !ok {
					groupLabels[t] = make(map[string]string)
				}
				oidIndex(groupLabels[t], t, group.OidIndex)
				//groupLabels[t]["oid_index"] = t
				outData.WriteString(fmt.Sprintf("snmp_%s_%s{%s} %v %d\n", group.Group, stat, promLabels(devLabels, commonLabels, groupLabels[t]), printPDU(variable, oidType), runTime))
			}
		}
	}
}

func checkLabels(labels map[string]string) bool {
	check := true
	for lbl, _ := range labels {
		if checkLabel(lbl) == false {
			fmt.Println("  invalid label:", lbl)
			check = false
		}
	}
	return check
}

func byteStr(b []byte, outFmt string) string {
	s := ""
	switch outFmt {
	case "ipv4":
		for i := 0; i < len(b); i++ {
			if i == 1 {
				s = fmt.Sprintf("%d", b[i])
			} else {
				s = fmt.Sprintf("%s.%d", s, b[i])
			}
		}
	case "ipv6":
		for i := 1; i < len(b); i = i + 2 {
			if i == 1 {
				s = fmt.Sprintf("%02x%02x", b[i-1], b[i])
			} else {
				s = fmt.Sprintf("%s:%02x%02x", s, b[i-1], b[i])
			}
		}
	case "mac":
		for i, c := range b {
			if i == 0 {
				s = fmt.Sprintf("%02x", c)
			} else {
				s = fmt.Sprintf("%s:%02x", s, c)
			}
		}
	case "hex":
		return fmt.Sprintf("%02x", b)
	default:
		return fmt.Sprintf("type! %02x", b)
	}
	return s
}

func oidIndex(lbl map[string]string, oid string, outFmt string) {
	if outFmt == "" {
		lbl["oid_index"] = oid
		return
	}

	sp := strings.Split(oid, ".")
	b := make([]byte, len(sp))
	for i, v := range sp {
		t, _ := strconv.Atoi(v)
		b[i] = byte(t)
	}
	switch outFmt {
	case "mac":
		if len(sp) == 6 {
			lbl["oid_mac"] = byteStr(b[0:6], outFmt)
		} else if len(sp) > 6 {
			lbl["oid_mac"] = byteStr(b[0:6], outFmt)
			lbl["oid_index"] = strings.Join(sp[6:], ".")
		} else {
			lbl["oid_index"] = "!mac " + byteStr(b, "hex")
		}
	case "route1":
		if len(sp) >= 13 {
			lbl["oid_subnet"] = strings.Join(sp[0:4], ".")
			lbl["oid_mask"] = strings.Join(sp[4:8], ".")
			lbl["oid_IPv"] = strings.Join(sp[8:9], ".")
			lbl["oid_nextHop"] = strings.Join(sp[9:13], ".")
			if len(sp) > 13 {
				lbl["oid_index"] = strings.Join(sp[13:len(sp)], ".")
			}
		} else {
			lbl["oid_index"] = "!route4 " + oid
		}
	case "route14":
		if len(sp) >= 14 {
			lbl["oid_subnet"] = strings.Join(sp[0:4], ".")
			lbl["oid_mask"] = strings.Join(sp[4:8], ".")
			lbl["oid_IPv"] = strings.Join(sp[8:9], ".")
			lbl["oid_nextHop"] = strings.Join(sp[10:14], ".")
			if len(sp) > 14 {
				lbl["oid_index"] = strings.Join(sp[13:len(sp)], ".")
			}
		} else {
			lbl["oid_index"] = "!route14 " + oid
		}
	case "route6":
		if len(sp) >= 17 {
			lbl["oid_addr"] = byteStr(b[0:16], "ipv6")
			if len(sp) > 16 {
				lbl["oid_index"] = strings.Join(sp[16:len(sp)], ".")
			}
		} else {
			lbl["oid_index"] = "!route6 " + oid
		}
	case "ipv4":
		if len(sp) == 4 {
			lbl["oid_ipv4"] = oid
		} else {
			lbl["oid_index"] = "!ipv4 " + oid
		}
	default:
		lbl["oid_index"] = oid
	}
}

func checkLabelN(labels map[string]float64) bool {
	check := true
	for lbl, _ := range labels {
		if checkLabel(lbl) == false {
			fmt.Println("  invalid label:", lbl, "/ allowed characters: [a-zA-Z0-9_]")
			check = false
		}
	}
	return check
}

func checkLabel(label string) bool {
	matched, err := regexp.Match(`^[a-zA-Z_][a-zA-Z0-9_]*$`, []byte(label))
	if err != nil {
		return false
	}
	return matched
}

func promLabels(lbl ...map[string]string) string {
	s := make(map[string]string)
	for _, in := range lbl {
		for k, v := range in {
			s[k] = fmt.Sprintf("%v", v)
		}
	}
	var out []string
	for k, v := range s {
		out = append(out, fmt.Sprintf("%s=%q", k, v))
	}
	return strings.Join(out, ",")
}