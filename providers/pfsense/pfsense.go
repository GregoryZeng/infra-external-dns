package pfsense

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql" // for MySQL lib importing
	"github.com/rancher/external-dns/providers"
	"github.com/rancher/external-dns/utils"
	"github.com/samuel/go-zookeeper/zk"
)

type PfsenseProvider struct {
	root        string
	apiKey      string
	apiSecret   string
	dnsTest     []interface{}
	dbOpenParam string
}

type WhitelistEntry struct {
	Fqdn   string
	host   string
	domain string
}

var WhiteList = []WhitelistEntry{}

func updateWhiteList() {
	c, _, err := zk.Connect([]string{"zk"}, time.Second)
	if err != nil {
		fmt.Println("zk connect fails")
		panic(err)
	}
	children, _, _, err := c.ChildrenW("/external-dns-whitelist")
	if err != nil {
		fmt.Println("children fetch fails")
		panic(err)
	}
	WhiteList = []WhitelistEntry{}
	for _, key := range children {
		recv, _, _ := c.Get("/external-dns-whitelist/" + key)
		full := string(recv)
		ind := strings.IndexRune(full, '.')
		WhiteList = append(WhiteList, WhitelistEntry{
			Fqdn:   key,
			host:   full[:ind],
			domain: full[ind+1:],
		})
	}
	fmt.Println("Current WhiteList:", WhiteList)

}

// TxtRec : A TXT record designed for bookkeeping all store records in DNS server is now implemented to be stored locally
var TxtRec = utils.DnsRecord{}

func init() {
	providers.RegisterProvider("pfsense", &PfsenseProvider{})
}

func readStrFromZK(path string) string {
	fmt.Println("***** readStrFromZK() called *****")

	c, _, err := zk.Connect([]string{"zk"}, time.Second)
	if err != nil {
		fmt.Println("zk connect fails")
		panic(err)
	}
	recv, _, err := c.Get(path)
	if err != nil {
		fmt.Println("children fetch fails")
		panic(err)
	}
	fmt.Println("recv:", string(recv))
	fmt.Println("***** readStrFromZK() ended *****")

	return string(recv)
}

func (pf *PfsenseProvider) Init(rootDomainName string) error {

	fmt.Println("***** Init() called *****")
	fmt.Printf("rootDomainNames: %s \n", rootDomainName)

	pf.apiSecret = readStrFromZK("/external-dns-configuration/PFSENSE_APISECRET")
	pf.apiKey = readStrFromZK("/external-dns-configuration/PFSENSE_APIKEY")
	pf.dbOpenParam = readStrFromZK("/external-dns-configuration/MYSQL_OPENPARAM")
	pf.root = utils.UnFqdn(rootDomainName)
	updateWhiteList()
	pf.getConfig()
	localDnsRecs, _ = pf.getConfig()

	fmt.Println("***** Init() ends ******")
	return nil
}

func (pf *PfsenseProvider) GetName() string {
	fmt.Println("***** GetName() called and ends *****")
	return "Pfsense"
}

func (pf *PfsenseProvider) HealthCheck() error {
	// fmt.Println("***** HealthCheck() called and ends ******")
	return nil
}

func (pf *PfsenseProvider) generateAuth() string {
	b := make([]byte, 40)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("rand errs")
		panic(err)
	}
	nonce := base64.StdEncoding.EncodeToString(b)
	// Now, nonce should be a UTF-8 byte sequence (aka string)
	nonce = strings.Replace(nonce, "=", "", -1)
	nonce = strings.Replace(nonce, "/", "", -1)
	nonce = strings.Replace(nonce, "+", "", -1)
	nonce = nonce[0:8]
	// nonce is completed

	timestamp := fmt.Sprintf("%04d%02d%02dZ%02d%02d%02d",
		time.Now().UTC().Year(),
		time.Now().UTC().Month(),
		time.Now().UTC().Day(),
		time.Now().UTC().Hour(),
		time.Now().UTC().Minute(),
		time.Now().UTC().Second(),
	)

	auth := sha256.Sum256([]byte(pf.apiSecret + timestamp + nonce))
	authHex := make([]byte, hex.EncodedLen(len(auth)))
	hex.Encode(authHex, auth[:])
	authVal := pf.apiKey + ":" + timestamp + ":" + nonce + ":" + string(authHex[:])
	return authVal
}

func (pf *PfsenseProvider) getConfig() (map[string]interface{}, error) {

	authVal := pf.generateAuth()
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://pfsense/fauxapi/v1/?action=config_get&__debug=True", nil)
	req.Header.Add("fauxapi-auth", authVal)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		panic("client GET fails")

	}
	defer resp.Body.Close()
	config, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		panic("resp errs")

	}
	var configDat map[string]interface{}

	if err = json.Unmarshal(config, &configDat); err != nil {
		fmt.Println(err)
		panic("json parse errs")

	}
	lst := configDat["data"].(map[string]interface{})["config"].(map[string]interface{})
	return lst, nil
}

var localDnsRecs map[string]interface{}

func (pf *PfsenseProvider) postConfig(conf map[string]interface{}) error {
	client := &http.Client{}
	configBytes, err := json.Marshal(conf)
	if err != nil {
		fmt.Println("json encoding fails")
		panic(err)
	}

	req, err := http.NewRequest("POST",
		"http://pfsense/fauxapi/v1/?action=config_set&__debug=True",
		bytes.NewBuffer(configBytes),
	)
	if err != nil {
		fmt.Println("POST fails")
		panic(err)
	}

	authVal := pf.generateAuth()
	req.Header.Add("fauxapi-auth", authVal)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("client GET fails")
		panic(err)
	}

	defer resp.Body.Close()
	return nil
}

func (pf *PfsenseProvider) AddRecord(record utils.DnsRecord) error {

	fmt.Println("***** AddRecord() called *****")
	fmt.Println("utils.dnsRecord:", record)
	// updateWhiteList()
	if record.Type == "A" {
		// Temporarily ignore non-A records, and only allow records appeared in whitelist to be registered in the pfsense
		var toHost string
		var toDomain string
		var found = false
		for _, rec := range WhiteList {
			if rec.Fqdn == record.Fqdn {
				found = true
				toHost = rec.host
				toDomain = rec.domain
				break
			}
		}
		if !found {
			return nil
		}

		if err := pf.RemoveRecord(record); err != nil {
			return err
		}

		conf, _ := pf.getConfig()

		hostList := conf["dnsmasq"].(map[string]interface{})["hosts"].([]interface{})

		hostList = append(hostList, map[string]interface{}{
			"aliases": "",
			"descr":   "a Rancher/external-dns autogenerated record",
			"domain":  toDomain,
			"host":    toHost,
			// "idx":     "",
			"ip": record.Records[0],
		})

		updateDnsmasq := conf["dnsmasq"].(map[string]interface{})
		updateDnsmasq["hosts"] = hostList
		conf["dnsmasq"] = updateDnsmasq

		fmt.Println("Current hostList:", hostList)
		pf.postConfig(conf)
		pf.applyChanges()

	} else if record.Type == "TXT" {

		// we now store the TXT record in DB

		db, err := sql.Open("mysql", pf.dbOpenParam)
		if err != nil {
			fmt.Println("db open errs")
			panic(err)
		}
		defer db.Close()

		err = db.Ping()
		if err != nil {
			fmt.Println("db ping err")
			panic(err)
		}

		var recordInJson = map[string]interface{}{
			"Fqdn":    record.Fqdn,
			"Records": record.Records,
			"Type":    record.Type,
			"TTL":     record.TTL,
		}
		var jsonInBytes, _ = json.Marshal(recordInJson)
		db.Exec("delete from TxtRec")
		db.Exec("insert into TxtRec (Txt) value (?)", string(jsonInBytes))

	}
	fmt.Println("*****AddRecord() ends *****")
	return nil
}

func (pf *PfsenseProvider) UpdateRecord(record utils.DnsRecord) error {
	fmt.Println("***** Update() called *****")
	fmt.Println("utils.dnsRecord:", record)

	if err := pf.RemoveRecord(record); err != nil {
		fmt.Println("remove record fails")
		panic(err)
	}
	fmt.Println("***** Update() ends *****")
	return pf.AddRecord(record)
}

func (pf *PfsenseProvider) RemoveRecord(record utils.DnsRecord) error {
	fmt.Println("***** RemoveRecord() called *****")
	// updateWhiteList()
	fmt.Println("utils.dnsRecord:", record)

	if record.Type != "A" {
		return nil
	}

	conf, _ := pf.getConfig()

	var toHost string
	var toDomain string
	var found = false
	for _, rec := range WhiteList {
		if rec.Fqdn == record.Fqdn {
			found = true
			toHost = rec.host
			toDomain = rec.domain
		}
	}
	if !found {
		fmt.Println("***** record to remove is not found. *****")
		return nil
	}

	hostList := conf["dnsmasq"].(map[string]interface{})["hosts"].([]interface{})
	var updatedList []interface{}
	fmt.Println("hostlist before:", hostList)

	fmt.Println("toHost:", toHost, "toDomain:", toDomain)
	for _, confRecord := range hostList {
		fmt.Println("conf[host]:", confRecord.(map[string]interface{})["host"].(string))
		fmt.Println("conf[domain]:", confRecord.(map[string]interface{})["domain"].(string))
		if confRecord.(map[string]interface{})["host"].(string) == toHost &&
			confRecord.(map[string]interface{})["domain"].(string) == toDomain {
			continue
		} else {
			updatedList = append(updatedList, confRecord)
		}
	}
	updateDnsmasq := conf["dnsmasq"].(map[string]interface{})
	updateDnsmasq["hosts"] = updatedList
	conf["dnsmasq"] = updateDnsmasq

	fmt.Println("hostlist after:", hostList)
	pf.postConfig(conf)
	pf.applyChanges()
	fmt.Println("*****RemoveRecord() ends******")

	return nil
}

func (pf *PfsenseProvider) GetRecords() ([]utils.DnsRecord, error) {
	fmt.Println("***** GetRecords() called *****")
	var records []utils.DnsRecord
	conf, _ := pf.getConfig()

	hostList := conf["dnsmasq"].(map[string]interface{})["hosts"].([]interface{})
	for idx, rec := range hostList {
		fmt.Println(idx, ":", rec)

		var fromFqdn string
		var found = false
		for _, whiteEnt := range WhiteList {
			if whiteEnt.host == rec.(map[string]interface{})["host"].(string) &&
				whiteEnt.domain == rec.(map[string]interface{})["domain"].(string) {
				fromFqdn = whiteEnt.Fqdn
				found = true
				break
			}
		}

		if !found {
			continue
		}

		records = append(records, utils.DnsRecord{
			Fqdn:    fromFqdn,
			Records: []string{rec.(map[string]interface{})["ip"].(string)},
			Type:    "A",
			// Currently, we only process Type A record
			TTL: 150,
		})
	}

	// Now, fetch TXT record from MySQL
	db, err := sql.Open("mysql", pf.dbOpenParam)
	if err != nil {
		fmt.Println("db open errs")
		panic(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		fmt.Println("db ping err")
		panic(err)
	}

	Txt, err := db.Query("select Txt from TxtRec limit 1")
	if err != nil {
		fmt.Println("db query errs:", err)
		panic(err)
	}
	var TxtInString string

	count := 0
	for Txt.Next() {
		Txt.Scan(&TxtInString)
		count++
	}
	defer Txt.Close()

	fmt.Println("count:", count)

	if count == 0 {
		// just do not emit the TXT record
	} else {

		var TxtJson map[string]interface{}
		err = json.Unmarshal([]byte(TxtInString), &TxtJson)
		if err != nil {
			fmt.Println("unmarshal errs")
			panic(err)
		}

		Ips := TxtJson["Records"].([]interface{})
		var Records []string
		for _, ip := range Ips {
			Records = append(Records, ip.(string))
		}

		records = append(records, utils.DnsRecord{
			Fqdn:    TxtJson["Fqdn"].(string),
			Records: Records,
			Type:    "TXT",
			TTL:     140,
		})
	}

	fmt.Println("***** GetRecords() ends *****")
	return records, nil
}

func (pf *PfsenseProvider) functionCall(f string) {
	client := &http.Client{}

	conf := map[string]interface{}{
		"function": f,
	}

	configBytes, err := json.Marshal(conf)
	if err != nil {
		fmt.Println("json encoding fails")
		panic(err)
	}

	req, err := http.NewRequest("POST",
		"http://pfsense/fauxapi/v1/?action=function_call&__debug=True",
		bytes.NewBuffer([]byte(configBytes)),
	)
	if err != nil {
		fmt.Println("POST fails")
		panic(err)
	}

	authVal := pf.generateAuth()
	req.Header.Add("fauxapi-auth", authVal)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("client POST fails")
		panic(err)
	}
	fmt.Println(resp.StatusCode)

	defer resp.Body.Close()
}

func (pf *PfsenseProvider) applyChanges() {
	pf.functionCall("services_dnsmasq_configure")
	pf.functionCall("filter_configure")
	pf.functionCall("system_resolvconf_generate")
	pf.functionCall("system_dhcpleases_configure")
	time.Sleep(10 * time.Second)
}
