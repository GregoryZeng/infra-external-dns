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
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql" // for MySQL lib importing
	"github.com/rancher/external-dns/providers"
	"github.com/rancher/external-dns/utils"
	"github.com/samuel/go-zookeeper/zk"
)

var varmutex = &sync.Mutex{}
var actionmutex = &sync.Mutex{}
var changed = false

type PfsenseProvider struct {
	apiKey      string
	apiSecret   string
	dbOpenParam string
}

func init() {
	providers.RegisterProvider("pfsense", &PfsenseProvider{})
}

func (pf *PfsenseProvider) Init(rootDomainName string) error {

	fmt.Println("***** Init() called *****")
	fmt.Printf("rootDomainNames: %s \n", rootDomainName)

	pf.apiSecret = pf.readStrFromZK("/external-dns-configuration/PFSENSE_APISECRET")
	pf.apiKey = pf.readStrFromZK("/external-dns-configuration/PFSENSE_APIKEY")
	pf.dbOpenParam = pf.readStrFromZK("/external-dns-configuration/MYSQL_OPENPARAM")

	pf.getWhiteList()
	pf.initLocalARecord()
	pf.initLocalTxt()

	pf.batchUpdate()

	fmt.Println("***** Init() ends ******")
	return nil
}

func (pf *PfsenseProvider) readStrFromZK(path string) string {
	fmt.Println("***** readStrFromZK() called *****")
	c, _, err := zk.Connect([]string{"zk"}, 10*time.Second)
	defer c.Close()
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

func (pf *PfsenseProvider) getWhiteList() {
	c, _, err := zk.Connect([]string{"zk"}, 10*time.Second)
	defer c.Close()
	if err != nil {
		fmt.Println("zk connect fails")
		panic(err)
	}
	children, _, _, err := c.ChildrenW("/external-dns-whitelist")
	if err != nil {
		fmt.Println("children fetch fails")
		panic(err)
	}
	whiteList = []whitelistEntry{}
	for _, key := range children {
		recv, _, _ := c.Get("/external-dns-whitelist/" + key)
		full := string(recv)
		ind := strings.IndexRune(full, '.')
		whiteList = append(whiteList, whitelistEntry{
			Fqdn:   key,
			host:   full[:ind],
			domain: full[ind+1:],
		})
	}
	fmt.Println("Current whiteList:", whiteList)
}

type whitelistEntry struct {
	Fqdn   string
	host   string
	domain string
}

var whiteList = []whitelistEntry{}

func (pf *PfsenseProvider) initLocalARecord() {
	conf := pf.getConfig()
	dnsrecs := conf["dnsmasq"].(map[string]interface{})["hosts"].([]interface{})
	for _, dnsrec := range dnsrecs {
		curDnsRec := dnsrec.(map[string]interface{})

		// Try to match DNS records returned from pfSense to entries
		//  in the whitelist and then perform a "translation" from the
		//  <host,domain> record to the corresponding service FQDN
		var serviceFqdn string
		var found = false
		for _, whiteEnt := range whiteList {
			// A "match" is made on the "host" field
			//  and the "domain" field
			if whiteEnt.host == curDnsRec["host"].(string) &&
				whiteEnt.domain == curDnsRec["domain"].(string) {
				serviceFqdn = whiteEnt.Fqdn
				found = true
				break
			}
		}

		if found {
			localDnsARecord = append(localDnsARecord, utils.DnsRecord{
				Fqdn:    serviceFqdn,
				Records: []string{curDnsRec["ip"].(string)},
				Type:    "A",
				TTL:     150,
			})
		}

	}
}

func (pf *PfsenseProvider) initLocalTxt() {

	exist, TxtInString := pf.getTxtFromMySQL()

	if exist {
		fmt.Println("initLocalTxt: previous rec found")
		var TxtJson map[string]interface{}
		err := json.Unmarshal([]byte(TxtInString), &TxtJson)
		if err != nil {
			fmt.Println("unmarshal errs")
			panic(err)
		}

		// initialize local txt record
		Ips := TxtJson["Records"].([]interface{})
		var Records []string
		for _, ip := range Ips {
			Records = append(Records, ip.(string))
		}

		localDnsARecordVarLock.Lock()
		pLocalTxtRec = new(utils.DnsRecord)
		*pLocalTxtRec = utils.DnsRecord{
			Fqdn:    TxtJson["Fqdn"].(string),
			Records: Records,
			Type:    "TXT",
			TTL:     140,
		}
		localDnsARecordVarLock.Unlock()

	} else {
		fmt.Println("initLocalTxt: no recs")
	}

}

func (pf *PfsenseProvider) getTxtFromMySQL() (bool, string) {
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

	exist := false
	count := 0
	for Txt.Next() {
		Txt.Scan(&TxtInString)
		exist = true
		count++
	}
	defer Txt.Close()

	if count > 1 {
		panic(fmt.Sprint("getTxtFromMySQL: should not have so many txt recs,", count))
	}

	return exist, TxtInString

}

var localDnsARecord []utils.DnsRecord
var localDnsARecordVarLock = sync.Mutex{}

// Note that txtRec is a pointer to a struct
//  it is nill if no prior records are found in MySQL
var pLocalTxtRec *utils.DnsRecord
var localTxtRecVarLock = sync.Mutex{}

// Note that batchUpdate() will create another goroutine,
//  which is responsible for updating local information
func (pf *PfsenseProvider) batchUpdate() {
	go func() {
		shouldApplyVarLock.Lock()

		// TODO: check if changes have been made from the main goroutine,
		//       thus avoiding unnecessary connections

		if shouldApply {
			shouldApply = false
			shouldApplyVarLock.Unlock()

			// perform getConfig, deltaChange (including additions
			//  and deletions), postConfig, applyConfig, updateMySQL.
			//  then sleep 5 secs waiting for the dnsmasq to restart

			// STEP 1. GET the latest config.xml from pfSense in JSON format
			conf := pf.getConfig()
			confDnsmasq := conf["dnsmasq"].(map[string]interface{})
			confDnsmasqHosts := confDnsmasq["hosts"].([]interface{})
			var hostlist []jsonDnsmasqHostEntry
			for _, dnsmasqEnt := range confDnsmasqHosts {
				curEnt := dnsmasqEnt.(map[string]interface{})
				hostlist = append(hostlist, jsonDnsmasqHostEntry{
					aliases: "",
					descr:   "a Rancher/external-dns autogenerated record",
					domain:  curEnt["domain"].(string),
					host:    curEnt["host"].(string),
					ip:      curEnt["ip"].(string),
				})
			}

			// STEP 2. perform deletions of DNS records (with translation according to the whitelist)
			var newHostlist []jsonDnsmasqHostEntry

			for _, jRec := range hostlist {

				// perform translation
				foundInWhiteList, Urec := transAJrecToUrec(jRec)

				if !foundInWhiteList {
					panic(fmt.Sprint("deletion:", jRec, " should have be in whitelist"))
				}

				// perform possible deletion
				shouldRemove := false
				recordsToRemoveVarLock.Lock()
				for _, remRec := range recordsToRemove {
					if remRec.Fqdn == Urec.Fqdn {
						shouldRemove = true
						break
					}
				}
				recordsToRemoveVarLock.Unlock()

				if shouldRemove {
					// just leave it
				} else {
					newHostlist = append(newHostlist, jRec)
				}

			}

			hostlist = newHostlist
			newHostlist = []jsonDnsmasqHostEntry{}

			// STEP 3. perform additions of Type-A DNS records (with translation according to the whitelist)

			recordsToAddVarLock.Lock()
			for _, addRec := range recordsToAdd {
				// should we check duplicates?
				//  if there exists a duplicate , do not add it this time.
				//  consider a scenario: the main goroutine wait at the lock located
				//  in AddRecord(). When the lock here is released, duplicate add
				//  requests are made.
				foundInWhiteList, addJrec := transUrecToAJrec(addRec)
				if !foundInWhiteList {
					panic(fmt.Sprint("add record:", addRec, " should have been in whitelist"))
				}

				foundDuplicate := false
				for _, hostListRec := range hostlist {
					if hostListRec.domain == addJrec.domain && hostListRec.host == addJrec.host {
						foundDuplicate = true
						break
					}
				}

				if foundDuplicate {
					continue
				} else {
					hostlist = append(hostlist, addJrec)
				}

			}
			recordsToAddVarLock.Unlock()

			// STEP 4. post the whole conf to pfSense

			var hostlistToSend []interface{}
			for _, jrec := range hostlist {
				hostlistToSend = append(hostlistToSend, map[string]interface{}{
					"aliases": "",
					"descr":   "a Rancher/external-dns autogenerated record",
					"domain":  jrec.domain,
					"host":    jrec.host,
					"ip":      jrec.ip,
				})
			}

			confDnsmasqHosts = hostlistToSend
			confDnsmasq["hosts"] = confDnsmasqHosts
			conf["dnsmasq"] = confDnsmasq

			pf.postConfig(conf)

			// STEP 5. update local TXT record & update its MySQL backup
			// TODO: check locks; clear change records; clear change flag; set change flag

			localTxtRecVarLock.Lock()
			*pLocalTxtRec = txtRecToUpdate
			localTxtRecVarLock.Unlock()

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

			localTxtRecVarLock.Lock()
			var txtInJson = map[string]interface{}{
				"Fqdn":    pLocalTxtRec.Fqdn,
				"Records": pLocalTxtRec.Records,
				"Type":    pLocalTxtRec.Type,
				"TTL":     pLocalTxtRec.TTL,
			}
			localTxtRecVarLock.Unlock()
			var txtJsonInBytes, _ = json.Marshal(txtInJson)

			db.Exec("delete from TxtRec")
			db.Exec("insert into TxtRec (Txt) value (?)", string(txtJsonInBytes))

			// STEP 6. update the local version of the conf, TXT record
			// TODO: Check locks!!!
			localDnsARecordVarLock.Lock()
			localDnsARecord = []utils.DnsRecord{}
			for _, jrec := range hostlist {
				foundInWhiteList, urec := transAJrecToUrec(jrec)
				if foundInWhiteList {
					localDnsARecord = append(localDnsARecord, urec)
				} else {
					// just leave it
				}
			}
			localDnsARecordVarLock.Unlock()

			// STEP 7. apply the changes made to dnsmasq, which would
			//          break down the DNS for a short interval

			pf.applyChanges()

			// STEP 8. wait for dnsmasq to restart
			time.Sleep(5 * time.Second)
		}
	}()
}

func transAJrecToUrec(Jrec jsonDnsmasqHostEntry) (bool, utils.DnsRecord) {
	var foundInWhiteList = false
	var Drec utils.DnsRecord
	for _, whiteEnt := range whiteList {
		if whiteEnt.host == Jrec.host && whiteEnt.domain == Jrec.domain {
			foundInWhiteList = true
			Drec.Fqdn = whiteEnt.Fqdn
			Drec.Records = []string{Jrec.ip}
			Drec.TTL = 150
			Drec.Type = "A"
			break
		}
	}
	return foundInWhiteList, Drec
}

func transUrecToAJrec(Urec utils.DnsRecord) (bool, jsonDnsmasqHostEntry) {
	var foundInWhiteList = false
	var Jrec jsonDnsmasqHostEntry
	for _, whiteEnt := range whiteList {
		if whiteEnt.Fqdn == Urec.Fqdn {
			foundInWhiteList = true
			Jrec.descr = "a Rancher/external-dns autogenerated record"
			Jrec.domain = whiteEnt.domain
			Jrec.ip = Urec.Records[0]
			break
		}
	}
	return foundInWhiteList, Jrec
}

type jsonDnsmasqHostEntry struct {
	aliases string
	descr   string
	domain  string
	host    string
	ip      string
}

var shouldApplyVarLock = sync.Mutex{}
var shouldApply = false

// GetName will be called by external-dns.go
func (pf *PfsenseProvider) GetName() string {
	fmt.Println("***** GetName() called and ends *****")
	return "Pfsense"
}

// HealthCheck will be called in a goroutine created by main.go
//  to perform satinization in the orginal setting.
//  However, it is of no use here.
func (pf *PfsenseProvider) HealthCheck() error {
	return nil
}

// generate auth for pfSense FauxAPI
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

// return the configuration file from pfSense (the config.xml)
//  in JSON format
func (pf *PfsenseProvider) getConfig() map[string]interface{} {

	authVal := pf.generateAuth()
	actionmutex.Lock()
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
	actionmutex.Unlock()
	var configDat map[string]interface{}

	if err = json.Unmarshal(config, &configDat); err != nil {
		fmt.Println(err)
		panic("json parse errs")

	}
	lst := configDat["data"].(map[string]interface{})["config"].(map[string]interface{})
	return lst
}

// post a new configuration file to pfSense
func (pf *PfsenseProvider) postConfig(conf map[string]interface{}) error {
	actionmutex.Lock()
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
	actionmutex.Unlock()
	varmutex.Lock()
	changed = true
	varmutex.Unlock()
	defer resp.Body.Close()
	return nil
}

// apply changes to dnsmasq. However, it is not safe to do so
//  since the first function call actually tries to kill and
//  restart the dnsmasq service, which might lead to the
//  following function calls to panic() when they fails to resolve
//  the hostname `pfsense`
func (pf *PfsenseProvider) applyChanges() {
	pf.functionCall("services_dnsmasq_configure")
	pf.functionCall("filter_configure")
	pf.functionCall("system_resolvconf_generate")
	pf.functionCall("system_dhcpleases_configure")
}

func (pf *PfsenseProvider) functionCall(f string) {

	// mutex should not be put here

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

func (pf *PfsenseProvider) AddRecord(record utils.DnsRecord) error {

	// TODO: filter according to whitelist
	fmt.Println("***** AddRecord() called *****")
	fmt.Println("utils.dnsRecord:", record)
	if record.Type == "A" {
		shouldApplyVarLock.Lock()
		shouldApply = true
		shouldApplyVarLock.Unlock()

		recordsToAddVarLock.Lock()
		// should remove duplicates?
		var newRecordsToAdd = []utils.DnsRecord{record}
		for _, rec := range recordsToAdd {
			if rec.Fqdn == record.Fqdn {
				continue
			} else {
				newRecordsToAdd = append(newRecordsToAdd, rec)
			}
		}
		recordsToAdd = newRecordsToAdd
		recordsToAddVarLock.Unlock()
	} else if record.Type == "TXT" {
		shouldApplyVarLock.Lock()
		shouldApply = true
		shouldApplyVarLock.Unlock()

		txtRecToUpdateVarLock.Lock()
		txtRecToUpdate = record
		txtRecToUpdateVarLock.Unlock()
	} else {
		fmt.Println("AddRecord: neither-A-nor-TXT record found")
	}
	fmt.Println("*****AddRecord() ends *****")
	return nil
}

var recordsToAdd []utils.DnsRecord
var recordsToAddVarLock = sync.Mutex{}
var txtRecToUpdate utils.DnsRecord
var txtRecToUpdateVarLock = sync.Mutex{}

func (pf *PfsenseProvider) UpdateRecord(record utils.DnsRecord) error {
	fmt.Println("***** Update() called *****")
	fmt.Println("utils.dnsRecord:", record)

	pf.RemoveRecord(record)

	pf.AddRecord(record)

	fmt.Println("***** Update() ends *****")
	return nil
}

func (pf *PfsenseProvider) RemoveRecord(record utils.DnsRecord) error {
	fmt.Println("***** RemoveRecord() called *****")
	// TODO: filter according to the whitelist
	fmt.Println("utils.dnsRecord:", record)

	if record.Type == "TXT" {
		fmt.Println("RemoveRecord: TXT record found")
		return nil
	} else if record.Type != "A" {
		fmt.Println("RemoveRecord: non-A record found")
		return nil
	}

	shouldApplyVarLock.Lock()
	shouldApply = true
	shouldApplyVarLock.Unlock()

	recordsToRemoveVarLock.Lock()
	// remove duplicates
	var newRecordsToRemove = []utils.DnsRecord{record}
	for _, rec := range recordsToRemove {
		if rec.Fqdn == record.Fqdn {
			continue
		} else {
			newRecordsToRemove = append(newRecordsToRemove, rec)
		}
	}
	recordsToRemove = newRecordsToRemove
	recordsToRemoveVarLock.Unlock()

	fmt.Println("*****RemoveRecord() ends******")

	return nil
}

var recordsToRemove []utils.DnsRecord
var recordsToRemoveVarLock = sync.Mutex{}

func (pf *PfsenseProvider) GetRecords() ([]utils.DnsRecord, error) {
	fmt.Println("***** GetRecords() called *****")

	localDnsARecordVarLock.Lock()
	var retRecords = make([]utils.DnsRecord, len(localDnsARecord), len(localDnsARecord)+1)
	copy(retRecords, localDnsARecord)
	localDnsARecordVarLock.Unlock()

	localTxtRecVarLock.Lock()
	retRecords = append(retRecords, *pLocalTxtRec)
	localTxtRecVarLock.Unlock()

	fmt.Println("***** GetRecords() ends *****")
	return retRecords, nil
}
