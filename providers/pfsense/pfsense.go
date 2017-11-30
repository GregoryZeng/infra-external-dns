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

// var varmutex = &sync.Mutex{}
// var actionmutex = &sync.Mutex{}
// var changed = false

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

	for pf.ifDnsmasqFails() {
		// if dnsmasq fails, the program would panic and restart
		// then these few lines of code will work
		// ugly workaround but got no better choices now
		pf.apiSecret = pf.readStrFromZK("10.130.9.15", "/pfsense-external-dns/bj/configuration/PFSENSE_APISECRET")
		pf.apiKey = pf.readStrFromZK("10.130.9.15", "/pfsense-external-dns/bj/configuration/PFSENSE_APIKEY")
		pf.applyChanges()
		fmt.Println("Init ifDnsmasqFails: now try to restart dnsmasq...")
		time.Sleep(5 * time.Second)
	}

	pf.apiSecret = pf.readStrFromZK("zk", "/pfsense-external-dns/bj/configuration/PFSENSE_APISECRET")
	pf.apiKey = pf.readStrFromZK("zk", "/pfsense-external-dns/bj/configuration/PFSENSE_APIKEY")
	pf.dbOpenParam = pf.readStrFromZK("zk", "/pfsense-external-dns/bj/configuration/MYSQL_OPENPARAM")

	var err error
	db, err = sql.Open("mysql", pf.dbOpenParam)
	if err != nil {
		fmt.Println("db open errs")
		panic(err)
	}

	pf.getWhiteList()
	pf.initLocalARecord()
	pf.initLocalTxt()

	pf.batchUpdate()
	forceRoutineBatchUpdate()

	fmt.Println("***** Init() ends ******")
	return nil
}

func forceRoutineBatchUpdate() {
	go func() {
		for {
			shouldApplyVarLock.Lock()
			shouldApply = true
			shouldApplyVarLock.Unlock()
			time.Sleep(5 * time.Minute)
		}
	}()
}

func (pf *PfsenseProvider) readStrFromZK(zkpath string, path string) string {
	fmt.Println("***** readStrFromZK() called *****")
	c, _, err := zk.Connect([]string{zkpath}, 10*time.Second)
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
	children, _, _, err := c.ChildrenW("/pfsense-external-dns/bj/whitelist")
	if err != nil {
		fmt.Println("children fetch fails")
		panic(err)
	}
	whiteList = []whitelistEntry{}
	for _, key := range children {
		recv, _, _ := c.Get("/pfsense-external-dns/bj/whitelist/" + key)
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
		var subRecords []string
		for _, ip := range Ips {
			subRecords = append(subRecords, ip.(string))
		}

		localDnsARecordVarLock.Lock()
		pLocalTxtRec = new(utils.DnsRecord)
		*pLocalTxtRec = utils.DnsRecord{
			Fqdn:    TxtJson["Fqdn"].(string),
			Records: subRecords,
			Type:    "TXT",
			TTL:     140,
		}
		localDnsARecordVarLock.Unlock()

	} else {
		fmt.Println("initLocalTxt: no recs")
	}

}

func (pf *PfsenseProvider) getTxtFromMySQL() (bool, string) {
	// db, err := sql.Open("mysql", pf.dbOpenParam)
	// if err != nil {
	// 	fmt.Println("db open errs")
	// 	panic(err)
	// }
	// defer db.Close()

	err := db.Ping()
	if err != nil {
		fmt.Println("db ping err")
		panic(err)
	}

	Txt, err := db.Query("select Txt from TxtRec")
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
// PROBLEM: if a user edits the dnsmasq table, the external-dns service will not be notified
func (pf *PfsenseProvider) batchUpdate() {
	go func() {
		for {
			// check if changes have been made from the main goroutine,
			//  thus avoiding unnecessary connections
			shouldApplyVarLock.Lock()
			tmp := shouldApply
			shouldApply = false
			shouldApplyVarLock.Unlock()
			if tmp {
				fmt.Println("***** batchUpdate called *****")

				// perform all sorts of updates that involves connections,
				//  then sleep 5 secs waiting for the dnsmasq to restart

				// STEP 1. GET the latest config.xml from pfSense in JSON format
				conf := pf.getConfig()
				confDnsmasq := conf["dnsmasq"].(map[string]interface{})
				confDnsmasqHosts := confDnsmasq["hosts"].([]interface{})
				var jhostlist []jsonDnsmasqHostEntry
				for ind, dnsmasqEnt := range confDnsmasqHosts {
					curEnt := dnsmasqEnt.(map[string]interface{})
					fmt.Println("step1 iter ", ind, curEnt)

					possibleEmptyAlias, isEmptyAlias := curEnt["aliases"].(string)
					if isEmptyAlias {
						jhostlist = append(jhostlist, jsonDnsmasqHostEntry{
							aliases: possibleEmptyAlias,
							descr:   curEnt["descr"].(string),
							domain:  curEnt["domain"].(string),
							host:    curEnt["host"].(string),
							ip:      curEnt["ip"].(string),
						})
					} else {
						jhostlist = append(jhostlist, jsonDnsmasqHostEntry{
							aliases: curEnt["aliases"].(map[string]interface{}),
							descr:   curEnt["descr"].(string),
							domain:  curEnt["domain"].(string),
							host:    curEnt["host"].(string),
							ip:      curEnt["ip"].(string),
						})
					}
				}

				fmt.Println("afer step1 jhostlist:", jhostlist)

				// STEP 2. perform additions of Type-A DNS records (with translation according to the whitelist)

				recordsToAddVarLock.Lock()
				fmt.Println("step2 addlst:", recordsToAdd)
				fmt.Println("recordstoadd:", recordsToAdd)
				for _, addURec := range recordsToAdd {

					foundInWhiteList, addJrec := transUrecToAJrec(addURec)
					if !foundInWhiteList {
						panic(fmt.Sprint("add record:", addURec, " not in whitelist"))
					}

					// check duplicates
					foundDuplicate := false
					for _, jhostListRec := range jhostlist {
						if jhostListRec.domain == addJrec.domain && jhostListRec.host == addJrec.host {
							foundDuplicate = true
							break
						}
					}

					if foundDuplicate {
						continue
					} else {
						jhostlist = append(jhostlist, addJrec)
					}

				}
				recordsToAdd = []utils.DnsRecord{}
				recordsToAddVarLock.Unlock()

				fmt.Println("after step2 jhostlist:", jhostlist)

				// STEP 3. perform deletions of DNS records (with translation according to the whitelist)
				// 		    then clear local remove queue
				var newjHostlist []jsonDnsmasqHostEntry

				recordsToRemoveVarLock.Lock()
				fmt.Println("step3 remList:", recordsToRemove)
				for _, jRec := range jhostlist {

					// perform possible deletion
					shouldRemove := false

					for ind, remURec := range recordsToRemove {
						foundInWhiteList, remJRec := transUrecToAJrec(remURec)
						fmt.Println("step2: iter", ind, foundInWhiteList, remJRec)
						if !foundInWhiteList {
							panic(fmt.Sprint("remove: ", remURec, "should not be in remlist"))
						}
						if remJRec.domain == jRec.domain && remJRec.host == jRec.host {
							shouldRemove = true
							break
						}
					}

					if shouldRemove {
						// just leave it
						fmt.Println("step2:", jRec, "should be removed")
					} else {
						newjHostlist = append(newjHostlist, jRec)
					}
				}
				// now clear out the remove queue
				recordsToRemove = []utils.DnsRecord{}
				recordsToRemoveVarLock.Unlock()

				// now some entries in jhostlist is removed
				jhostlist = newjHostlist
				newjHostlist = []jsonDnsmasqHostEntry{}

				fmt.Println("after step3 jhostlist", jhostlist)

				// STEP 4. post the whole conf to pfSense

				var jhostlistToSend []interface{}
				for _, jrec := range jhostlist {
					jhostlistToSend = append(jhostlistToSend, map[string]interface{}{
						"aliases": jrec.aliases,
						"descr":   jrec.descr,
						"domain":  jrec.domain,
						"host":    jrec.host,
						"ip":      jrec.ip,
					})
				}

				confDnsmasqHosts = jhostlistToSend
				confDnsmasq["hosts"] = confDnsmasqHosts
				conf["dnsmasq"] = confDnsmasq

				pf.postConfig(conf)

				fmt.Println("after step4: post remote conf")

				// STEP 5. update local TXT record & update its MySQL backup

				// update local
				var localTxtToUpdateCopy *utils.DnsRecord

				// copy txtRecToUpdate to localTxtToUpdateCopy
				txtRecToUpdateVarLock.Lock()
				if txtRecToUpdate != nil {
					localTxtToUpdateCopy = new(utils.DnsRecord)
					*localTxtToUpdateCopy = *txtRecToUpdate
					txtRecToUpdate = nil
				}
				txtRecToUpdateVarLock.Unlock()

				// TODO: modify localTxtToUpdateCopy to remove redundant entries
				if localTxtToUpdateCopy != nil {
					var newTxtHostList []string
					for _, fqdn := range localTxtToUpdateCopy.Records {
						found := false
						// search in the jhostlist
						for _, jrec := range jhostlist {
							f, urec := transAJrecToUrec(jrec)
							if !f {
								fmt.Println(jrec, "ignored")
								continue
							}
							if urec.Fqdn == fqdn {
								found = true
								break
							}
						}
						if found {
							newTxtHostList = append(newTxtHostList, fqdn)
						} else {
							// leave it
						}
					}
					localTxtToUpdateCopy.Records = newTxtHostList
				}

				// copy localTxtToUpdateCopy to pLocalTxtRec
				localTxtRecVarLock.Lock()
				if localTxtToUpdateCopy != nil {
					// if exists updates to the TXT rec
					if pLocalTxtRec == nil {
						pLocalTxtRec = new(utils.DnsRecord)
					}
					*pLocalTxtRec = *localTxtToUpdateCopy
				}
				localTxtRecVarLock.Unlock()

				// update mysql

				if localTxtToUpdateCopy != nil {

					err := db.Ping()
					if err != nil {
						fmt.Println("db ping err")
						panic(err)
					}

					var txtInJson = map[string]interface{}{
						"Fqdn":    localTxtToUpdateCopy.Fqdn,
						"Records": localTxtToUpdateCopy.Records,
						"Type":    localTxtToUpdateCopy.Type,
						"TTL":     localTxtToUpdateCopy.TTL,
					}

					var txtJsonInBytes, _ = json.Marshal(txtInJson)

					// TODO: replace 2 SQL commands with only 1
					// ("delete from TxtRec")db.Exec
					// db.Exec("insert into TxtRec (Txt) value (?)", string(txtJsonInBytes))
					db.Exec("insert into TxtRec (Dummy,Txt) values (1,(?)) on duplicate key update Dummy = 1, Txt = (?)", string(txtJsonInBytes), string(txtJsonInBytes))

				}

				fmt.Println("after step5: update remote and local txt rec")

				// STEP 6. update the local version of the conf
				// TODO: Check locks
				localDnsARecordVarLock.Lock()
				localDnsARecord = []utils.DnsRecord{}
				for _, jrec := range jhostlist {
					foundInWhiteList, urec := transAJrecToUrec(jrec)
					if foundInWhiteList {
						localDnsARecord = append(localDnsARecord, urec)
					} else {
						// just leave it
					}
				}
				localDnsARecordVarLock.Unlock()

				fmt.Println("after step6: update local conf")

				// STEP 7. apply the changes made to dnsmasq, which would
				//          break down the DNS for a short interval

				pf.applyChanges()

				// STEP 8. wait for dnsmasq to restart
				fmt.Println("***** batchUpdate ends *****")
				time.Sleep(5 * time.Second)
			} else {

			}

		}
	}()
}

var db *sql.DB

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
			Jrec.host = whiteEnt.host

			aliasHost, aliasDomain := fqdnToHostDomain(whiteEnt.Fqdn)

			Jrec.aliases = map[string]interface{}{
				"item": []interface{}{
					map[string]interface{}{
						"description": "<service>.<stack>.<environment>.<domain>",
						"domain":      aliasDomain,
						"host":        aliasHost,
					},
				},
			}
			break
		}
	}
	return foundInWhiteList, Jrec
}

func fqdnToHostDomain(fqdn string) (string, string) {
	unfqdn := utils.UnFqdn(fqdn)
	ind1 := strings.IndexRune(unfqdn, '.')

	return unfqdn[:ind1], unfqdn[ind1+1:]
}

type jsonDnsmasqHostEntry struct {
	aliases interface{} // could be string or map[string]interface{}
	descr   string
	domain  string
	host    string
	ip      string
}

var shouldApplyVarLock = sync.Mutex{}
var shouldApply = true

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

// it is an easy way to check if DNS is healthy or not
func (pf *PfsenseProvider) ifDnsmasqFails() bool {

	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://pfsense/", nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("ifDnsmasqFails: cannot connect")
		return true
	}
	defer resp.Body.Close()
	return false
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
	// actionmutex.Lock()
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
	// actionmutex.Unlock()
	var configDat map[string]interface{}

	if err = json.Unmarshal(config, &configDat); err != nil {
		fmt.Println(err)
		panic("json parse errs")

	}
	lst := configDat["data"].(map[string]interface{})["config"].(map[string]interface{})
	return lst
}

// post a new configuration file (in whole) to pfSense
func (pf *PfsenseProvider) postConfig(conf map[string]interface{}) error {
	// actionmutex.Lock()
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
	// actionmutex.Unlock()
	// varmutex.Lock()
	// changed = true
	// varmutex.Unlock()
	defer resp.Body.Close()
	return nil
}

// apply changes to dnsmasq. However, it is not safe to do so
//  since the first function call actually tries to kill and
//  restart the dnsmasq service, which might lead to the
//  following function calls to panic() when they fails to resolve
//  the hostname `pfsense`
func (pf *PfsenseProvider) applyChanges() {
	pf.sendEvent("interface all reload")
	//pf.functionCall("services_dnsmasq_configure")
	// pf.functionCall("filter_configure")
	// pf.functionCall("system_resolvconf_generate")
	// pf.functionCall("system_dhcpleases_configure")
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
		"http://10.130.1.1/fauxapi/v1/?action=function_call&__debug=True",
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

func (pf *PfsenseProvider) sendEvent(event string) {

	// mutex should not be put here

	client := &http.Client{}

	conf := []string{event}

	configBytes, err := json.Marshal(conf)
	if err != nil {
		fmt.Println("json encoding fails")
		panic(err)
	}

	req, err := http.NewRequest("POST",
		"http://10.130.1.1/fauxapi/v1/?action=send_event&__debug=True",
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

func urecInWhitelist(record utils.DnsRecord) (bool, *whitelistEntry) {
	for _, wrec := range whiteList {
		if wrec.Fqdn == record.Fqdn {
			return true, &wrec
		}
	}
	return false, nil
}

func (pf *PfsenseProvider) AddRecord(record utils.DnsRecord) error {

	fmt.Println("***** AddRecord() called *****")
	fmt.Println("utils.dnsRecord:", record)
	if record.Type == "A" {

		// whether in whitelist
		found, _ := urecInWhitelist(record)
		if !found {
			fmt.Println("AddRecord():", record, " not found in whitelist")
			return nil
		}

		shouldApplyVarLock.Lock()
		shouldApply = true
		fmt.Println("AddRecord A: I true the shouldApply")
		shouldApplyVarLock.Unlock()

		// remove duplicates in queue
		recordsToAddVarLock.Lock()
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
		fmt.Println("AddRecord TXT: I true the shouldApply")
		shouldApplyVarLock.Unlock()

		txtRecToUpdateVarLock.Lock()
		if txtRecToUpdate == nil {
			txtRecToUpdate = new(utils.DnsRecord)
		}
		*txtRecToUpdate = record
		txtRecToUpdateVarLock.Unlock()
	} else {
		fmt.Println("AddRecord: neither-A-nor-TXT record found")
	}
	fmt.Println("*****AddRecord() ends *****")
	return nil
}

var recordsToAdd []utils.DnsRecord
var recordsToAddVarLock = sync.Mutex{}
var txtRecToUpdate *utils.DnsRecord
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

	fmt.Println("utils.dnsRecord:", record)

	if record.Type == "TXT" {
		fmt.Println("RemoveRecord: TXT record found")
		return nil
	} else if record.Type != "A" {
		fmt.Println("RemoveRecord: non-A record found")
		return nil
	}

	// whether in whitelist
	found, _ := urecInWhitelist(record)
	if !found {
		fmt.Println("***** RemoveRecord:", record, "not found in whitelist *****")
		return nil
	}

	shouldApplyVarLock.Lock()
	shouldApply = true
	fmt.Println("RemoveRecord: I true the shouldApply")
	shouldApplyVarLock.Unlock()

	// remove duplicates
	recordsToRemoveVarLock.Lock()
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

	// Add Type A records
	localDnsARecordVarLock.Lock()
	var retRecords = make([]utils.DnsRecord, len(localDnsARecord), len(localDnsARecord)+1)
	count := copy(retRecords, localDnsARecord)
	if count != len(localDnsARecord) {
		panic(fmt.Sprint("GetRecords: copy", count, "elements!"))
	}
	fmt.Println("getrecord(): localDnsARecord", localDnsARecord)
	localDnsARecordVarLock.Unlock()

	// Add Type TXT record
	localTxtRecVarLock.Lock()
	if pLocalTxtRec == nil {
		// just leave it

	} else {
		retRecords = append(retRecords, *pLocalTxtRec)
		fmt.Println("getrecord(): txtrecord", *pLocalTxtRec)
	}

	localTxtRecVarLock.Unlock()

	fmt.Println("***** GetRecords() ends *****")
	return retRecords, nil
}
