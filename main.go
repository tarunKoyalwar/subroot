package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

type results struct {
	CN      string `json:"common_name"`
	OrgName string `json:"name_value"`
}

var OrgNames goflags.StringSlice
var DomainLevel int

func main() {
	flagset := goflags.NewFlagSet()
	flagset.SetDescription("subroot is tool to find root domains from crt.sh using Organization names")
	flagset.StringSliceVarP(&OrgNames, "org-names", "on", []string{}, "Org name to use", goflags.CommaSeparatedStringSliceOptions)
	flagset.IntVarP(&DomainLevel, "root-level", "rl", 2, "Root level of domain (ex: 2 means *.domain.com)")

	if err := flagset.Parse(); err != nil {
		gologger.Fatal().Msgf("failed to parse flags %v", err)
	}

	if len(OrgNames) == 0 {
		gologger.Fatal().Msg("Org name is required but not given")
	}

	rootDomains := map[string]struct{}{}

	for _, v := range OrgNames {
		res, err := FetchSubs(v)
		if err != nil {
			gologger.Fatal().Msgf("failed to get repsonse from crt.sh got %v", err)
		}
		for _, r := range res {
			rval := strings.TrimSpace(r.OrgName)
			rval = strings.TrimRight(rval, ".") // remove . if any
			if v == rval {
				parts := strings.Split(r.CN, ".")
				count := len(parts)
				if count >= DomainLevel {
					rootName := strings.Join(parts[count-DomainLevel:], ".")
					rootDomains[rootName] = struct{}{}
				}
			}
		}
	}

	for k := range rootDomains {
		fmt.Println(k)
	}
}

func FetchSubs(orgname string) ([]results, error) {
	orgname = strings.TrimSpace(orgname)
	orgname = strings.ReplaceAll(orgname, " ", "+")
	var res []results
	resp, err := http.Get(fmt.Sprintf("https://crt.sh/?q=%v&output=json", orgname))
	if err != nil {
		return res, err
	}
	bin, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(bin, &res)
	return res, err
}
