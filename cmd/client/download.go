package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/codegangsta/cli"

	"github.com/endophage/go-tuf"
	"github.com/endophage/go-tuf/client"
	"github.com/endophage/go-tuf/data"
	"github.com/endophage/go-tuf/keys"
	"github.com/endophage/go-tuf/roles"
	"github.com/endophage/go-tuf/store"
)

var commandDownload = cli.Command{
	Name:   "download",
	Usage:  "provide the path to a target you wish to download.",
	Action: download,
}

func download(ctx *cli.Context) {
	if len(ctx.Args()) < 1 {
		fmt.Println("At least one package must be provided.")
		return
	}
	pypiRoot := `{
	  "_type": "Root", 
	  "expires": "2014-08-31 00:49:33 UTC", 
	  "keys": {
	   "07f12f6c470e60d49fe6a60cd893dfba870db387083d50fe4fc43c6171a0be59": {
		"keytype": "rsa", 
		"keyval": {
		 "private": "", 
		 "public": "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAtb4vuMJF1kOc1deExdqV\nZ3o9W6zulfRDX6u8Exd3NEL0/9bCYluqpshFzgmDYpCsuS79Ve5S8WgXAnEXyWOf\nHL/FnAVqFSnmgmYr52waMYV57BsNMY8pXxOnJm1opUbt0PdnF2D2yfLLY8IgZ/0m\niJ+gWojwEBMRlTOnHFx+l/UVvZAhpVsua6C8C2ThFLrXlmmtkg5BAIm1kWPsZ0nB\n3Cczcwh8zE0l2ytVi458AuRGKwi1TMIGXl064ekjsWexH1zCuoEcv/CKob0BkL4c\nLFUKe6WD6XlEp/xnMh6lNG8LT+UKzSb1hPkTtt23RntFB4Qx7UUT8LoO79bv6coE\njeEqHltmeohHpVmTLWsbTdaX7W3clWPUErGh5kAO0SJu1EM94p5nGWlZ+kwASxtO\nz1qR8AqQ02HBBQU+cY24CNnOwKDq/Kgsg1Aw7bqglvtUwBUQkuuCuisjHI0bSMFr\ntGIhlswxItfQ709/OMrN44Vw/H/Z50UzGFtRlu1h07/vAgMBAAE=\n-----END PUBLIC KEY-----"
		}
	   }, 
	   "2d9f41a1b79429e9d950a687fe00da0bb4fd751da98aeade1524b8d28968eb89": {
		"keytype": "rsa", 
		"keyval": {
		 "private": "", 
		 "public": "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAmjt8CIbohZxZQ1+I8CQn\nvugLsGXq1G2OiMZvbN281q1/E1futll3+EnfxPLP0SBlyYxixma/ozoMj94lPyOX\nBbiF/U1WJ0Wp5D1kpT0Jzt9Ar0bkRxWoPhubeJ7D4k8Br2m7aG+wchfozdbMmUwK\n/MiAZ1fmpKQAr1ek3/hJiN/dURw+mQEdgXwgA4raDy4Ty3AkG7SDCG1cYoYYMJa3\nKg82AWISQQEHUO1MwRVBon2B5d2UriUEzsYYi+2whDOekchjgyd2xdcRvdCBbdGv\nJBCtzVZpd52lCwqAMJUyDGre6Mb6NmKC2nuk+TYEujqRQK97LnjmPwI42b4cBHqv\nDtg7Z8K3rEQIyD+VvrcWlu+1cE8drjh3y+r7oTtjRPr1M8xaCWn/dh8huSJmaFlk\nmWKDX9KI3/5pxFjgpry20eBRYkZHJWwByc9GVvwhRsIF61QdKvA6uGqkFHy9YQBW\nnzWTPo/4UTUwcpfjneoyMOVKx2K05ZePa5UNAgJVDgFfAgMBAAE=\n-----END PUBLIC KEY-----"
		}
	   }, 
	   "92db731bf30e31c13e775360453f0adc8bfd3107f5000b99431c4bdbcebb31ed": {
		"keytype": "rsa", 
		"keyval": {
		 "private": "", 
		 "public": "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEArvqUPYb6JJROPJQglPTj\n5uDrsxQKl34Mo+3pSlBVuD6puE4lDnG649a2YksJy+C8ZIPJgokn5w+C3alh+dMe\nzbdWHHxrY1h9CLpYz5cbMlE16303ubkt1rvwDqEezG0HDBzPaKj4oP9YJ9x7wbsq\ndvFcy+Qc3wWd7UWcieo6E0ihbJkYcY8chRXVLg1rL7EfZ+e3bq5+ojA2ECM5JqzZ\nzgDpqCv5hTCYYZp72MZcG7dfSPAHrcSGIrwg7whzz2UsEtCOpsJTuCl96FPN7kAu\n4w/WyM3+SPzzr4/RQXuY1SrLCFD8ebM2zHt/3ATLhPnGmyG5I0RGYoegFaZ2AViw\nlqZDOYnBtgDvKP0zakMtFMbkh2XuNBUBO7Sjs0YcZMjLkh9gYUHL1yWS3Aqus1Lw\nlI0gHS22oyGObVBWkZEgk/Foy08sECLGao+5VvhmGpfVuiz9OKFUmtPVjWzRE4ng\niekEu4drSxpH41inLGSvdByDWLpcTvWQI9nkgclh3AT/AgMBAAE=\n-----END PUBLIC KEY-----"
		}
	   }, 
	   "e1ccde549849bb6aa548412e79c407c93f303f3a3ca0ab1e5923ff7d5c4de769": {
		"keytype": "rsa", 
		"keyval": {
		 "private": "", 
		 "public": "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAqnNAzjIb73u2Nk+r2AdU\nnK+xvKDcZgIzjSzRVjtRJgu3MVffzPcGIsjv2RS8/LLl8nSf48V+tWZf/PnTzkMn\n1iJhbdOQTt6bABiizm5dLP9Jm/AIMTTUpbu+fpFbV8vNH+qM5/Z0WNOptQnOEfNs\n84MNh919lJjHc5VPTw86h68Mkn7W5RChZqnwEv75M1XfWdAnUGeLfZh6BKxFMnaB\nciYxieUvc1bnCtqsdaDE2Ab86WXM7cmNCqyLAh4JkTV+RcMzqEnZCAm68TkO6gM/\n5g4A7fbnn9Jc4O3fJvu80fYOg63nS6hAFldmN74oYu2h5PV75xyTIEERoXqJbSaj\n1Agj/98khIZGsSVjoQ5Mi7ETcSbsH7rqWdHFIu+dbKw8vlnqWnEQYjXA8CIOY3X7\nB6/u5FBS5AdxjO6AR/MuaqpWdDTZwXwgZ9c4wqO4Re4z73sGM1PugUK4dbXIGwVe\nRtzv7cSFOB7OPmj53miJWt2ILACb+Dpnxt9h6TzT1C0JAgMBAAE=\n-----END PUBLIC KEY-----"
		}
	   }
	  }, 
	  "roles": {
	   "release": {
		"keyids": [
		 "e1ccde549849bb6aa548412e79c407c93f303f3a3ca0ab1e5923ff7d5c4de769"
		], 
		"threshold": 1
	   }, 
	   "root": {
		"keyids": [
		 "92db731bf30e31c13e775360453f0adc8bfd3107f5000b99431c4bdbcebb31ed"
		], 
		"threshold": 1
	   }, 
	   "targets": {
		"keyids": [
		 "07f12f6c470e60d49fe6a60cd893dfba870db387083d50fe4fc43c6171a0be59"
		], 
		"threshold": 1
	   }, 
	   "timestamp": {
		"keyids": [
		 "2d9f41a1b79429e9d950a687fe00da0bb4fd751da98aeade1524b8d28968eb89"
		], 
		"threshold": 1
	   }
	  }, 
	  "version": 1
	}`

	data.SetTUFTypes(
		map[string]string{
			"snapshot": "release",
		},
	)
	roles.SetValidRoles(
		map[string]string{
			"snapshot": "release",
		},
	)

	r := &data.Root{}
	err := json.Unmarshal([]byte(pypiRoot), r)
	if err != nil {
		fmt.Println("Could not read initial root.json")
		return
	}
	kdb := keys.NewDB()
	for _, key := range r.Keys {
		kdb.AddKey(&data.PublicKey{TUFKey: *key})
	}
	for roleName, role := range r.Roles {
		role.Name = roleName
		err := kdb.AddRole(role)
		if err != nil {
			fmt.Println("Failed to add role to db")
			return
		}
	}
	repo := tuf.TufRepo{
		Targets: make(map[string]*data.Targets),
	}
	repo.SetRoot(r)
	remote, err := store.NewHTTPStore(
		"http://mirror1.poly.edu/test-pypi/",
		"metadata",
		"txt",
		"targets",
	)
	cached := store.NewFileCacheStore(remote, "/tmp/tuf")
	if err != nil {
		fmt.Println(err)
		return
	}

	client := client.NewClient(&repo, cached, kdb)

	err = client.Update()
	if err != nil {
		fmt.Println(err)
		return
	}
	filename := filepath.Base(ctx.Args()[0])
	f, err := os.OpenFile(filename, os.O_TRUNC|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()
	m := client.TargetMeta(ctx.Args()[0])
	if m == nil {
		fmt.Println("Requested package not found.")
		return
	}
	err = client.DownloadTarget(f, ctx.Args()[0], m)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Requested pacakge downloaded.")
}
