// SPDX-License-Identifier: MIT OR Apache-2.0

// The IronAuth Terraform provider entry point (issue #51).
package main

import (
	"context"
	"flag"
	"log"

	"github.com/ELares/IronAuth/terraform-provider-ironauth/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run with support for debuggers")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.opentofu.org/ELares/ironauth",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
