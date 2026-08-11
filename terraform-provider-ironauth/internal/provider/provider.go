// SPDX-License-Identifier: MIT OR Apache-2.0

package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// IronAuthProvider is the provider implementation.
type IronAuthProvider struct {
	version string
}

// New returns a provider constructor for the given version.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &IronAuthProvider{version: version}
	}
}

type providerModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Token    types.String `tfsdk:"token"`
}

func (p *IronAuthProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ironauth"
	resp.Version = p.version
}

func (p *IronAuthProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage IronAuth through its management API (issue #51).",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "The management API base URL. Falls back to `IRONAUTH_ENDPOINT`.",
				Optional:            true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "The operator bearer credential. Falls back to `IRONAUTH_TOKEN`. " +
					"Marked sensitive, so it never appears in plan output or logs.",
				Optional:  true,
				Sensitive: true,
			},
		},
	}
}

func (p *IronAuthProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Environment fallback so a credential need never be written into a .tf file
	// that lands in version control. The variable wins only when the attribute is
	// absent, which keeps an explicit configuration authoritative.
	endpoint := config.Endpoint.ValueString()
	if endpoint == "" {
		endpoint = os.Getenv("IRONAUTH_ENDPOINT")
	}
	token := config.Token.ValueString()
	if token == "" {
		token = os.Getenv("IRONAUTH_TOKEN")
	}
	if endpoint == "" {
		resp.Diagnostics.AddError(
			"Missing endpoint",
			"Set the provider `endpoint` attribute or the IRONAUTH_ENDPOINT environment variable.",
		)
	}
	if token == "" {
		resp.Diagnostics.AddError(
			"Missing token",
			"Set the provider `token` attribute or the IRONAUTH_TOKEN environment variable.",
		)
	}
	if resp.Diagnostics.HasError() {
		return
	}
	client := NewClient(endpoint, token)
	resp.ResourceData = client
	resp.DataSourceData = client
}

func (p *IronAuthProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewTenantResource,
	}
}

func (p *IronAuthProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}
