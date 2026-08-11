// SPDX-License-Identifier: MIT OR Apache-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TenantResource manages an IronAuth tenant.
type TenantResource struct {
	client *Client
}

type tenantModel struct {
	ID          types.String `tfsdk:"id"`
	DisplayName types.String `tfsdk:"display_name"`
}

// NewTenantResource constructs the resource.
func NewTenantResource() resource.Resource {
	return &TenantResource{}
}

func (r *TenantResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tenant"
}

func (r *TenantResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An IronAuth tenant: the top of the four-level resource model.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The server-assigned `ten_` identifier.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					// The id is assigned by the server and never changes. Without this
					// every plan shows it as "known after apply" and Terraform proposes
					// replacing a tenant that is perfectly fine.
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"display_name": schema.StringAttribute{
				MarkdownDescription: "The human-facing name. Updating it renames in place.",
				Required:            true,
			},
		},
	}
}

func (r *TenantResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data",
			fmt.Sprintf("expected *Client, got %T", req.ProviderData),
		)
		return
	}
	r.client = client
}

func (r *TenantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan tenantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// The idempotency key is derived from the DISPLAY NAME rather than minted from
	// entropy, so a retried create replays the first one instead of making a second
	// tenant nothing in state points at. Same rule the store's outbox follows: derive
	// the handle from the domain fact.
	created, err := r.client.CreateTenant(ctx, plan.DisplayName.ValueString(), "tf-tenant-"+plan.DisplayName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Creating tenant", err.Error())
		return
	}
	plan.ID = types.StringValue(created.ID)
	plan.DisplayName = types.StringValue(created.DisplayName)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TenantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state tenantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	found, err := r.client.GetTenant(ctx, state.ID.ValueString())
	if err != nil {
		if NotFound(err) {
			// Deleted out of band. REMOVING it from state is what lets the next apply
			// recreate it; returning an error would wedge every future plan on a
			// resource the operator can no longer reach.
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Reading tenant", err.Error())
		return
	}
	state.DisplayName = types.StringValue(found.DisplayName)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *TenantResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan tenantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var state tenantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	updated, err := r.client.UpdateTenant(ctx, state.ID.ValueString(), plan.DisplayName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Updating tenant", err.Error())
		return
	}
	plan.ID = state.ID
	plan.DisplayName = types.StringValue(updated.DisplayName)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TenantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tenantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteTenant(ctx, state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Deleting tenant", err.Error())
	}
}

// ImportState adopts an existing tenant by id, which is criterion 1's "including
// import": an operator who created a tenant through the console must be able to
// bring it under Terraform without recreating it.
func (r *TenantResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

var (
	_ resource.Resource                = &TenantResource{}
	_ resource.ResourceWithConfigure   = &TenantResource{}
	_ resource.ResourceWithImportState = &TenantResource{}
)
