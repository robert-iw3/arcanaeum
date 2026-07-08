<#
    .SYNOPSIS
    Helper functions used by the main flow or by the different sub-modules
#>

############################## Static variables ########################
import-module ./modules/EntraTokenAid.psm1 -force

$global:GLOBALMainTableDetailsHEAD = @'
<div id="mainTableContainer">
  <label>
    <select id="pageSize">
      <option value="1000">1000</option>
      <option value="5000">5000</option>
      <option value="10000">10000</option>
    </select>
  </label>
  <div id="tableWrapper"></div>
  <div id="paginationControls"></div>
</div>
<script id="mainTableData" type="application/json">
'@

# JavaScript for improved HTML table output
$global:GLOBALJavaScript = @'
    <script>
        // Predefined Views
        const predefinedViews = {
            "User": [
                {
                    label: "Inactive Users",
                    filters: {
                        Inactive: "=true",
                        Enabled: "=true"
                    },
                    columns: ["UPN", "Enabled", "UserType", "EntraRoles", "AzureRoles", "Inactive", "LastSignInDays", "Impact", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "LastSignInDays", direction: "desc" }
                },
                {
                    label: "Users with Roles (Entra ID / Azure)",
                    filters: {
                        AzureRoles: "or_>0",
                        EntraRoles: "or_>0",
                        Warnings: "or_EntraRoles||AzureRoles"
                    },
                    columns: ["UPN", "Enabled", "UserType", "Protected", "OnPrem", "EntraRoles", "AzureRoles", "Inactive", "MfaCap", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Users with Roles (Entra ID only)",
                    filters: {
                        EntraRoles: "or_>0",
                        Warnings: "or_EntraRoles"
                    },
                    columns: ["UPN", "Enabled", "UserType", "Protected", "OnPrem", "EntraRoles", "Inactive", "MfaCap", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Users Without MFA Methods",
                    filters: {
                        MfaCap: "=false",
                    }
                },
                {
                    label: "Privileged Unprotected Users",
                    filters: {
                        Protected: "=false",
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0",
                        AppRegOwn: "or_>0",
                        SPOwn: "or_>0"
                    },
                    columns: ["UPN", "Enabled", "UserType", "Protected", "EntraRoles", "AzureRoles", "Inactive", "AppRegOwn", "SPOwn", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "New Users",
                    columns: ["UPN", "Enabled", "UserType", "EntraRoles", "AzureRoles", "Inactive", "LastSignInDays", "CreatedDays", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "CreatedDays", direction: "asc" }
                },
                {
                    label: "Guest Users",
                    filters: {
                        UserType: "=Guest"
                    },
                    columns: ["UPN", "Enabled", "UserType", "GrpMem", "GrpOwn", "AppRegOwn", "SpOwn", "EntraRoles", "AzureRoles", "Inactive", "LastSignInDays", "CreatedDays", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"]
                },
                  {
                    label: "User Owning Applications",
                    filters: {
                        AppRegOwn: "or_>0",
                        SPOwn: "or_>0"
                    },
                    columns: ["UPN", "Enabled", "UserType", "Protected", "AppRegOwn", "SpOwn", "Inactive", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Entra Connect Accounts",
                    filters: {
                        UPN: "^Sync_||^ADToAADSyncServiceAccount"
                    },
                    columns: ["UPN", "Enabled", "GrpMem", "GrpOwn", "AppRegOwn", "SpOwn", "EntraRoles", "AzureRoles", "Inactive", "LastSignInDays", "CreatedDays", "Impact", "MfaCap", "Likelihood", "Risk", "Warnings"]
                }
            ],
            "Groups": [
                {
                    label: "Public M365 Groups",
                    filters: { Visibility: "=Public", Type: "=M365 Group" },
                    columns: ["DisplayName", "Type", "SecurityEnabled", "Visibility", "Users", "AzureRoles", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Dynamic Groups",
                    filters: { Dynamic: "=true"},
                    columns: ["DisplayName", "Type", "Dynamic", "SecurityEnabled", "Visibility", "Users", "Devices", "AzureRoles", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Privileged Unprotected Groups",
                    filters: {
                        Protected: "=false",
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0",
                        Warnings: "or_Eligible"
                    },
                    columns: ["DisplayName", "Type", "Dynamic", "Protected", "SecurityEnabled", "Visibility", "Users", "Devices", "AzureRoles", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Groups Used in CAPs",
                    filters: {
                        CAPs: "or_>0",
                        Warnings: "or_used in CAP"
                    },
                    columns: ["DisplayName", "Type", "Protected", "SecurityEnabled", "Visibility", "Users", "Devices", "NestedGroups", "NestedInGroups", "CAPs", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Groups Owned by Guests",
                    filters: {
                        Warnings: "Guest as owner"
                    },
                    columns: ["DisplayName", "Type", "Protected", "SecurityEnabled", "Users", "AzureRoles", "EntraRoles", "NestedGroups", "NestedInGroups", "AppRoles", "CAPs", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Groups Onboarded to PIM",
                    filters: { PIM: "=true" },
                    columns: ["DisplayName", "Type", "Protected", "SecurityEnabled", "PIM", "Users", "NestedGroups", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "AzureRoles", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Interesting Groups by Keywords",
                    filters: {
                        DisplayName: "admin||subscription||owner||contributor||secret||geheim||keyvault||passwor"
                    },
                    columns: ["DisplayName", "Type", "Dynamic", "DirectOwners", "PIM", "NestedOwners", "Protected", "SecurityEnabled", "Visibility", "Users", "Guests", "SPCount", "Devices", "NestedGroups", "NestedInGroups", "AppRoles", "CAPs", "EntraRoles", "AzureRoles", "Impact", "Likelihood", "Risk", "Warnings"]
                }

            ],
            "Enterprise Apps": [
                {
                    label: "Foreign Apps: Privileged",
                    filters: {
                        Foreign: "=True",
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        ApiMedium: "or_>0",
                        AppOwn: "or_>0",
                        SpOwn: "or_>0",
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0",
                        Warnings: "or_delegated API permissions||through group"
                    },
                    columns: ["DisplayName", "PublisherName", "Enabled", "Inactive", "Foreign", "GrpMem", "GrpOwn", "AppOwn", "SpOwn", "EntraRoles", "AzureRoles", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Foreign Apps: Extensive API Privs (Application)",
                    filters: {
                        Foreign: "=True",
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        ApiMedium: "or_>0"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Foreign Apps: Extensive API Privs (Delegated)",
                    filters: {
                        Foreign: "=True",
                        ApiDelegated: ">0",
                        Warnings: "delegated API permissions"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Foreign Apps: With Roles",
                    filters: {
                        Foreign: "=True",
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "EntraRoles", "AzureRoles", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Internal Apps: Privileged",
                    filters: {
                        Foreign: "=False",
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        AppOwn: "or_>0",
                        SpOwn: "or_>0",
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0",
                        Warnings: "or_delegated API permissions||through group"
                    },
                    columns: ["DisplayName", "Foreign", "Enabled", "Inactive", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Apps with Credentials",
                    filters: {
                        Credentials: ">0"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Credentials", "GrpMem", "GrpOwn", "AppOwn", "SpOwn", "EntraRoles", "AzureRoles", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Apps with Owners",
                    filters: {
                        Owners: ">0"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Owners", "GrpMem", "GrpOwn", "AppOwn", "SpOwn", "EntraRoles", "AzureRoles", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"]
                },
                {
                    label: "Inactive Apps",
                    filters: {
                        Inactive: "=true",
                        Enabled: "=true"
                    },
                    columns: ["DisplayName", "PublisherName", "Foreign", "Enabled", "Inactive", "LastSignInDays", "Owners", "GrpMem", "GrpOwn", "AppOwn", "SpOwn", "EntraRoles", "AzureRoles", "ApiDangerous", "ApiHigh", "ApiMedium", "ApiLow", "ApiMisc", "ApiDelegated", "Impact", "Likelihood", "Risk", "Warnings"],
                    sort: { column: "LastSignInDays", direction: "desc" }
                }
            ],
            "Managed Identities": [
                {
                    label: "Privileged Managed Identities",
                    filters: {
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        ApiMedium: "or_>0",
                        AppOwn: "or_>0",
                        SpOwn: "or_>0",
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0",
                        Warnings: "or_through group"
                    }
                },
                {
                    label: "Managed Identities: Extensive API Privs",
                    filters: {
                        ApiDangerous: "or_>0",
                        ApiHigh: "or_>0",
                        ApiMedium: "or_>0"
                    }
                },
                {
                    label: "Managed Identities: With Roles",
                    filters: {
                        EntraRoles: "or_>0",
                        AzureRoles: "or_>0"
                    }
                }
            ],
            "App Registrations": [
                {
                    label: "Apps with Owners",
                    filters: {
                        OwnerCount: ">0"
                    }
                },
                {
                    label: "Apps Controlled by App Admins",
                    filters: {
                        CloudAppAdmins: "or_>0",
                        AppAdmins: "or_>0"
                    },
                    sort: { column: "Impact", direction: "desc" }
                },
                {
                    label: "App with Secrets",
                    filters: {
                        SecretsCount: ">0"
                    }
                },
                {
                    label: "App Not Protected by AppLock",
                    filters: {
                        AppLock: "=false"
                    }
                },
                {
                    label: "Multitenant Apps",
                    filters: {
                        SignInAudience: "AzureADandPersonalMicrosoftAccount||AzureADMultipleOrgs"
                    }
                }

            ],
            "Conditional Access Policies": [
                {
                    label: "Enabled Policies",
                    filters: {
                        State: "=enabled"
                    }
                },
                {
                    label: "Blocking Policies",
                    filters: {
                        GrantControls: "=block"
                    }
                },
                {
                    label: "MFA Policies",
                    filters: {
                        GrantControls: "mfa"
                    }
                },
                {
                    label: "Authentication Strength Policies",
                    filters: {
                        AuthStrength: "!=empty"
                    }
                },
                {
                    label: "Device Registration Policies",
                    filters: {
                        UserActions: "urn:user:registerdevice"
                    }
                },
                {
                    label: "Security Info Registration Policies",
                    filters: {
                        UserActions: "urn:user:registersecurityinfo"
                    }
                },
                {
                    label: "Legacy Authentication Policies",
                    filters: {
                        AppTypes: "exchangeActiveSync||other"
                    }
                },
                {
                    label: "Device Code Flow Policies",
                    filters: {
                        AuthFlow: "deviceCodeFlow"
                    }
                },
                {
                    label: "Network Location Policies",
                    filters: {
                        IncNw: "or_!=0",
                        ExcNw: "or_!=0"
                    }
                },
                {
                    label: "Session Control Policies",
                    filters: {
                        SessionControls: ">0"
                    }
                }
            ],
            "Role Assignments Entra ID": [
                {
                    label: "Eligible Assignments",
                    filters: {
                        AssignmentType: "=Eligible"
                    }
                },
                {
                    label: "Active Assignments",
                    filters: {
                        AssignmentType: "Active"
                    }
                },
                {
                    label: "Tier-0 Assignments",
                    filters: {
                        RoleTier: "=Tier-0"
                    }
                },
                {
                    label: "Service Principal Assignments",
                    filters: {
                        PrincipalType: "Managed Identity||Enterprise Application"
                    }
                },
                {
                    label: "Scoped Assignments",
                    filters: {
                        Scope: "!=/ (Tenant)"
                    }
                },
                {
                    label: "Custom Roles",
                    filters: {
                        RoleType: "=CustomRole"
                    }
                }
            ],
            "Role Assignments Azure IAM": [
                {
                    label: "Eligible Assignments",
                    filters: {
                        AssignmentType: "=Eligible"
                    }
                },
                {
                    label: "Active Assignments",
                    filters: {
                        AssignmentType: "Active"
                    }
                },
                {
                    label: "Additional Conditions",
                    filters: {
                        Conditions: "=true"
                    }
                },
                {
                    label: "Service Principal Assignments",
                    filters: {
                        PrincipalType: "ServicePrincipal"
                    }
                },
                {
                    label: "Custom Roles",
                    filters: {
                        RoleType: "=CustomRole"
                    }
                }
            ]
        };

        //Define columns which are hidden by default
        const defaultHidden = ["DeviceReg", "DeviceOwn", "LicenseStatus", "OwnersSynced", "DefaultMS", "AppRoleRequired", "RoleAssignable", "LastSignInDays", "CreatedDays",];

        // Function to obtain the GET parameters from the URL
        function getURLParams() {
            const params = new URLSearchParams(window.location.search);
            const result = {};
            for (const [key, value] of params.entries()) {
                result[key] = value;
            }
            return result;
        }

        //Tooltips for column headers
        const columnTooltips = {
            "AuUnits": "Administrative Units",
            "Impact": "Score representing the potential impact if the object is compromised",
            "Likelihood": "Score representing the likelihood the object is compromised",
            "Risk": "Calculation: Impact x Likelihood",
            "OnPrem": "Objects synced from on-prem AD",
            "AzureRoles": "Directly or indirectly assigned Azure IAM roles",
            "EntraRoles": "Directly or indirectly assigned Entra ID roles",
            "CAPs": "Number of Conditional Access Policies the group is used in",
            "AppLock": "App Instance Property Lock status",
            "DeviceReg": "Device registered by the user",
            "DeviceOwn": "Device owned by the user",
            "AppAdmins": "App Admins scoped to tenant or app",
            "CloudAppAdmins": "Cloud App Admins scoped to tenant or app",
            "MfaCap": "User has one or more MFA methods registered",
            "Inactive": "No successful sign-in in the last 180+ days",
            "AppRoles": "Has application roles assigned",
            "GrpMem": "Member of Groups",
            "GrpOwn": "Owner of Groups",
            "SpOwn": "Owned Service Principals",
            "AppOwn": "Owned App Registrations",
            "AppRegOwn": "Owner of App Registrations",
            "SPOwn": "Owner of ServicePrincipals",
            "ApiDeleg": "Unique consented delegated API permissions",
            "PIM": "Onboarded to PIM for Groups",
            "Protected": "Cannot be modified by low-tier admins",
            "AssignmentType": "Note: Activated eligible assignments additionally appear as active.",
            "Conditions": "Has additional conditions"
        };

        (function () {
            let data = JSON.parse(document.getElementById("mainTableData").textContent);
            if (!Array.isArray(data)) {
                data = [data]; // wrap single object into an array
            }

            const container = document.getElementById("mainTableContainer");
            const wrapper = container.querySelector("#tableWrapper");
            const pageSizeSelector = container.querySelector("#pageSize");
            const pagination = container.querySelector("#paginationControls");

            let currentPage = 1;
            let rowsPerPage = parseInt(pageSizeSelector.value);
            let filteredData = [...data];
            let currentSort = { column: null, asc: true };
            let columnFilters = {};
            let hiddenColumns = new Set();

            const columnSelector = document.createElement("div");
            const exportBtn = document.createElement("button");
            const infoBox = document.createElement("div");

            exportBtn.textContent = "\u{1F4BE} Export CSV";
            exportBtn.style.margin = "10px 0";
            infoBox.style.margin = "10px 0";

            exportBtn.onclick = () => {
            const csvRows = [];

            const allColumns = Object.keys(data[0]);
            const linkColumn = allColumns[0]; // always treat first data column as link
            const visibleColumns = getVisibleColumns().filter(col => col !== linkColumn);

            // Final header: ID, DisplayName, then all other visible columns
            const header = ["ID", "DisplayName", ...visibleColumns];
            csvRows.push(header.join(","));

            filteredData.forEach(row => {
                const line = [];

                // Extract from first column, even if it's hidden
                const cellValue = row[linkColumn];
                if (typeof cellValue === "string") {
                    const match = cellValue.match(/<a\s+href=#([a-f0-9-]+)>(.*?)<\/a>/i);
                    if (match) {
                        line.push(`"${match[1]}"`); // GUID
                        line.push(`"${match[2].replace(/"/g, '""')}"`); // DisplayName
                    } else {
                        line.push(`""`);
                        line.push(`"${cellValue.replace(/"/g, '""')}"`);
                    }
                } else {
                    line.push(`""`, `""`);
                }

                // Add remaining visible columns
                visibleColumns.forEach(col => {
                    const val = row[col];
                    line.push(`"${String(val).replace(/"/g, '""')}"`);
                });

                csvRows.push(line.join(","));
            });

            const blob = new Blob([csvRows.join("\n")], { type: "text/csv" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            const baseName = decodeURIComponent(window.location.pathname
                .split('/')
                .pop()
                .replace(/\.[^/.]+$/, '')) || "export"; // fallback
            a.download = `${baseName}_table_export.csv`;
            a.click();
            URL.revokeObjectURL(url);
        };

        function applyPredefinedView(view) {
            columnFilters = {};

            // Filters
            Object.entries(view.filters || {}).forEach(([col, val]) => {
                const match = Object.keys(data[0]).find(k => k.toLowerCase() === col.toLowerCase());
                columnFilters[match || col] = val;
            });

            // Columns
            if (Array.isArray(view.columns)) {
                const allCols = Object.keys(data[0]);
                const allowed = view.columns
                    .map(v => allCols.find(col => col.toLowerCase() === v.toLowerCase()))
                    .filter(Boolean); // Only valid column names

                if (allowed.length > 0) {
                    hiddenColumns = new Set(allCols.filter(col => !allowed.includes(col)));
                } else {
                    console.warn("No valid matching columns found in view.columns");
                }
            }

            // Sort
            if (view.sort) {
                const sortCol = Object.keys(data[0]).find(k => k.toLowerCase() === view.sort.column.toLowerCase());
                if (sortCol) {
                    currentSort.column = sortCol;
                    currentSort.asc = view.sort.direction.toLowerCase() !== "desc";
                }
            }

            filterData();
            createColumnSelector();
        }

        function createPresetFilterModal() {
            const title = document.querySelector("h1")?.textContent || "";
            const type = title.includes("Users Enumeration") ? "User" :
                        title.includes("Groups Enumeration") ? "Groups" :
                        title.includes("EnterpriseApps Enumeration") ? "Enterprise Apps" :
                        title.includes("AppRegistration Enumeration") ? "App Registrations" :
                        title.includes("ManagedIdentities Enumeration") ? "Managed Identities" :
                        title.includes("ConditionalAccessPolicies Enumeration") ? "Conditional Access Policies" :
                        title.includes("Role Assignments Entra ID") ? "Role Assignments Entra ID" :
                        title.includes("Role Assignments Azure IAM") ? "Role Assignments Azure IAM" : null;

            const views = predefinedViews[type];
            if (!views?.length) return;

            const presetBtn = document.createElement("button");
            presetBtn.textContent = "\uD83E\uDDF0 Preset Views";
            presetBtn.style.margin = "10px 0px";

			const resetViewBtn = document.createElement("button");
			resetViewBtn.textContent = "\uD83D\uDD01 Reset View";
			resetViewBtn.style.margin = "10px 0px";

            const toolbarLeft = document.querySelector(".toolbar .left-section");
            if (toolbarLeft) {
				toolbarLeft.appendChild(presetBtn);
				toolbarLeft.appendChild(resetViewBtn);
			}

            //Resetview button
            resetViewBtn.addEventListener("click", () => {
                columnFilters = {};
                hiddenColumns = new Set();
                defaultHidden.forEach(col => hiddenColumns.add(col));
                currentSort = { column: "Risk", asc: false };
                filterData();
                createColumnSelector();
            });

            const modal = document.createElement("div");
            modal.className = "preset-modal hidden";
            modal.innerHTML = `
                <div class="preset-modal-content">
                    <h3>Preset Views for ${type}</h3>
                    ${views.map(v => `<button class="preset-btn" data-label="${v.label}">${v.label}</button>`).join("")}
                            <button class="close-preset-modal" style="margin-top: 20px;">\u2716 Close</button>
                </div>
            `;
            document.body.appendChild(modal);

            // Toggle visibility
            presetBtn.onclick = () => modal.classList.toggle("hidden");

            // Apply view
            modal.querySelectorAll(".preset-btn").forEach(btn => {
                btn.addEventListener("click", () => {
                    const view = views.find(v => v.label === btn.dataset.label);
                    if (view) applyPredefinedView(view);
                    modal.classList.add("hidden");
                });
            });


            // Close on outside click
            document.addEventListener("click", (e) => {
                const isInside = modal.contains(e.target);
                const isButton = e.target === presetBtn;
                if (!isInside && !isButton) {
                    modal.classList.add("hidden");
                }
            });

            // Close on
            modal.querySelector(".close-preset-modal").addEventListener("click", () => {
                modal.classList.add("hidden");
            });
        }

        // Top toolbar
        function createToolbar() {
            const toolbar = document.createElement("div");
            toolbar.className = "toolbar";

            const leftSection = document.createElement("div");
            leftSection.className = "left-section";

            const rightSection = document.createElement("div");
            rightSection.className = "right-section";

            // Page size selector
            const pageSizeLabel = document.createElement("label");
            pageSizeLabel.textContent = "Rows per page:";
            pageSizeLabel.style.fontSize = "14px";
            pageSizeLabel.appendChild(pageSizeSelector);
            leftSection.appendChild(pageSizeLabel);

            // Column toggle menu
            const columnWrapper = document.createElement("div");
            columnWrapper.appendChild(columnSelector);
            leftSection.appendChild(columnWrapper);

            // Export button
            leftSection.appendChild(exportBtn);
            const shareBtn = document.createElement("button");
            shareBtn.textContent = "\u{1F441} Share View";
            shareBtn.style.margin = "10px 0px";
            leftSection.appendChild(shareBtn);

            // Info box ("Showing entries")
            infoBox.className = "info-box";
            rightSection.appendChild(infoBox);

            toolbar.appendChild(leftSection);
            toolbar.appendChild(rightSection);

            container.insertBefore(toolbar, wrapper);

            shareBtn.onclick = () => {
                const url = new URL(window.location.href);
                url.search = "";

                // Add filters
                Object.entries(columnFilters).forEach(([key, val]) => {
                    if (!val.trim()) return;

                    const match = val.match(/^(or_|group\d+_)(.+)$/i);
                    if (match) {
                        const [_, groupPrefix, realVal] = match;
                        url.searchParams.set(`${groupPrefix}${key}`, realVal);
                    } else {
                        url.searchParams.set(key, val.trim());
                    }
                });

                // Add visible columns
                const visibleCols = getVisibleColumns();
                url.searchParams.set("columns", visibleCols.join(","));

                // Add sort info
                if (currentSort.column) {
                    url.searchParams.set("sort", currentSort.column);
                    url.searchParams.set("sortDir", currentSort.asc ? "asc" : "desc");
                }

                // Copy to clipboard
                navigator.clipboard.writeText(url.toString()).then(() => {
                    showToast("View (Filter, Columns, Sorting) link copied to clipboard");
                }).catch(err => {
                    console.error("Clipboard write failed", err);
                    showToast("\u{26A0} Failed to copy URL", 4000);
                });
            };

        }

        function getVisibleColumns() {
            return Object.keys(data[0]).filter(col => !hiddenColumns.has(col));
        }

        // Renders main table
        function renderTable() {
            let start = (currentPage - 1) * rowsPerPage;
            let end = start + rowsPerPage;
            let pageData = filteredData.slice(start, end);

            if (pageData.length === 0 && currentPage > 1) {
                currentPage = 1;
                return renderTable();
            }

            const columns = Object.keys(data[0] || {});
            const visibleCols = getVisibleColumns();

            //Capture active input to re-apply after filtering
            const activeElement = document.activeElement;
            let activeFilter = null;
            let caretPos = null;

            if (activeElement && activeElement.tagName === "INPUT" && activeElement.dataset.filter) {
                activeFilter = activeElement.dataset.filter;
                caretPos = activeElement.selectionStart;
            }

            let html = '<table class="overview-table"><thead><tr>';
            visibleCols.forEach(col => {
                const tooltip = columnTooltips[col] || "";
                const isSorted = currentSort.column === col;
                const sortIcon = isSorted
                    ? `<span style="font-size: 12px;"> ${currentSort.asc ? "\u{25B2}" : "\u{25BC}"}</span>`
                    : "";
                html += `<th data-col="${col}" title="${tooltip}">${col}${sortIcon}</th>`;
            });
            html += '</tr><tr>';
            visibleCols.forEach(col => {
                const val = Object.entries(columnFilters).find(([k]) => k.toLowerCase() === col.toLowerCase())?.[1] || '';
                html += `<th><input data-filter="${col}" value="${val}" placeholder="Filter..." style="width: 90%;" /></th>`;
            });
            html += '</tr></thead><tbody>';

            pageData.forEach(row => {
                html += '<tr>';
                visibleCols.forEach(col => {
                    const val = row[col];
                    const colIndex = columns.indexOf(col);
                    const columnHeader = columns[colIndex];
                    const columnHeaderLower = (columnHeader || "").toLowerCase();

                    const isLeftAligned =
                        columnHeader === undefined || // no matching header (cell without header)
                        columnHeaderLower.includes("displayname") ||
                        columnHeaderLower.includes("warnings") ||
                        columnHeaderLower === "role" ||
                        columnHeaderLower === "principal" ||
                        columnHeaderLower === "scope" ||
                        columnHeaderLower === "namelink" ||
                        columnHeaderLower === "apipermissiondescription" ||
                        columnHeaderLower.startsWith("upn") ||
                        columnHeaderLower.includes("scoperesolved");

                    const cellClass = isLeftAligned ? "left-align" : "";
                    html += `<td class="${cellClass}">${val}</td>`;
                });
                html += '</tr>';
            });

            html += '</tbody></table>';
            wrapper.innerHTML = html;

            // Sorting
            container.querySelectorAll("thead tr:first-child th").forEach(th => {
                th.onclick = () => {
                    const col = th.getAttribute("data-col");
                    if (currentSort.column === col) {
                        currentSort.asc = !currentSort.asc;
                    } else {
                        currentSort.column = col;
                        currentSort.asc = false;
                    }
                    sortData();
                    renderTable();
                };
            });

            // Re-attach input listeners without losing focus
            container.querySelectorAll("input[data-filter]").forEach(input => {
                const col = input.getAttribute("data-filter");
                let debounceTimer;
                input.addEventListener("input", () => {
                    const existingKey = Object.keys(columnFilters).find(k => k.toLowerCase() === col.toLowerCase());
                    columnFilters[existingKey || col] = input.value;
                    clearTimeout(debounceTimer);
                    debounceTimer = setTimeout(() => {
                        filterData();
                    }, 800);
                });
            });

            renderPagination();
            renderInfo(start, end);

            const table = wrapper.querySelector("table");
            if (table) colorCells(table);

            //Re-apply filter to focus
            if (activeFilter) {
                const newInput = container.querySelector(`input[data-filter="${activeFilter}"]`);
                if (newInput) {
                    newInput.focus();
                    if (caretPos !== null) {
                        newInput.setSelectionRange(caretPos, caretPos);
                    }
                }
            }
        }


        //Pagination for the main table
        function renderPagination() {
            const totalPages = Math.max(1, Math.ceil(filteredData.length / rowsPerPage));
            let html = '';

            if (currentPage > 1) {
                html += `<button onclick="goToPage(${currentPage - 1})">Previous</button>`;
            }
            html += `<span> Page ${Math.min(currentPage, totalPages)} of ${totalPages} </span>`;

            if (currentPage < totalPages) {
                html += `<button onclick="goToPage(${currentPage + 1})">Next</button>`;
            }
            pagination.innerHTML = html;
        }


        // Displays how many entries are shown (e.g., "Showing 1-10 of 50 entries")
        function renderInfo(start, end) {
            const shownStart = filteredData.length === 0 ? 0 : start + 1;
            const shownEnd = Math.min(end, filteredData.length);
            infoBox.textContent = `Showing ${shownStart}-${shownEnd} of ${filteredData.length} entries`;
        }

        window.goToPage = function (page) {
            currentPage = page;
            renderTable();
        };

        //MainTable sort function (special handling of cells containing links)
        function sortData() {
            const { column, asc } = currentSort;
            if (!column) return;

            function extractText(val) {
                if (typeof val === "string") {
                    // Extract text inside anchor if present
                    const match = val.match(/<a[^>]*>(.*?)<\/a>/i);
                    return match ? match[1] : val;
                }
                return val ?? '';
            }

            filteredData.sort((a, b) => {
                const valA = extractText(a[column]);
                const valB = extractText(b[column]);

                const numA = parseFloat(valA);
                const numB = parseFloat(valB);
                const isNumA = !isNaN(numA);
                const isNumB = !isNaN(numB);

                let result;
                if (isNumA && isNumB) {
                    result = numA - numB;
                } else {
                    result = String(valA).localeCompare(String(valB), undefined, { numeric: true, sensitivity: 'base' });
                }

                return asc ? result : -result;
            });
        }
        function parseOperatorFilter(input, rawValue) {
            // Extract visible text only (e.g., from anchor tags)
            function extractText(html) {
                const tempDiv = document.createElement('div');
                tempDiv.innerHTML = html;
                return tempDiv.textContent || tempDiv.innerText || '';
            }

            // Support simple OR: "value1 || value2"
            if (input.includes('||')) {
                return input.split('||').some(part => parseOperatorFilter(part.trim(), rawValue));
            }
            const visibleText = extractText(rawValue).trim();
            const valStr = visibleText.toLowerCase();
            const rawStr = String(rawValue).toLowerCase(); // includes HTML
            const lowerInput = input.toLowerCase();

            // Handle "=empty" and "!=empty"
            if (input.trim().toLowerCase() === "=empty") {
                return !rawStr || rawStr === "";
            }
            if (input.trim().toLowerCase() === "!=empty") {
                return !!rawStr && rawStr !== "";
            }

            // Match standard operators: =, >, <, >=, <=, ^, $, plus negated versions: !=, !^, !$
            const operatorMatch = input.match(/^(!?)([<>]=?|=|\^|\$)\s*(.+)$/);
            if (operatorMatch) {
                const [, negate, op, rawFilter] = operatorMatch;
                const num = parseFloat(rawFilter);
                const isNumeric = !isNaN(num);
                const filterStr = rawFilter.toLowerCase();

                let result = false;

                switch (op) {
                    case '=':
                        if (isNumeric && !isNaN(parseFloat(visibleText))) {
                            result = parseFloat(visibleText) === num;
                        } else {
                            result = valStr === filterStr;
                        }
                        break;
                    case '<':
                        result = isNumeric && parseFloat(visibleText) < num;
                        break;
                    case '<=':
                        result = isNumeric && parseFloat(visibleText) <= num;
                        break;
                    case '>':
                        result = isNumeric && parseFloat(visibleText) > num;
                        break;
                    case '>=':
                        result = isNumeric && parseFloat(visibleText) >= num;
                        break;
                    case '^':
                        result = valStr.startsWith(filterStr);
                        break;
                    case '$':
                        result = valStr.endsWith(filterStr);
                        break;
                }

                return negate ? !result : result;
            }

            // Handle general "does not contain" (!value with no operator)
            if (lowerInput.startsWith('!')) {
                const negatedFilter = lowerInput.slice(1);
                return !rawStr.includes(negatedFilter);
            }

            // Default: contains → search raw HTML (so href/id is searchable)
            return rawStr.includes(lowerInput);
        }


        // Applies per-column filters
        function filterData() {
            const groups = {}; // { groupName: [ { col, input } ] }

            Object.entries(columnFilters).forEach(([colKey, input]) => {
                if (!input.trim()) return;

                const match = input.match(/^(or_|group\d+_)(.+)$/i); // match prefix inside input
                if (match) {
                    const [, groupPrefix, innerInput] = match;
                    const groupName = groupPrefix.slice(0, -1); // remove trailing _
                    if (!groups[groupName]) groups[groupName] = [];
                    groups[groupName].push({ col: colKey, input: innerInput });
                } else {
                    if (!groups.default) groups.default = [];
                    groups.default.push({ col: colKey, input });
                }
            });

            filteredData = data.filter(row => {
                const defaultPass = (groups.default || []).every(f => {
                    const colMatch = Object.keys(row).find(c => c.toLowerCase() === f.col.toLowerCase());
                    if (!colMatch) return false;
                    return parseOperatorFilter(f.input.trim(), row[colMatch]);
                });

                if (!defaultPass) return false;

                const orGroups = Object.entries(groups).filter(([g]) => g !== "default");
                for (const [groupName, filters] of orGroups) {
                    const groupPass = filters.some(f => {
                        const colMatch = Object.keys(row).find(c => c.toLowerCase() === f.col.toLowerCase());
                        if (!colMatch) return false;
                        return parseOperatorFilter(f.input.trim(), row[colMatch]);
                    });
                    if (!groupPass) return false;
                }

                return true;
            });

            currentPage = 1;
            sortData();
            renderTable();

            const loadingOverlay = document.getElementById('loadingOverlay');
            if (loadingOverlay) loadingOverlay.style.display = 'none';
        }

        function updateColumnCountLabel(button, allCols) {
            const visibleCount = allCols.filter(col => !hiddenColumns.has(col)).length;
            button.textContent = `\u2699\uFE0F Columns (${visibleCount}/${allCols.length}) \u25BC`;
        }

        // Dropdown for toggling column visibility
        function createColumnSelector() {
            const wrapperDiv = document.createElement("div");
            wrapperDiv.className = "column-toggle-wrapper";

            const toggleButton = document.createElement("button");
            toggleButton.className = "column-toggle-button";

            const allColumns = Object.keys(data[0] || {});
            updateColumnCountLabel(toggleButton, allColumns); // INITIAL count

            wrapperDiv.appendChild(toggleButton);

            const menu = document.createElement("div");
            menu.className = "column-toggle-menu";

            const checkboxes = {};

            // Select/Deselect All
            const toggleAllCheckbox = document.createElement("input");
            toggleAllCheckbox.type = "checkbox";
            toggleAllCheckbox.checked = allColumns.every(c => !hiddenColumns.has(c));
            toggleAllCheckbox.onchange = () => {
                const checked = toggleAllCheckbox.checked;
                allColumns.forEach(col => {
                    checkboxes[col].checked = checked;
                    if (checked) hiddenColumns.delete(col);
                    else hiddenColumns.add(col);
                });
                updateColumnCountLabel(toggleButton, allColumns);
                renderTable();
            };

            const toggleAllWrapper = document.createElement("label");
            toggleAllWrapper.appendChild(toggleAllCheckbox);
            toggleAllWrapper.appendChild(document.createTextNode(" Select All"));
            menu.appendChild(toggleAllWrapper);
            menu.appendChild(document.createElement("hr"));

            // Individual columns
            allColumns.forEach(col => {
                const checkbox = document.createElement("input");
                checkbox.type = "checkbox";
                checkbox.checked = !hiddenColumns.has(col);
                checkboxes[col] = checkbox;

                checkbox.onchange = () => {
                    if (!checkbox.checked) hiddenColumns.add(col);
                    else hiddenColumns.delete(col);
                    updateColumnCountLabel(toggleButton, allColumns);
                    renderTable();
                    toggleAllCheckbox.checked = allColumns.every(c => checkboxes[c].checked);
                };

                const label = document.createElement("label");
                label.appendChild(checkbox);
                label.appendChild(document.createTextNode(" " + col));
                label.style.display = "block";
                label.style.margin = "4px 0";
                menu.appendChild(label);
            });

            wrapperDiv.appendChild(menu);
            columnSelector.innerHTML = "";
            columnSelector.appendChild(wrapperDiv);

            toggleButton.addEventListener("click", () => {
                wrapperDiv.classList.toggle("show");
            });

            document.addEventListener("click", (e) => {
                if (!wrapperDiv.contains(e.target)) {
                    wrapperDiv.classList.remove("show");
                }
            });
        }


        // Dark and light mode
        function applyTheme(theme) {
            document.body.classList.remove("light-mode", "dark-mode");
            document.body.classList.add(`${theme}-mode`);
            localStorage.setItem("theme", theme);
        }

        // Initializes theme on page load
        function initTheme() {
            const savedTheme = localStorage.getItem("theme") || "dark";
            applyTheme(savedTheme);

            const toggle = document.getElementById("themeToggle");
            if (toggle) {
                toggle.value = savedTheme;
                toggle.addEventListener("change", (e) => {
                    applyTheme(e.target.value);

                    const table = document.querySelector("#tableWrapper table");
                    if (table) colorCells(table);
                });
            }
        }

        // Event: Page size change
        pageSizeSelector.addEventListener("change", () => {
            rowsPerPage = parseInt(pageSizeSelector.value);
            currentPage = 1;
            renderTable();
        });

        //Apply columns selection based on GET parameters
        const urlParams = getURLParams();

        // Only apply defaultHidden if no `columns` param is present
        if (!urlParams.columns) {
            defaultHidden.forEach(col => hiddenColumns.add(col));
        }

        const columnParam = urlParams.columns;
        if (columnParam) {
            const allowedCols = columnParam.split(',').map(c => c.trim().toLowerCase());
            const allCols = Object.keys(data[0] || {});

            allCols.forEach(col => {
                if (!allowedCols.includes(col.toLowerCase())) {
                    hiddenColumns.add(col);
                }
            });
        }

        //Apply filters based on GET parameters
        const lowerKeys = Object.keys(data[0] || {}).reduce((map, col) => {
            map[col.toLowerCase()] = col;
            return map;
        }, {});

        Object.entries(urlParams).forEach(([key, value]) => {
            const match = key.match(/^(or|group\d+)_(.+)$/i);
            if (match) {
                const [, groupName, column] = match;
                const colKey = lowerKeys[column.toLowerCase()] || column;

                // Add prefix into value so input shows or_>0, etc.
                const operatorMatch = value.match(/^(=|!=|<=|>=|<|>|\^|\$|!)/);
                const operator = operatorMatch ? '' : '=';

                columnFilters[colKey] = `${groupName}_${operator}${value}`;
            } else {
                const colKey = lowerKeys[key.toLowerCase()];
                if (colKey) {
                    columnFilters[colKey] = value;
                }
            }
        });

        //Apply sort based on GET parameters
        if (urlParams.sort) {
            const sortCol = lowerKeys[urlParams.sort.toLowerCase()];
            const sortDir = (urlParams.sortDir || "asc").toLowerCase();

            if (sortCol) {
                currentSort.column = sortCol;
                currentSort.asc = sortDir !== "desc";
            }
        } else {
            //Default sort: Risk (descending)
            currentSort.column = "Risk";
            currentSort.asc = false;
        }

        // Init
        createColumnSelector();
        createToolbar();
        createPresetFilterModal();
        initTheme();
        filterData();
        })();

        // ###################################### SECTION for DETAILS ######################################
        // Parse object details JSON
        const rawElement = document.getElementById('object-data');
        let objects = [];

        if (rawElement && rawElement.textContent.trim()) {
            try {
                const parsedJson = JSON.parse(rawElement.textContent);
                objects = Array.isArray(parsedJson) ? parsedJson : [parsedJson];
            } catch (e) {
                console.warn("JSON parsing failed or no valid data found for object-data:", e);
            }
        } else {
            console.log("No object-data element found or it's empty.");
        }

        if (!Array.isArray(objects)) {
            objects = [objects]; // wrap single object in array
        }

        const container = document.getElementById('object-container');

        if (container) {
            container.innerHTML = '';

            const rawElement = document.getElementById('object-data');
            let objects = [];

            if (rawElement && rawElement.textContent.trim()) {
                try {
                    const parsedJson = JSON.parse(rawElement.textContent);
                    objects = Array.isArray(parsedJson) ? parsedJson : [parsedJson];
                } catch (e) {
                    console.warn("JSON parsing failed or no valid data found for object-data:", e);
                }
            } else {
                console.log("No object-data element found or it's empty.");
            }

            const renderTable = (title, data) => {
                const section = document.createElement('div');
                const heading = document.createElement('h3');
                heading.textContent = title;
                section.appendChild(heading);

                const table = document.createElement('table');
                table.className = 'property-table';

                const header = table.insertRow();
                Object.keys(data[0]).forEach(key => {
                    const th = document.createElement('th');
                    th.textContent = key;
                    header.appendChild(th);
                });

                data.forEach(obj => {
                    const row = table.insertRow();
                    Object.values(obj).forEach(value => {
                        const cell = row.insertCell();
                        cell.innerHTML = typeof value === 'string' && value.startsWith('<a') ? value : value ?? '';
                    });
                });

                section.appendChild(table);
                return section;
            };

            // Render vertical table
            const renderVerticalTable = (title, obj) => {
                const section = document.createElement('div');
                const heading = document.createElement('h3');
                heading.textContent = title;
                section.appendChild(heading);

                const table = document.createElement('table');
                table.className = 'property-table';

                for (const [key, value] of Object.entries(obj)) {
                    const row = table.insertRow();
                    const keyCell = row.insertCell();
                    keyCell.textContent = key;

                    const valueCell = row.insertCell();
                    valueCell.innerHTML = typeof value === 'string' && value.startsWith('<a') ? value : value ?? '';
                }

                section.appendChild(table);
                return section;
            };

            objects.forEach(obj => {
                const details = document.createElement('details');

                const objectId = obj["Object ID"];
                details.id = objectId;
                const summary = document.createElement('summary');
                summary.textContent = obj["Object Name"] || objectId;
                details.appendChild(summary);

                for (let [key, value] of Object.entries(obj)) {
                    key = key.trim();
                    if (!value || (Array.isArray(value) && value.length === 0)) continue;

                    if (Array.isArray(value)) {
                        const allStrings = value.every(v => typeof v === 'string');
                        const objectsOnly = value.filter(v => typeof v === 'object');

                        if (objectsOnly.length) {
                            details.appendChild(renderTable(key, objectsOnly));
                        } else if (allStrings) {
                            details.appendChild(renderPreBlock(key, value));
                        }
                    } else if (typeof value === 'object') {
                        if (key === "General Information") {
                            details.appendChild(renderVerticalTable(key, value));
                        } else {
                            details.appendChild(renderTable(key, [value]));
                        }
                    }
                }

                container.appendChild(details);
            });

            window.addEventListener('DOMContentLoaded', scrollToObjectByHash);
            window.addEventListener('hashchange', scrollToObjectByHash);
        } else {
            console.warn("Element with id 'object-container' does not exist.");
        }


        function scrollToObjectByHash() {
            const targetId = window.location.hash.replace('#', '');
            if (!targetId) return;

            const targetElement = document.getElementById(targetId);
            if (targetElement) {
                targetElement.open = true;
                setTimeout(() => {
                    targetElement.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }, 100);
            }
        }

        //YAML rendering CAP
        function renderPreBlock(title, lines) {
            const section = document.createElement('div');
            const heading = document.createElement('h3');
            heading.textContent = title;
            section.appendChild(heading);

            const pre = document.createElement('pre');
            pre.className = 'yaml-block';

            // Join lines with newlines — keep them raw so links render
            pre.innerHTML = lines.join('\n');

            section.appendChild(pre);
            return section;
        }

        window.addEventListener('DOMContentLoaded', scrollToObjectByHash);
        window.addEventListener('hashchange', scrollToObjectByHash);

        let expandedState = false; // false = collapsed, true = expanded

        function toggleAll() {
            const allDetails = document.querySelectorAll('details');

            if (!expandedState && allDetails.length >= 2000) {
                const confirmExpand = confirm(
                    `Warning: Expanding ${allDetails.length} objects at once may slow down the page.\n\nDo you want to continue?`
                );
                if (!confirmExpand) return;
            }

            allDetails.forEach(d => d.open = !expandedState);
            expandedState = !expandedState;

            // Update button label
            const btn = document.getElementById('toggle-expand');
            btn.textContent = expandedState ? 'Collapse All' : 'Expand All';
        }

        document.addEventListener("DOMContentLoaded", () => {
            const toggleExpandBtn = document.getElementById('toggle-expand');
            if (toggleExpandBtn) {
                toggleExpandBtn.addEventListener('click', toggleAll);
            } else {
                console.warn("Element with id 'toggle-expand' does not exist.");
            }

            const nav = document.getElementById('topNav');
            const headings = document.querySelectorAll('h2');

            // Generate anchor links from <h2>
            headings.forEach(h2 => {
                const id = h2.id || h2.textContent.trim().toLowerCase().replace(/\s+/g, '-');
                h2.id = id;

                const link = document.createElement('a');
                link.href = `#${id}`;
                link.textContent = h2.textContent.trim();
                nav.appendChild(link);
            });

            // === Add Theme Selector to navbar ===

            // Flexible spacer to push selector right
            const spacer = document.createElement('div');
            spacer.style.flexGrow = '1';
            nav.appendChild(spacer);

            // Theme selector
            const themeLabel = document.createElement('label');
            themeLabel.style.display = 'flex';
            themeLabel.style.alignItems = 'center';
            themeLabel.style.gap = '4px';
            themeLabel.style.marginLeft = 'auto';
            themeLabel.innerHTML = `
                <select id="navThemeToggle" style="padding: 4px 8px; font-size: 14px; border-radius: 4px;">
                    <option value="dark">\uD83C\uDF13 Dark</option>
                    <option value="light">\uD83C\uDF13 Light</option>
                </select>
            `;
            nav.appendChild(themeLabel);

            // Apply stored or default theme
            const themeSelect = document.getElementById('navThemeToggle');
            const savedTheme = localStorage.getItem('theme') || 'dark';
            themeSelect.value = savedTheme;
            document.body.classList.add(`${savedTheme}-mode`);

            themeSelect.addEventListener('change', (e) => {
                const newTheme = e.target.value;
                document.body.classList.remove("light-mode", "dark-mode");
                document.body.classList.add(`${newTheme}-mode`);
                localStorage.setItem("theme", newTheme);

                const table = document.querySelector("#tableWrapper table");
                if (table) colorCells(table);
            });

            // *** HELP MODAL ****
            if (!themeLabel) return;

            // Create Help button
            const helpBtn = document.createElement('button');
            helpBtn.textContent = '\u2753 Help';
            helpBtn.style.padding = '1px 10px';
            helpBtn.style.fontSize = '14px';
            helpBtn.style.borderRadius = '4px';
            helpBtn.style.border = '1px solid #6e6e6e';
            helpBtn.style.cursor = 'pointer';
            helpBtn.style.marginLeft = '10px';
            themeLabel.parentElement.appendChild(helpBtn);

            // Create overlay background
            const modalOverlay = document.createElement('div');
            modalOverlay.style.position = 'fixed';
            modalOverlay.style.top = '0';
            modalOverlay.style.left = '0';
            modalOverlay.style.width = '100vw';
            modalOverlay.style.height = '100vh';
            modalOverlay.style.backgroundColor = 'rgba(0, 0, 0, 0.6)';
            modalOverlay.style.display = 'none';
            modalOverlay.style.zIndex = '9999';
            modalOverlay.style.justifyContent = 'center';
            modalOverlay.style.alignItems = 'center';

            // Create modal content box
            const modalContent = document.createElement('div');
            modalContent.style.background = 'var(--nav-link-bg)';
            modalContent.style.color = 'var(--nav-link-text)';
            modalContent.style.padding = '24px';
            modalContent.style.borderRadius = '12px';
            modalContent.style.maxWidth = '800px';
            modalContent.style.width = '90%';
            modalContent.style.boxShadow = '0 8px 16px rgba(0,0,0,0.4)';
            modalContent.style.fontSize = '15px';
            modalContent.style.lineHeight = '1.6';
            modalContent.style.position = 'relative';

            modalContent.innerHTML = `
                <h2 style="margin-top: 0;">How to Use This Report</h2>
				<strong>General</strong>
				<ul style="margin-top: 6px;">
                    <li>Click the \u2699\uFE0F <strong>Columns</strong> button to show or hide specific columns.
                    <li>Click \u{1F4BE} <strong>Export CSV</strong> to download the currently visible data as a CSV file.</li>
                    <li>Click \u{1F441} <strong>Share View</strong> to copy filters, sorting, and column selection as a shareable link.</li>
                    <li>Click \uD83E\uDDF0 <strong>Preset Views</strong> to apply preconfigured filters and column selections.</li>
                    <li>Click \uD83D\uDD01 <strong>Reset View</strong> to reset the view to the default.</li>
                    <li>Click on object names to jump to detailed information, even across reports.<br>
                    Links look like this: <a href="#" onclick="return false;" style="pointer-events: none;">Example Link</a></li>
                    <li>When navigating within the report, use the browser's back button to return.</li>
                    <li>Browser search can locate content even within collapsed <em>details</em> sections.</li>
                    <li>Some table header fields display helper text on mouse hover.</li>
                    <li>Sort data by clicking any table header.
				</ul>
				<strong>Filtering</strong>
				<ul style="margin-top: 6px;">
					<li>If no operator is specified, filtering defaults to <em>contains</em>.</li>
					<li>Use <code>=</code> for an exact match.</li>
					<li>Use <code>^</code> for <em>starts with</em> (e.g., <code>^Mallory</code>).</li>
					<li>Use <code>$</code> for <em>ends with</em> (e.g., <code>$domain.ch</code>).</li>
					<li>Comparison operators like <code>&gt;</code>, <code>&lt;</code>, <code>&gt;=</code>, <code>&lt;=</code> are supported (for numeric values only).</li>
                    <li>Filters can be negated by starting with <code>!</code> (except for numeric comparisons).<br>Examples: <code>!Mallory</code>, <code>!=Mallory</code>, <code>!^Mallory</code> or <code>!$domain.ch</code>.</li>
                    <li>Use <code>=empty</code> to match empty cells, or <code>!=empty</code> to match non-empty cells.</li>
                    <li>Use <code>||</code> to match any of multiple values in the same column (e.g., <code>Admin || Guest</code>).</li>
                    <li>To apply <code>OR</code> logic across columns, use <code>or_</code> or <code>group1_</code>. Examples: Column1:<code>or_>1</code> Column2:<code>or_!Mallory</code>.</li>
					<li>The <strong>DisplayName</strong> column includes the object's ID (hidden), allowing filtering by ID.</li>
				</ul>
				<strong>Rating</strong>
				<ul style="margin-top: 6px;">
					<li><strong>Impact</strong>: Represents the amount or severity of permission the object has.</li>
					<li><strong>Likelihood</strong>: Represents how easily the object can be influenced or strongly it is protected.</li>
					<li><strong>Risk</strong>: Calculated as: <em>Impact x Likelihood = Risk</em>.</li>
                    <li><strong>Important</strong>:
                        <ul>
                            <li>This scoring is meant as a basic evaluation to help sort and prioritize entries in the table.</li>
                            <li>Risk scores are not directly comparable between object types or reports.</li>
                            <li>It is not intended to replace a full risk assessment.</li>
                        </ul>
                    </li>
				</ul>
                \u{1F4D6} More information in the <a href="https://github.com/CompassSecurity/EntraFalcon">GitHub README</a><br>
                <button id="closeHelpModal" style="margin-top: 16px; padding: 6px 12px; font-size: 14px; border-radius: 4px; border: 1px solid #aaa; cursor: pointer;">\u2716 Close</button>
            `;

            modalOverlay.appendChild(modalContent);
            document.body.appendChild(modalOverlay);

            // Show modal
            helpBtn.addEventListener('click', () => {
                modalOverlay.style.display = 'flex';
            });

            // Close modal on background click or button click
            modalOverlay.addEventListener('click', (e) => {
                if (e.target === modalOverlay || e.target.id === 'closeHelpModal') {
                    modalOverlay.style.display = 'none';
                }
            });
            document.addEventListener('keydown', (e) => {
                const isVisible = modalOverlay.style.display === 'flex';
                if (e.key === 'Escape' && isVisible) {
                    modalOverlay.style.display = 'none';
                }
            });
        });

        //Toast displayed when copy the current view
        function showToast(message, duration = 3000) {
            const toast = document.createElement("div");
            toast.textContent = message;
            toast.style.position = "fixed";
            toast.style.bottom = "30px";
            toast.style.right = "30px";
            toast.style.padding = "10px 16px";
            toast.style.background = "#333";
            toast.style.color = "#fff";
            toast.style.borderRadius = "8px";
            toast.style.boxShadow = "0 2px 6px rgba(0, 0, 0, 0.4)";
            toast.style.fontSize = "14px";
            toast.style.opacity = "0";
            toast.style.transition = "opacity 0.3s ease";

            document.body.appendChild(toast);
            requestAnimationFrame(() => toast.style.opacity = "1");

            setTimeout(() => {
                toast.style.opacity = "0";
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }


        // Coloring cells
        function colorCells(table) {
			const rows = table.rows;
			if (!rows.length) return;

			const isDark = document.body.classList.contains("dark-mode");
			const headers = Array.from(rows[0].cells).map(th => th.getAttribute("data-col") || th.textContent.trim());

			const redIfTrueHeaders = new Set(['Foreign', 'Inactive', 'PIM', 'Dynamic', 'SecurityEnabled', 'OnPrem', 'Conditions', 'IsBuiltIn','IsPrivileged']);
			const redIfFalseHeaders = new Set(['AppLock', 'MfaCap', 'Protected', 'Enabled', 'RoleAssignable']);
			const redIfContent = new Set(['all', 'alltrusted', 'report-only', 'disabled', 'public', 'guest', 'customrole', 'active']);
			const redIfContentHeaders = new Set(['IncUsers', 'IncResources', 'IncNw', 'ExcNw', 'IncPlatforms', 'State', 'Visibility', 'UserType', 'RoleType', 'AssignmentType']);

			const redColor = isDark ? "#800000" : "#FFB6C1";
			const greenColor = isDark ? "#005f00" : "#98FB98";

			for (let i = 2; i < rows.length; i++) {
				const cells = rows[i].cells;

				for (let j = 0; j < cells.length; j++) {
					const cell = cells[j];
					const cellValue = cell.textContent.trim();
					const lowerValue = cellValue.toLowerCase();
					const columnHeader = headers[j];

					let backgroundColor = "";

					if (!isNaN(cellValue) && cellValue !== "") {
						backgroundColor = parseFloat(cellValue) === 0 ? greenColor : redColor;
					} else if (lowerValue === "true" || lowerValue === "false") {
						const boolVal = lowerValue === "true";

						if (redIfTrueHeaders.has(columnHeader)) {
							backgroundColor = boolVal ? redColor : greenColor;
						} else if (redIfFalseHeaders.has(columnHeader)) {
							backgroundColor = boolVal ? greenColor : redColor;
						}
					} else if (redIfContentHeaders.has(columnHeader)) {
						if (redIfContent.has(lowerValue)) {
							backgroundColor = redColor;
						} else {
							backgroundColor = greenColor; // Now only applies to those in redIfContentHeaders!
						}
					}

					if (cell.style.backgroundColor !== backgroundColor && backgroundColor) {
						cell.style.backgroundColor = backgroundColor;
					}
				}
			}
		}

    </script>
'@

# CSS for formating the table
$global:GLOBALCss = @"
<style>
    /* ======== Shared Styles ======== */
    html {
        scroll-behavior: smooth;
    }

    body {
        font-family: Arial, Helvetica, sans-serif;
        margin: 0;
        padding: 0;
        padding-left: 12px;
        padding-right: 12px;
    }

	#topNav {
		display: flex;
		gap: 8px;
		padding: 12px 16px;
		background-color: var(--nav-bg);
		border-bottom: 1px solid var(--nav-border);
		position: sticky;
		top: 0;
		z-index: 1000;
		flex-wrap: wrap;
        margin-left: -12px;
        margin-right: -12px;
        padding-left: 12px;
        padding-right: 12px;
	}

	#topNav a {
		padding: 6px 14px;
		font-size: 14px;
		font-weight: 500;
		border-radius: 999px;
		text-decoration: none;
		background-color: var(--nav-link-bg);
		color: var(--nav-link-text);
		transition: background 0.2s ease, color 0.2s ease;
		border: 1px solid transparent;
	}

	#topNav a:hover {
		background-color: var(--nav-link-hover-bg);
	}

	#topNav a.active {
		background-color: var(--nav-link-active-bg);
		color: var(--nav-link-active-text);
		border-color: var(--nav-link-active-border);
	}

	h2 {
		scroll-margin-top: var(--sticky-offset, 60px); /* Matches nav height */
	}

    table {
        width: auto;
        max-width: 100%;
        margin-top: 20px;
        border-collapse: collapse;
        font-size: 12px;
    }

    th {
        font-size: 11px;
        font-weight: bold;
        padding-top: 6px;
        padding-bottom: 6px;
        vertical-align: middle;
    }

	td {
        padding: 6px;
        max-width: 100%;
    }

    .overview-table td {
        text-align: center;
        padding: 6px;
        max-width: 100%;
    }

	.property-table th {
		font-size: 12px;
		padding-left: 8px;
		padding-right: 8px;
	}

    td.left-align {
        text-align: left;
    }

    thead input[data-filter] {
        width: auto;
        max-width: 90%;
        font-size: 11px;
        padding: 0px;
    }

    thead tr:first-child th {
        position: sticky;
        top: 0;
        top: 50px;
        z-index: 2;
    }

    #mainTableContainer {
        padding: 0px 16px 5px 0px;
        max-width: fit-content;
        margin: 0;
    }

    #mainTableContainer table {
        width: 100%;
    }

    .toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        width: 100%;
        margin: 15px 0;
    }

    .toolbar .left-section,
    .toolbar .right-section {
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .toolbar .spacer {
        flex-grow: 1;
    }

    .info-box {
        font-size: 14px;
        white-space: nowrap;
    }

    .toolbar select,
    .toolbar button,
    select,
    button {
        padding: 6px 10px;
        font-size: 14px;
        border-radius: 4px;
        border: 1px solid;
    }

    #paginationControls {
        margin-top: 16px;
    }

    #loadingOverlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(20, 20, 20, 0.85);
        z-index: 2000;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        color: #fff;
        font-size: 20px;
        font-weight: bold;
        backdrop-filter: blur(3px);
    }

    #loadingOverlay .spinner {
        border: 6px solid #ccc;
        border-top: 6px solid #4CAF50;
        border-radius: 50%;
        width: 60px;
        height: 60px;
        animation: spin 1s linear infinite;
        margin-bottom: 15px;
    }

    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }

    /* -- Details Section -- */
    .column-toggle-wrapper {
        position: relative;
        display: inline-block;
        margin: 0;
    }

    .column-toggle-button {
        padding: 6px 10px;
        font-size: 14px;
        cursor: pointer;
        border-radius: 4px;
    }

    .column-toggle-menu {
        display: none;
        position: absolute;
        top: 110%;
        left: 0;
        padding: 8px;
        z-index: 1000;
        max-height: 200px;
        overflow-y: auto;
        min-width: 150px;
    }

    .column-toggle-wrapper.show .column-toggle-menu {
        display: block;
    }

    .column-toggle-menu label {
        display: block;
        white-space: nowrap;
        margin: 4px 0;
        font-size: 13px;
    }

    details {
        margin-bottom: 12px;
        border-radius: 8px;
        padding: 10px;
        box-shadow: 0 1px 4px rgba(0,0,0,0.4);
        scroll-margin-top: var(--sticky-offset, 60px); /* Matches nav height */
    }

    summary {
        font-weight: bold;
        font-size: 14px;
        cursor: pointer;
    }

    pre.yaml-block {
        padding: 10px;
        border-radius: 6px;
        white-space: pre-wrap;
        font-family: Consolas, monospace;
        font-size: 12px;
        margin-top: 10px;
        overflow-x: auto;
    }

    #toggle-expand {
        border-radius: 4px;
        padding: 6px 12px;
        margin: 10px 0;
        cursor: pointer;
        font-size: 14px;
    }

    code {
        padding: 2px 5px;
        border-radius: 4px;
        font-family: Consolas, monospace;
        font-size: 90%;
    }

    .preset-modal {
        position: fixed;
        top: 110px;
        left: 50%;
        transform: translateX(-50%);
        z-index: 9999;
        padding: 20px;
        border-radius: 12px;
        max-width: 480px;
        width: auto;
        background: var(--nav-link-bg);
        color: var(--nav-link-text);
        border: 1px solid var(--nav-link-hover-bg);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
        display: none;
        flex-direction: column;
        gap: 10px;
    }

    .preset-modal-content {
        display: flex;
        flex-direction: column;
        gap: 10px;
    }

    .preset-modal.show,
    .preset-modal:not(.hidden) {
        display: flex;
    }

    .preset-modal button {
        padding: 6px 12px;
        font-size: 14px;
        border-radius: 6px;
        cursor: pointer;
        border: 1px solid var(--nav-link-hover-bg);
        background-color: var(--nav-link-bg);
        color: var(--nav-link-text);
    }

    .preset-modal button:hover {
        background-color: var(--nav-link-hover-bg);
    }
    /* ======== Dark Mode ======== */
    body.dark-mode {
        background-color: #121212;
        color: #E0E0E0;
    }

    body.dark-mode h1 {
        color: #bebebe;
        font-size: 32px;
        border-bottom: 2px solid #bebebe;
    }

    body.dark-mode h2 {
        color: #BB86FC;
        font-size: 24px;
        font-weight: bold;
    }

    body.dark-mode h3 {
        color: #03DAC6;
        font-size: 18px;
    }

    body.dark-mode table {
        background-color: #1E1E1E;
        color: #E0E0E0;
    }

    body.dark-mode th {
        background: #282a36;
        color: #E0E0E0;
        border: 1px solid #333;
    }

    body.dark-mode td {
        border: 1px solid #333;
    }

    body.dark-mode tbody tr:nth-child(even) {
        background-color: #1A1A1A;
    }

    body.dark-mode tbody tr:nth-child(odd) {
        background-color: #2A2A2A;
    }

    body.dark-mode tbody tr:hover td {
        background-color: #444 !important;
    }

    body.dark-mode a {
        color: #FFB74D;
        text-decoration: none;
    }

    body.dark-mode a:hover {
        color: #FF6F61;
        text-decoration: underline;
    }

    body.dark-mode .column-toggle-button {
        background-color: #2a2a2a;
        color: #e0e0e0;
        border-color: #555;
    }

    body.dark-mode .column-toggle-menu {
        background: #1e1e1e;
        color: #e0e0e0;
        border: 1px solid #555;
        box-shadow: 0 2px 8px rgba(255, 255, 255, 0.05);
    }

    body.dark-mode .column-toggle-button:hover {
        background-color: #3a3a3a;
    }

    body.dark-mode select,
    body.dark-mode button {
        background-color: #2a2a2a;
        color: #e0e0e0;
        border-color: #555;
    }

    body.dark-mode select:hover,
    body.dark-mode button:hover {
        background-color: #3a3a3a;
    }

    body.dark-mode select:focus,
    body.dark-mode button:focus {
        outline: none;
        border-color: #888;
        box-shadow: 0 0 4px #888;
    }

    body.dark-mode details {
        background-color: #1c1c1c;
        border: 1px solid #333;
    }

    body.dark-mode pre.yaml-block {
        background-color: #1e1e1e;
        color: #e0e0e0;
        border: 1px solid #444;
    }

    body.dark-mode #toggle-expand {
        background-color: #333;
        color: #E0E0E0;
        border: 1px solid #666;
    }

    body.dark-mode #toggle-expand:hover {
        background-color: #444;
        border-color: #888;
    }

    body.dark-mode {
        --nav-bg: #1e1e1e;
        --nav-text: #fff;
        --nav-link-bg: #2a2a2a;
        --nav-link-text: #fff;
        --nav-link-hover-bg: #3a3a3a;
    }

    body.dark-mode code {
        background-color: #2e2e2e;
        color: #ff79c6; /* Bright pink/purple for dark contrast */
        border: 1px solid #444;
    }

    /* ======== Light Mode ======== */
    body.light-mode {
        background-color: white;
        color: black;
    }

    body.light-mode h1 {
        color: #e68a00;
        font-size: 32px;
        border-bottom: 2px solid #bebebe;
    }

    body.light-mode h2 {
        color: #3a3aec;
        font-size: 24px;
        font-weight: bold;
    }

    body.light-mode h3 {
        color: #000099;
        font-size: 18px;
    }

    body.light-mode th {
        background: #5d8fb8;
        color: #fff;
        border: 1px solid #d2d2d2;
    }

    body.light-mode td {
        border: 1px solid #d2d2d2;
    }

    body.light-mode tbody tr:nth-child(even) {
        background: #f0f0f2;
    }

    body.light-mode tbody tr:nth-child(odd) {
        background: white;
    }

    body.light-mode tbody tr:hover td {
        background-color: lightblue !important;
    }

    body.light-mode a {
        color: #0645AD;
        text-decoration: none;
    }

    body.light-mode a:hover {
        text-decoration: underline;
    }

    body.light-mode .column-toggle-button {
        background-color: #f4f4f4;
        color: #000;
        border-color: #ccc;
    }

    body.light-mode .column-toggle-button:hover {
        background-color: #e0e0e0;
    }

    body.light-mode .column-toggle-menu {
        background: #fff;
        color: #000;
        border: 1px solid #ccc;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    }

    body.light-mode select,
    body.light-mode button {
        background-color: #f4f4f4;
        color: #000;
        border-color: #ccc;
    }

    body.light-mode select:hover,
    body.light-mode button:hover {
        background-color: #e0e0e0;
    }

    body.light-mode select:focus,
    body.light-mode button:focus {
        outline: none;
        border-color: #666;
        box-shadow: 0 0 4px #aaa;
    }

    body.light-mode details {
        background-color: rgb(250, 250, 250);
        border: 1px solid #333;
        box-shadow: 0 1px 4px rgb(213, 223, 231);
    }

    body.light-mode pre.yaml-block {
        background-color: rgb(205, 209, 211);
        border: 1px solid #444;
        color: #000;
    }

    body.light-mode #toggle-expand {
        background-color: rgb(231, 229, 229);
        color: #000;
        border: 1px solid #666;
    }

    body.light-mode #toggle-expand:hover {
        background-color: #e0e0e0;
        border-color: #888;
    }

    body.light-mode {
        --nav-bg: #f9f9f9;
        --nav-text: #000;
        --nav-link-bg: #e0e0e0;
        --nav-link-text: #000;
        --nav-link-hover-bg: #ccc;
    }
    body.light-mode code {
        background-color: #f2f2f2;
        color: #d6336c;
        border: 1px solid #ddd;
    }
</style>
"@

############################## Internal function section ########################

# Check if MS Graph is authenticated; if not, call the function for interactive sign-in
function EnsureAuthMsGraph {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][String[]]$AuthMethod
    )

    $result = $false
    if (AuthCheckMSGraph) {
        write-host "[+] MS Graph session OK"
        $result = $true

    } else {
        if (AuthenticationMSGraph -AuthMethod $AuthMethod) {
            write-host "[+] MS Graph successfully authenticated"
            $result = $true
        } else {
            if (-not $GLOBALAuthParameters['Tenant']) {write-host "[i] Maybe try to specify the tenant: -Tenant"}
            Write-host "[!] Aborting"
            $result = $false

        }
    }
    Return $result
}


# Check if ARM API authentication worked. If not, call the function for interactive sign-in
function EnsureAuthAzurePsNative {
    if (AuthCheckAzPSNative) {
        write-host "[+] Azure PS Session OK"
        $result = $true
    } else {
        if (AuthenticationAzurePSNative) {
            write-host "[+] Azure PS successfully authenticated"
            $result = $true
        } else {
            $result = $false
        }
    }
    return $result
}

#Function to check if a valid MS Graph session exists
function AuthCheckMSGraph {
    $result = $true
    Write-host "[*] Checking session MS Graph"
    if ($null -ne $GLOBALMsGraphAccessToken.access_token) {
        try {
            Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/organization?$select=id' -erroraction Stop -UserAgent $($GlobalAuditSummary.UserAgent.Name) | out-null
        } catch {
            write-host "[!] Auth error: $($_.Exception.Message -split '\n')"
            $result = $false
        }
    } else {
        Write-host "[i] Not yet authenticated"
        $result = $false
    }
    return $result
}
#Get basic tenant info
function Get-OrgInfo {
    $QueryParameters = @{
        '$select' = "Id,DisplayName"
    }
    $OrgInfo = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/organization" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    return $OrgInfo
}

#Get information if users are MFA capable
function Get-RegisterAuthMethodsUsers {
    # Requires Premium otherwise HTTP 403:Tenant is not a B2C tenant and doesn't have premium license
    write-host "[*] Retrieve users registered auth methods"

    $QueryParameters = @{
        '$select' = "Id,IsMfaCapable"
        '$top' = "5000"
    }
    try {
        $RegisteredAuthMethods = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/reports/authenticationMethods/userRegistrationDetails" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop
    } catch {
        if ($($_.Exception.Message) -match "Status: 403") {
            write-host "[!] HTTP 403 Error: Most likely due to missing Entra ID premium licence. Can't retrieve users auth methods."
        } else {
            write-host "[!] Auth error: $($_.Exception.Message -split '\n'). Can't retrieve users auth methods."
        }
    }

    #Convert to HT
    $UserAuthMethodsTable = @{}
    foreach ($method in $RegisteredAuthMethods ) {
        $UserAuthMethodsTable[$method.Id] = $method.IsMfaCapable
    }
    return $UserAuthMethodsTable
}

#Get all Devices
function Get-Devices {
     write-host "[*] Retrieve devices"

    $QueryParameters = @{
        '$select' = "Id,accountEnabled,displayName,Manufacturer,trustType,operatingSystem,operatingSystemVersion"
        '$top' = "999"
    }

    $DevicesRaw = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/devices" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    #Convert to HT
    $Devices = @{}
    foreach ($device in $DevicesRaw) {
        $Devices[$device.Id] = $device
    }

    return $Devices
}

function AuthCheckAzPSNative {
    $result = $true
    Write-host "[*] Checking access to ARM API"
    if ($null -ne $GLOBALArmAccessToken.access_token) {
        try {
            $url = 'https://management.azure.com/subscriptions?api-version=2022-12-01'
            $headers = @{
                'Authorization' = "Bearer $($GLOBALArmAccessToken.access_token)"
                'User-Agent' = $($GlobalAuditSummary.UserAgent.Name)
            }
            Invoke-RestMethod -Uri $url -Method GET -Headers $headers -erroraction 'Stop'
        } catch {
            write-host "[!] Auth error: $($_.Exception.Message -split '\n')"
            $result = $false
        }
    } else {
        Write-host "[i] Not yet authenticated"
        $result = $false
    }
    return $result
}


function checkSubscriptionNative {
    $result = $true

    $url = 'https://management.azure.com/subscriptions?api-version=2022-12-01'
    $headers = @{
        'Authorization' = "Bearer $($GLOBALArmAccessToken.access_token)"
        'User-Agent' = $($GlobalAuditSummary.UserAgent.Name)
    }
    $Subscription = Invoke-RestMethod -Uri $url -Method GET -Headers $headers -erroraction 'Stop'

    if ($Subscription.count.value -gt 0) {
        write-host "[+] User has access to $($Subscription.count.value) Subscription(s)."
        $GlobalAuditSummary.Subscriptions.Count = $Subscription.count.value
    } else {
        write-host "[-] User does not have access to a Subscription."
        $result = $false
    }
    return $result
}

#Function to perform MSGraph authentication using EntraTokenAid
function AuthenticationMSGraph {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][String[]]$AuthMethod
    )

    if ($AuthMethod -eq "AuthCode") {
        $tokens = Invoke-Auth -DisableJwtParsing @GLOBALAuthParameters
        $global:GLOBALMsGraphAccessToken = $tokens

    } elseif ($AuthMethod -eq "DeviceCode"){
        $tokens = Invoke-DeviceCodeFlow -DisableJwtParsing @GLOBALAuthParameters
        $global:GLOBALMsGraphAccessToken = $tokens

    } elseif ($AuthMethod -eq "ManualCode"){
        $tokens = Invoke-Auth -DisableJwtParsing -ManualCode @GLOBALAuthParameters
        $global:GLOBALMsGraphAccessToken = $tokens

    } else {
        Write-host "[!] Invalid AuthMethod provided"
    }

    if (AuthCheckMSGraph) {
        $result = $true
    } else {
        write-host "[!] Authentication failed (MS Graph)"
        $result = $false
    }

    return $result
}


function AuthenticationAzurePSNative {

    #Get tokens for Azure ARM API
    $GLOBAL:GLOBALArmAccessToken = Invoke-Refresh -RefreshToken $GLOBALMsGraphAccessToken.refresh_token -Api management.azure.com -DisableJwtParsing @GLOBALAuthParameters
    if (AuthCheckAzPSnative) {
        $result = $true
    } else {
        write-host "[!] Authentication failed (ARM API)"
        $result = $false
    }

return $result
}

#Refresh MS Graph session
function RefreshAuthenticationMsGraph {
    $result = $true
    $tokens = Invoke-Refresh -RefreshToken $GLOBALMsGraphAccessToken.refresh_token -DisableJwtParsing @GLOBALAuthParameters

    $global:GLOBALMsGraphAccessToken = $tokens

    if (AuthCheckMSGraph) {
        $result = $true
    } else {
        write-host "[!] Refresh failed"
        $result = $false
    }

    return $result
}

function Invoke-CheckTokenExpiration ($Object) {
    #write-host "[*] Checking MS Graph access token expiration... $($Object.Target)"
    $validForMinutes = [Math]::Ceiling((NEW-TIMESPAN -Start (Get-Date) -End $Object.Expiration_time).TotalMinutes)

    #Check if the token is valid for more than 15 minutes
    if ($validForMinutes -ge 30) {
        #write-host "[+] MS Graph Token is still valid for $validForMinutes minutes"
        $result = $true

    } elseif ($validForMinutes -le 30 -and $validForMinutes -ge 0) {
        write-host "[!] MS Graph Token will expire in $validForMinutes minutes"
        $result = $false
    } else {
        write-host "[!] MS Graph Token has expired $([Math]::Abs($validForMinutes)) minutes ago"
        $result = $false
    }
    return $result

}

#Rough Entra role rating (Tier level per role)
$global:GLOBALEntraRoleRating = @{
    "62e90394-69f5-4237-9190-012177145e10" = 0 #Global Administrator
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8" = 0 #Partner Tier2 Support
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = 0 #Privileged Authentication Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814" = 0 #Privileged Role Administrator
    "8329153b-31d0-4727-b945-745eb3bc5f31" = 0 #Domain Name Administrator
    "be2f45a1-457d-42af-a067-6ec1fa63bc45" = 0 #External Identity Provider Administrator
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2" = 0 #Hybrid Identity Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = 0 #Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7" = 0 #Cloud Application Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d" = 1 #Security Administrator
    "d29b2b05-8046-44ba-8758-1e26182fcf32" = 1 #Directory Synchronization Accounts
    "a92aed5d-d78a-4d16-b381-09adb37eb3b0" = 1 #On Premises Directory Sync Account
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" = 1 #Conditional Access Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f" = 1 #Authentication Administrator
    "e3973bdf-4987-49ae-837a-ba8e231c7286" = 1 #Azure DevOps Administrator
    "9360feb5-f418-4baa-8175-e2a00bac4301" = 1 #Directory Writers
    "29232cdf-9323-42fd-ade2-1d097af3e4de" = 1 #Exchange Administrator
    "fdd7a751-b60b-444a-984c-02652fe8fa1c" = 1 #Groups Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8" = 1 #Helpdesk Administrator
    "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e" = 1 #Identity Governance Administrator
    "3a2c62db-5318-420d-8d74-23affee5d9d5" = 1 #Intune Administrator
    "b5a8dcf3-09d5-43a9-a639-8e29ef291470" = 1 #Knowledge Administrator
    "744ec460-397e-42ad-a462-8b3f9747a02c" = 1 #Knowledge Manager
    "59d46f88-662b-457b-bceb-5c3809e5908f" = 1 #Lifecycle Workflows Administrator
    "4ba39ca4-527c-499a-b93d-d9b492c50246" = 1 #Partner Tier1 Support
    "966707d0-3269-4727-9be2-8c3a10f19b9d" = 1 #Password Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = 1 #SharePoint Administrator
    "69091246-20e8-4a56-aa4d-066075b2a7a8" = 1 #Teams Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1" = 1 #User Administrator
    "11451d60-acb2-45eb-a7d6-43d0f0125c13" = 1 #Windows 365 Administrator
    "810a2642-a034-447f-a5e8-41beaa378541" = 1 #Yammer Administrator
    "0526716b-113d-4c15-b2c8-68e3c22b9f80" = 2 #Authentication Policy Administrator
    "9f06204d-73c1-4d4c-880a-6edb90606fd8" = 2 #Azure AD Joined Device Local Administrator
    "7698a772-787b-4ac8-901f-60d6b08affd2" = 2 #Cloud Device Administrator
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451" = 2 #Global Reader
    "95e79109-95c0-4d8e-aee3-d01accf2d47b" = 2 #Guest Inviter
    "5d6b6bb7-de71-4623-b4af-96380a352509" = 2 #Security Reader
    "88d8e3e3-8f55-4a1e-953a-9b9898b8876b" = 2 #Directory Readers
}

#Rough Entra role rating (Tier level per role)
$global:GLOBALAzureRoleRating = @{
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" = 0 #Owner
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" = 0 #User Access Administrator
    "b24988ac-6180-42a0-ab88-20f7382dd24c" = 0 #Contributor
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168" = 0 #Role Based Access Control Administrator
    "a8889054-8d42-49c9-bc1c-52486c10e7cd" = 0 #Reservations Administrator
    "fb1c8493-542b-48eb-b624-b4c8fea62acd" = 1 #Security Admin
    "9980e02c-c2be-4d73-94e8-173b1dc7cf3c" = 1 #Virtual Machine Contributor
    "66f75aeb-eabe-4b70-9f1e-c350c4c9ad04" = 1 #Virtual Machine Data Access Administrator
    "1c0163c0-47e6-4577-8991-ea5c82e286e4" = 1 #Virtual Machine Administrator Login
    "a6333a3e-0164-44c3-b281-7a577aff287f" = 1 #Windows Admin Center Administrator Login
    "3bc748fc-213d-45c1-8d91-9da5725539b9" = 1 #Container Registry Contributor and Data Access Configuration Administrator
    "00482a5a-887f-4fb3-b363-3b7fe8e74483" = 1 #Key Vault Administrator
    "8b54135c-b56d-4d72-a534-26097cfdc8d8" = 1 #Key Vault Data Access Administrator
    "b86a8fe4-44ce-4948-aee5-eccb2c155cd7" = 1 #Key Vault Secrets Officer
    "4633458b-17de-408a-b874-0445c86b69e6" = 1 #Key Vault Secrets User
    "3498e952-d568-435e-9b2c-8d77e338d7f7" = 1 #Azure Kubernetes Service RBAC Admin
    "b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b" = 1 #Azure Kubernetes Service RBAC Cluster Admin
    "dffb1e0c-446f-4dde-a09f-99eb5cc68b96" = 1 #Azure Arc Kubernetes Admin
    "8393591c-06b9-48a2-a542-1bd6b377f6a2" = 1 #Azure Arc Kubernetes Cluster Admin
    "b748a06d-6150-4f8a-aaa9-ce3940cd96cb" = 1 #Azure Arc VMware VM Contributor
    "17d1049b-9a84-46fb-8f53-869881c3d3ab" = 1 #Storage Account Contributor
    "acdd72a7-3385-48ef-bd42-f606fba81ae7" = 2 #Reader
    "39bc4728-0917-49c7-9d2c-d95423bc2eb4" = 2 #SecurityReader
    "fb879df8-f326-4884-b1cf-06f3ad86be52" = 3 #Virtual Machine User Login
    "1d18fff3-a72a-46b5-b4a9-0b38a3cd7e63" = 3 #Desktop Virtualization User
}

$global:GLOBALImpactScore = @{
    "EntraRoleTier0"            = 800
    "EntraRoleTier1"            = 400
    "EntraRoleTier2"            = 80
    "EntraRoleTier?Privileged"  = 100
    "EntraRoleTier?"            = 80
    "AzureRoleTier0"            = 200
    "AzureRoleTier1"            = 100
    "AzureRoleTier2"            = 50
    "AzureRoleTier3"            = 10
    "AzureRoleTier?"            = 50
}

$global:GLOBALApiPermissionCategorizationList= @{
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" = "Dangerous" #RoleManagement.ReadWrite.Directory
    "06b708a9-e830-4db3-a914-8e69da51d44f" = "Dangerous" #AppRoleAssignment.ReadWrite.All
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" = "Dangerous" #Application.ReadWrite.All
    "dd199f4a-f148-40a4-a2ec-f0069cc799ec" = "Dangerous" #RoleAssignmentSchedule.ReadWrite.Directory
    "41202f2c-f7ab-45be-b001-85c9728b9d69" = "Dangerous" #PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup
    "2f6817f8-7b12-4f0f-bc18-eeaf60705a9e" = "Dangerous" #PrivilegedAccess.ReadWrite.AzureADGroup
    "fee28b28-e1f3-4841-818e-2704dc62245f" = "Dangerous" #RoleEligibilitySchedule.ReadWrite.Directory
    "618b6020-bca8-4de6-99f6-ef445fa4d857" = "Dangerous" #PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup
    "7e05723c-0bb0-42da-be95-ae9f08a6e53c" = "Dangerous" #Domain.ReadWrite.All
    "ab43b826-2c7a-4aff-9ecd-d0629d0ca6a9" = "High" #ADSynchronization.ReadWrite.All
    "9acd699f-1e81-4958-b001-93b1d2506e19" = "High" #EntitlementManagement.ReadWrite.All
    "292d869f-3427-49a8-9dab-8c70152b74e9" = "High" #Organization.ReadWrite.All
    "a402ca1c-2696-4531-972d-6e5ee4aa11ea" = "High" #Policy.ReadWrite.PermissionGrant
    "b38dcc4d-a239-4ed6-aa84-6c65b284f97c" = "High" #RoleManagementPolicy.ReadWrite.AzureADGroup
    "31e08e0a-d3f7-4ca2-ac39-7343fb83e8ad" = "High" #RoleManagementPolicy.ReadWrite.Directory
    "29c18626-4985-4dcd-85c0-193eef327366" = "High" #Policy.ReadWrite.AuthenticationMethod"
    "eccc023d-eccf-4e7b-9683-8813ab36cecc" = "High" #User.DeleteRestore.All
    "3011c876-62b7-4ada-afa2-506cbbecc68c" = "High" #User.EnableDisableAccount.All
    "8e8e4742-1d95-4f68-9d56-6ee75648c72a" = "High" #DelegatedPermissionGrant.ReadWrite.All
    "01c0a623-fc9b-48e9-b794-0756f8e8f067" = "High" #Policy.ReadWrite.ConditionalAccess
    "9241abd9-d0e6-425a-bd4f-47ba86e767a4" = "High" #DeviceManagementConfiguration.ReadWrite.All
    "e330c4f0-4170-414e-a55a-2f022ec2b57b" = "High" #DeviceManagementRBAC.ReadWrite.Al
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7" = "High" #Directory.ReadWrite.All
    "62a82d76-70ea-41e2-9197-370581804d09" = "High" #Group.ReadWrite.All
    "dbaae8cf-10b5-4b86-a4a1-f871c94c6695" = "High" #GroupMember.ReadWrite.All
    "50483e42-d915-4231-9639-7fdb7fd190e5" = "High" #UserAuthenticationMethod.ReadWrite.All
    "cc117bb9-00cf-4eb8-b580-ea2a878fe8f7" = "High" #User-PasswordProfile.ReadWrite.All
    "a82116e5-55eb-4c41-a434-62fe8a61c773" = "High" #Sites.FullControl.All
    "678536fe-1083-478a-9c59-b99265e6b0d3" = "High" #Sites.FullControl.All SharePointAPI
    "9bff6588-13f2-4c48-bbf2-ddab62256b36" = "High" #Sites.Manage.All SharePointAPI
    "d13f72ca-a275-4b96-b789-48ebcc4da984" = "High" #Sites.Read.All SharePointAPI
    "fbcd29d2-fcca-4405-aded-518d457caae4" = "High" #Sites.ReadWrite.All SharePointAPI
    "0c0bf378-bf22-4481-8f81-9e89a9b4960a" = "High" #Sites.Manage.All
    "332a536c-c7ef-4017-ab91-336970924f0d" = "High" #Sites.Read.All
    "9492366f-7969-46a4-8d15-ed1a20078fff" = "High" #Sites.ReadWrite.All
    "01d4889c-1287-42c6-ac1f-5d1e02578ef6" = "High" #Files.Read.All
    "75359482-378d-4052-8f01-80520e7db3cd" = "High" #Files.ReadWrite.All
    "db51be59-e728-414b-b800-e0f010df1a79" = "High" #DeviceLocalCredential.Read.All
    "5eb59dd3-1da2-4329-8733-9dabdc435916" = "High" #AdministrativeUnit.ReadWrite.All
    "741f803b-c850-494e-b5df-cde7c675a1ca" = "Medium" #User.ReadWrite.All
    "6b7d71aa-70aa-4810-a8d9-5d9fb2830017" = "Medium" #Chat.Read.All
    "294ce7c9-31ba-490a-ad7d-97a7d075e4ed" = "Medium" #Chat.ReadWrite.All
    "ef54d2bf-783f-4e0f-bca1-3210c0444d99" = "Medium" #Calendars.ReadWrite
    "810c84a8-4a9e-49e6-bf7d-12d183f40d01" = "Medium" #Mail.Read
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9" = "Medium" #Mail.ReadWrite
    "b633e1c5-b582-4048-a93e-9f11b44c7e96" = "Medium" #Mail.Send
    "b8bb2037-6e08-44ac-a4ea-4674e010e2a4" = "Medium" #OnlineMeetings.ReadWrite.All
    "de89b5e4-5b8f-48eb-8925-29c2b33bd8bd" = "Medium" #CustomSecAttributeAssignment.ReadWrite.All
    "89c8469c-83ad-45f7-8ff2-6e3d4285709e" = "Medium" #ServicePrincipalEndpoint.ReadWrite.All (Still an issue?)
}

$global:GLOBALDelegatedApiPermissionCategorizationList= @{
    "RoleManagement.ReadWrite.Directory" = "Dangerous" #d01b97e9-cbc0-49fe-810a-750afd5527a3
    "AppRoleAssignment.ReadWrite.All" = "Dangerous" #84bccea3-f856-4a8a-967b-dbe0a3d53a64
    "Application.ReadWrite.All" = "Dangerous" #bdfbf15f-ee85-4955-8675-146e8e5296b5
    "RoleAssignmentSchedule.ReadWrite.Directory" = "Dangerous" #8c026be3-8e26-4774-9372-8d5d6f21daff
    "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup" = "Dangerous" #06dbc45d-6708-4ef0-a797-f797ee68bf4b
    "PrivilegedAccess.ReadWrite.AzureADGroup" = "Dangerous" #32531c59-1f32-461f-b8df-6f8a3b89f73b
    "RoleEligibilitySchedule.ReadWrite.Directory" = "Dangerous" #62ade113-f8e0-4bf9-a6ba-5acb31db32fd
    "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup" = "Dangerous" #ba974594-d163-484e-ba39-c330d5897667
    "Domain.ReadWrite.All" = "Dangerous" #0b5d694c-a244-4bde-86e6-eb5cd07730fe
    "EntitlementManagement.ReadWrite.All" = "High" #ae7a573d-81d7-432b-ad44-4ed5c9d89038
    "Organization.ReadWrite.All" = "High" #46ca0847-7e6b-426e-9775-ea810a948356
    "Policy.ReadWrite.PermissionGrant" = "High" #2672f8bb-fd5e-42e0-85e1-ec764dd2614e
    "RoleManagementPolicy.ReadWrite.AzureADGroup" = "High" #0da165c7-3f15-4236-b733-c0b0f6abe41d
    "RoleManagementPolicy.ReadWrite.Directory" = "High" #1ff1be21-34eb-448c-9ac9-ce1f506b2a68
    "Policy.ReadWrite.AuthenticationMethod" = "High" #7e823077-d88e-468f-a337-e18f1f0e6c7c
    "User.DeleteRestore.All" = "High" #4bb440cd-2cf2-4f90-8004-aa2acd2537c5
    "User.EnableDisableAccount.All" = "High" #f92e74e7-2563-467f-9dd0-902688cb5863
    "DelegatedPermissionGrant.ReadWrite.All" = "High" #41ce6ca6-6826-4807-84f1-1c82854f7ee5
    "Policy.ReadWrite.ConditionalAccess" = "High" #ad902697-1014-4ef5-81ef-2b4301988e8c
    "DeviceManagementConfiguration.ReadWrite.All" = "High" #0883f392-0a7a-443d-8c76-16a6d39c7b63
    "DeviceManagementRBAC.ReadWrite.All" = "High" #0c5e8a55-87a6-4556-93ab-adc52c4d862d
    "Directory.ReadWrite.All" = "High" #c5366453-9fb0-48a5-a156-24f0c49a4b84
    "User-PasswordProfile.ReadWrite.All" = "High" #56760768-b641-451f-8906-e1b8ab31bca7
    "Group.ReadWrite.All" = "High" #4e46008b-f24c-477d-8fff-7bb4ec7aafe0
    "GroupMember.ReadWrite.All" = "High" #f81125ac-d3b7-4573-a3b2-7099cc39df9e
    "UserAuthenticationMethod.ReadWrite.All" = "High" #b7887744-6746-4312-813d-72daeaee7e2d
    "Sites.FullControl.All" = "High" #5a54b8b3-347c-476d-8f8e-42d5c7424d29
    "Sites.Manage.All" = "High" #65e50fdc-43b7-4915-933e-e8138f11f40a
    "Sites.Read.All" = "High" #205e70e5-aba6-4c52-a976-6d2d46c48043
    "Sites.ReadWrite.All" = "High" #89fe6a52-be36-487e-b7d8-d061c450a026
    "Files.Read.All" = "High" #df85f4d6-205c-4ac5-a5ea-6bf408dba283
    "Files.ReadWrite.All" = "High" #863451e7-0667-486c-a5d6-d135439485f0
    "DeviceLocalCredential.Read.All" = "High" #9917900e-410b-4d15-846e-42a357488545
    "AdministrativeUnit.ReadWrite.All" = "High" #7b8a2d34-6b3f-4542-a343-54651608ad81
    "User.ReadWrite.All" = "Medium" #204e0828-b5ca-4ad8-b9f3-f32a958e7cc4
    "Chat.ReadWrite.All" = "Medium" #7e9a077b-3711-42b9-b7cb-5fa5f3f7fea7
    "Mail.Read" = "Medium" #570282fd-fa5c-430d-a7fd-fc8dc98a9dca
    "Mail.ReadWrite" = "Medium" #024d486e-b451-40bb-833d-3e66d98c5c73
    "Mail.Send" = "Medium" #e383f46e-2787-4529-855e-0e479a3ffac0
    "CustomSecAttributeAssignment.ReadWrite.All" = "Medium" #ca46335e-8453-47cd-a001-8459884efeae
    "ServicePrincipalEndpoint.ReadWrite.All" = "Medium" #7297d82c-9546-4aed-91df-3d4f0a9b3ff0
    "BitlockerKey.Read.All" = "Medium" #b27a61ec-b99c-4d6a-b126-c4375d08ae30
    "Calendars.Read" = "Medium" #465a38f9-76ea-45b9-9f34-9e8b0d4b0b42
    "Calendars.Read.Shared" = "Medium" #2b9c4092-424d-4249-948d-b43879977640
    "Calendars.ReadWrite" = "Medium" #1ec239c2-d7c9-4623-a91a-a9775856bb36
    "Calendars.ReadWrite.Shared" = "Medium" #12466101-c9b8-439a-8589-dd09ee67e8e9
    "ChannelMessage.ReadWrite" = "Medium" #5922d31f-46c8-4404-9eaf-2117e390a8a4
    "ChannelMessage.Send" = "Medium" #ebf0f66e-9fb1-49e4-a278-222f76911cf4
    "Chat.ReadWrite" = "Medium" #9ff7295e-131b-4d94-90e1-69fde507ac11
    "Directory.AccessAsUser.All" = "Medium" #0e263e50-5827-48a4-b97c-d940288653c7
    "Directory.Read.All" = "Medium" #06da0dbc-49e2-44d2-8312-53f166ab848a
    "Files.ReadWrite" = "Medium" #5c28f0bf-8a70-41f1-8ab2-9032436ddb65
    "MailboxItem.ImportExport" = "Medium" #df96e8a0-f4e1-4ecf-8d83-a429f822cbd6
    "offline_access" = "Medium" #7427e0e9-2fba-42fe-b0c0-848c9e6a8182
    "openid" = "Low" #37f7f235-527c-4136-accd-4a02d197296e
    "email" = "Low" #64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0
    "profile" = "Low" #14dad69e-099b-42c9-810b-d002981feec1
    "User.Read" = "Low" #14dad69e-099b-42c9-810b-d002981feec1
}

#Store the MS Tenant IDs in an array to check if an Enterprise Application is a Microsoft app
$global:GLOBALMsTenantIds = @("f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47", "33e01921-4d64-4f8c-a055-5bdaffd5e33d", "cdc5aeea-15c5-4db6-b079-fcadd2505dc2")

#Function to rate Entra ID role assignments and generate the warning message
function Invoke-EntraRoleProcessing {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$RoleDetails
    )

        #Process Entra Role assignments
        $ImpactScore = 0
        $Tier0Count = 0
        $Tier1Count = 0
        $Tier2Count = 0
        $UnknownTierCount = 0
        $roleSummary = ""

        foreach ($Role in $RoleDetails) {
            switch ($Role.RoleTier) {
                0 {
                    $ImpactScore += $GLOBALImpactScore["EntraRoleTier0"]
                    $Tier0Count++
                    break
                }
                1 {
                    $ImpactScore += $GLOBALImpactScore["EntraRoleTier1"]
                    $Tier1Count++
                    break
                }
                2 {
                    $ImpactScore += $GLOBALImpactScore["EntraRoleTier2"]
                    $Tier2Count++
                    break
                }
                default {
                    $UnknownTierCount++
                    if ($Role.IsPrivileged) {
                        $ImpactScore += $GLOBALImpactScore["EntraRoleTier?Privileged"]
                    } else {
                        $ImpactScore += $GLOBALImpactScore["EntraRoleTier?"]
                    }
                    break
                }
            }
        }

        # Build role description parts
        $roleParts = @()
        if ($Tier0Count -ge 1) { $roleParts += "$Tier0Count (Tier0)" }
        if ($Tier1Count -ge 1) { $roleParts += "$Tier1Count (Tier1)" }
        if ($Tier2Count -ge 1) { $roleParts += "$Tier2Count (Tier2)" }
        if ($UnknownTierCount -ge 1) { $roleParts += "$UnknownTierCount (Tier?)" }
        if (($Tier0Count + $Tier1Count + $Tier2Count + $UnknownTierCount) -ge 2) {
            $word = "roles"
        } else {
            $word = "role"
        }
        # If not already handled, create summary
        if ($roleParts.Count -gt 0) {
            $roleSummary = ($roleParts -join ", ") + " Entra "+$word+" assigned"
        }

        return [PSCustomObject]@{
            ImpactScore = $ImpactScore
            Warning     = $roleSummary
        }
}

#Function to rate Entra ID role assignments and generate the warning message
function Invoke-AzureRoleProcessing {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$RoleDetails
    )

        #Process Entra Role assignments
        $ImpactScore = 0
        $Tier0Count = 0
        $Tier1Count = 0
        $Tier2Count = 0
        $Tier3Count = 0
        $UnknownTierCount = 0
        $roleSummary = ""

        foreach ($Role in $RoleDetails) {
            switch ($Role.RoleTier) {
                0 {
                    $ImpactScore += $GLOBALImpactScore["AzureRoleTier0"]
                    $Tier0Count++
                    break
                }
                1 {
                    $ImpactScore += $GLOBALImpactScore["AzureRoleTier1"]
                    $Tier1Count++
                    break
                }
                2 {
                    $ImpactScore += $GLOBALImpactScore["AzureRoleTier2"]
                    $Tier2Count++
                    break
                }
                3 {
                    $ImpactScore += $GLOBALImpactScore["AzureRoleTier3"]
                    $Tier3Count++
                    break
                }
                default {
                    $UnknownTierCount++
                    if ($Role.IsPrivileged) {
                        $ImpactScore += $GLOBALImpactScore["AzureRoleTier?Privileged"]
                    } else {
                        $ImpactScore += $GLOBALImpactScore["AzureRoleTier?"]
                    }
                    break
                }
            }
        }

        # Build role description parts
        $roleParts = @()
        if ($Tier0Count -ge 1) { $roleParts += "$Tier0Count (Tier0)" }
        if ($Tier1Count -ge 1) { $roleParts += "$Tier1Count (Tier1)" }
        if ($Tier2Count -ge 1) { $roleParts += "$Tier2Count (Tier2)" }
        if ($Tier3Count -ge 1) { $roleParts += "$Tier3Count (Tier3)" }
        if ($UnknownTierCount -ge 1) { $roleParts += "$UnknownTierCount (Tier?)" }
        if (($Tier0Count + $Tier1Count + $Tier2Count + $UnknownTierCount) -ge 2) {
            $word = "roles"
        } else {
            $word = "role"
        }
        # If not already handled, create summary
        if ($roleParts.Count -gt 0) {
            $roleSummary = ($roleParts -join ", ") + " Azure "+$word+" assigned"
        }

        return [PSCustomObject]@{
            ImpactScore = $ImpactScore
            Warning     = $roleSummary
        }
}


# Function to get Azure IAM assignments
function Get-AllAzureIAMAssignmentsNative {
    [CmdletBinding()]
    param()

    Write-Host "[*] Get Azure IAM assignments"

    $IamAssignmentsHT = @{}
    $assignmentsEligible = @()
    $seenAssignments = New-Object System.Collections.Generic.HashSet[System.String]
    $headers = @{
        'Authorization' = "Bearer $($GLOBALArmAccessToken.access_token)"
        'User-Agent' = $($GlobalAuditSummary.UserAgent.Name)
    }

    #Retrieve role assignments for each subscription and filter by scope
    $url = 'https://management.azure.com/subscriptions?api-version=2022-12-01'
    $response = Invoke-RestMethod -Uri $url -Method GET -Headers $headers -erroraction 'Stop'
    $subscriptions = $response.value | ForEach-Object {
        [PSCustomObject]@{
            Id          = $_.subscriptionId
            displayName  = $_.displayName
            managedByTenants  = $_.managedByTenants
        }
    }

    foreach ($subscription in $subscriptions) {
        #Get all Azure roles for lookupp
        $url = "https://management.azure.com/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
        $response = Invoke-RestMethod -Uri $url -Method GET -Headers $headers
        $roleHashTable = @{}
        $response.value | ForEach-Object {
            # Extract RoleName and ObjectId
            $roleName = $_.properties.RoleName
            $RoleType = $_.properties.type
            $objectId = ($_.id -split '/')[-1]

            # Store the values in the hashtable (ObjectId as the key, RoleName as the value)
            $roleHashTable[$objectId] = @{
                RoleName = $roleName
                RoleType = $roleType
                RoleId   = $objectId
            }
        }

        #Get all custom roles and add them to the HT
        $url = "https://management.azure.com/providers/Microsoft.Authorization/roleDefinitions?`$filter=type+eq+'CustomRole'&api-version=2022-04-01"
        $response = Invoke-RestMethod -Uri $url -Method GET -Headers $headers

        $response.value | ForEach-Object {
            # Extract RoleName and ObjectId
            $roleName = $_.properties.RoleName
            $RoleType = $_.properties.type
            $objectId = ($_.id -split '/')[-1]

            # Store the values in the hashtable (ObjectId as the key, RoleName as the value)
            $roleHashTable[$objectId] = @{
                RoleName = $roleName
                RoleType = $roleType
                RoleId   = $objectId
            }
        }

        #Active Roles
        $url = "https://management.azure.com/subscriptions/$($subscription.Id)/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
        $response = Invoke-RestMethod -Uri $url -Method GET -Headers $headers
        $AssignmentsActive = $response.value | ForEach-Object {
            $RoleDetails = $roleHashTable[(($_.properties.roleDefinitionId -split '/')[-1])]
            $hasCondition = ($null -ne $_.properties.condition -and $_.properties.condition.Trim() -ne "")
            if ($GLOBALAzureRoleRating.ContainsKey($RoleDetails.RoleId)) {
                # If the RoleDefinition ID is found, return it's Tier-Level
                $RoleTier = $GLOBALAzureRoleRating[$RoleDetails.RoleId]
            } else {
                # Set to ? if not assigned to a tier level
                $RoleTier = "?"
            }
            [PSCustomObject]@{
                ObjectId           = $_.properties.principalId
                RoleDefinitionName = $RoleDetails.RoleName
                RoleType           = $RoleDetails.RoleType
                RoleTier           = $RoleTier
                Scope              = $_.properties.scope
                Conditions         = $hasCondition
                PrincipalType      = $_.properties.principalType
                AssignmentType     = "Active"
            }
        }

        #Eligible Roles
        # If HTTP 400 assuing error message is "The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license.",
        $AzurePIM = $true
        try {
            $url = "https://management.azure.com/subscriptions/$($subscription.Id)/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01-preview"
            $response = Invoke-RestMethod -Uri $url -Method GET -Headers $headers
        } catch {
            if ($($_.Exception.Message) -match "400") {
                write-host "[!] HTTP 400 Error: Most likely due to missing Entra ID premium licence. Assuming no PIM for Azure is used."
            } else {
                write-host "[!] Auth error: $($_.Exception.Message)"
            }
            $AzurePIM = $false
        }
        if ($AzurePIM) {
            $AssignmentsEligible = $response.value | ForEach-Object {
                $RoleDetails = $roleHashTable[(($_.properties.roleDefinitionId -split '/')[-1])]
                $hasCondition = ($null -ne $_.properties.condition -and $_.properties.condition.Trim() -ne "")
                if ($GLOBALAzureRoleRating.ContainsKey($RoleDetails.RoleId)) {
                    # If the RoleDefinition ID is found, return it's Tier-Level
                    $RoleTier = $GLOBALAzureRoleRating[$RoleDetails.RoleId]
                } else {
                    # Set to ? if not assigned to a tier level
                    $RoleTier = "?"
                }
                [PSCustomObject]@{
                    ObjectId          = $_.properties.principalId
                    RoleDefinitionName = $RoleDetails.RoleName
                    RoleType           = $RoleDetails.RoleType
                    RoleTier           = $RoleTier
                    Scope              = $_.properties.scope
                    Conditions         = $hasCondition
                    PrincipalType      = $_.properties.principalType
                    AssignmentType     = "Eligible"
                }
            }
        }


        $AllAssignments = $AssignmentsActive + $assignmentsEligible
        foreach ($assignment in $AllAssignments) {
            # Create a unique key for each role assignment
            $uniqueKey = "$($assignment.ObjectId)|$($assignment.RoleDefinitionName)|$($assignment.Scope)|$($assignment.AssignmentType)"

            # Check if the role assignment has already been processed
            if (-not $seenAssignments.Contains($uniqueKey)) {
                # Add the key to the HashSet to mark it as seen
                $seenAssignments.Add($uniqueKey) | Out-Null

                # Ensure the ObjectId exists in the hashtable
                if (-not $IamAssignmentsHT.ContainsKey($assignment.ObjectId)) {
                    $IamAssignmentsHT[$assignment.ObjectId] = @()
                }

                # Add the assignment to the hashtable
                $IamAssignmentsHT[$assignment.ObjectId] += [PSCustomObject]@{
                    RoleDefinitionName = $assignment.RoleDefinitionName
                    Scope = $assignment.Scope
                    RoleType = $assignment.RoleType
                    RoleTier = $assignment.RoleTier
                    Conditions = $assignment.Conditions
                    PrincipalType = $assignment.PrincipalType
                    AssignmentType = $assignment.AssignmentType
                }
            }
        }
    }

    return $IamAssignmentsHT
}

# Function to check the Azure IAM role assignments for the input object
function Get-AzureRoleDetails {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$AzureIAMAssignments,
        [Parameter(Mandatory = $true)]
        [string]$ObjectId
    )

    $azureRoleDetails = @()

    # Filtering assignments based on ObjectType and the associated IDs
    if ($AzureIAMAssignments.ContainsKey($ObjectId)) {
        # Key exists, retrieve its value
        $matchingAzureRoles = $AzureIAMAssignments[$ObjectId]
        foreach ($role in $matchingAzureRoles) {
            $roleInfo = [PSCustomObject]@{
                RoleName = $role.RoleDefinitionName
                RoleType = $role.RoleType
                Scope    = $role.Scope
                Conditions = $role.Conditions
                RoleTier = $role.RoleTier
                AssignmentType  = $role.AssignmentType
            }
            $azureRoleDetails += $roleInfo
        }
    }

    return $azureRoleDetails
}


# Function to get user details for PIM fro groups eligible assignments
function Get-PIMForGroupsAssignmentsDetails {
    param (
        [Parameter(Mandatory = $true)]
        [array]$TenantPimForGroupsAssignments
    )

    foreach ($item in $TenantPimForGroupsAssignments) {

        $principalId = $item.principalId

        # Lookup displayname and object type for each object
        $ObjectInfo = Get-ObjectInfo $principalId

        if ($ObjectInfo) {
            # Add properties to the matching entry
            $TenantPimForGroupsAssignments | ForEach-Object {
                if ($_.principalId -eq $principalId) {
                    $_ | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $ObjectInfo.DisplayName -Force
                    $_ | Add-Member -MemberType NoteProperty -Name "Type" -Value $ObjectInfo.Type -Force
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'UserPrincipalName') {$_ | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value $ObjectInfo.UserPrincipalName -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'AccountEnabled') {$_ | Add-Member -MemberType NoteProperty -Name "AccountEnabled" -Value $ObjectInfo.AccountEnabled -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'UserType') {$_ | Add-Member -MemberType NoteProperty -Name "UserType" -Value $ObjectInfo.UserType -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'OnPremisesSyncEnabled') {$_ | Add-Member -MemberType NoteProperty -Name "OnPremisesSyncEnabled" -Value $ObjectInfo.OnPremisesSyncEnabled -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'Department') {$_ | Add-Member -MemberType NoteProperty -Name "Department" -Value $ObjectInfo.Department -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'JobTitle') {$_ | Add-Member -MemberType NoteProperty -Name "JobTitle" -Value $ObjectInfo.JobTitle -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'SecurityEnabled') {$_ | Add-Member -MemberType NoteProperty -Name "SecurityEnabled" -Value $ObjectInfo.SecurityEnabled -Force}
                    if ($ObjectInfo.PSObject.Properties.Name -contains 'IsAssignableToRole') {$_ | Add-Member -MemberType NoteProperty -Name "IsAssignableToRole" -Value $ObjectInfo.IsAssignableToRole -Force}
                }
            }
        }
    }
    return $TenantPimForGroupsAssignments
}

# Function to get all administrative units
function Get-AdministrativeUnitsWithMembers {
    Write-Host "[*] Get Administrative units with members"
    $QueryParameters = @{
        '$select' = "Id,DisplayName,IsMemberManagementRestricted"
    }
    $AdminUnits = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/directory/administrativeUnits" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    $AdminUnitWithMembers = foreach ($AdminUnit in $AdminUnits) {

        # Retrieve members of the current administrative unit
        $Members = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/directory/administrativeUnits/$($AdminUnit.Id)/members" -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

        $MembersUser = $Members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user'} | Select-Object id,@{n='Type';e={'User'}},displayName
        $MembersGroup = $Members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group'}  | Select-Object id,@{n='Type';e={'Group'}},displayName
        $MembersDevices = $Members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.device'} | Select-Object id,@{n='Type';e={'Device'}},displayName

        # Create a custom object for the administrative unit with its members
        [pscustomobject]@{
            AuId                            = $AdminUnit.Id
            DisplayName                     = $AdminUnit.Displayname
            IsMemberManagementRestricted    = $AdminUnit.IsMemberManagementRestricted
            MembersUser                     = $MembersUser
            MembersGroup                    = $MembersGroup
            MembersDevices                  = $MembersDevices
        }
    }

    $AuCount = $($AdminUnitWithMembers | Measure-Object).Count

    #Add information to the enumeration summary
    $GlobalAuditSummary.AdministrativeUnits.Count = $AuCount

    Write-Host "[+] Got $AuCount Administrative units with members"
    Return $AdminUnitWithMembers
}

# Get Conditional Access Policies with user and group relations
function Get-ConditionalAccessPolicies {

    Write-Host "[*] Get Conditional Access Policies"
    $Caps = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/identity/conditionalAccess/policies" -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    if ($Caps) {
        $CapsCount = $($Caps | Measure-Object).Count
        Write-Host "[+] Got $CapsCount Conditional Access Policies"
        $CapGroups = foreach ($cap in $Caps) {
            $excludedGroups = $cap.Conditions.Users.ExcludeGroups
            $includedGroups = $cap.Conditions.Users.IncludeGroups
            $ExcludeUsers = $cap.Conditions.Users.ExcludeUsers
            $IncludeUsers = $cap.Conditions.Users.IncludeUsers
            [PSCustomObject]@{
                Id = $cap.Id
                CAPName = $cap.DisplayName
                ExcludedGroup = $excludedGroups
                IncludedGroup = $includedGroups
                ExcludedUser = $ExcludeUsers
                IncludedUser = $IncludeUsers
                CAPStatus = $cap.State
            }
        }
        $global:GLOBALPermissionForCaps = $true
    } else {
        Write-Host "[!] No Conditional Access Policies found."
        $GroupScriptWarningList += "Group CAPs assignments were not assessed"
        $global:GLOBALPermissionForCaps = $false
    }
    Return $CapGroups
}

#Authenticate using an ARM Refresh token and get a new token for PIM
function Invoke-MsGraphAuthPIM {

    write-host "[*] Refresh to Managed Meeting Rooms client"
    #Alternative: 50aaa389-5a33-4f1a-91d7-2c45ecd8dac8 (Azure PIM)
    $global:GLOBALPIMsGraphAccessToken = Invoke-Refresh -RefreshToken $GLOBALMsGraphAccessToken.refresh_token -clientid "eb20f3e3-3dce-4d2c-b721-ebb8d4414067" -DisableJwtParsing @GLOBALAuthParameters

    #Abort if error
    if ($GLOBALPIMsGraphAccessToken) {
        if (AuthCheckMSGraph) {
            write-host "[+] MS Graph session OK"
            $result = $true
            $global:GLOBALGraphExtendedChecks = $true

        } else {
            Write-host "[!] Authentication with Managed Meeting Rooms client failed"
            $result = $false
            $global:GLOBALGraphExtendedChecks = $false
        }
    } else {
        write-host "[!] PIM Data will not be collected"
        $global:GLOBALGraphExtendedChecks = $false
        $result = $false
    }
    return $result
}


#Get all active Entra role assignments
function Get-EntraPIMRoleAssignments {

    Write-Host "[*] Get PIM Entra role assignments"

    $TenantPIMRoleAssignments = @()

    #Ugly workaround since $_.RoleDefinition.IsPrivileged is always empty :-(
    $EntraroleDefinitions = @{}
    # Get the role definitions and populate the array

    # Get all roleassignments and store as HT
    $QueryParameters = @{
        '$select' = "Id,IsPrivileged"
    }
    $TenantRoleDefinitions= Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/roleManagement/directory/roleDefinitions" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)
    foreach ($role in $TenantRoleDefinitions) {
        $EntraroleDefinitions[$role.Id] = $role.IsPrivileged
    }

    try {
        # Get all PIM for Roles assignments
        $QueryParameters = @{
            '$select' = "PrincipalId,DirectoryScopeId,RoleDefinition,RoleDefinitionId,ScheduleInfo"
            '$expand' = "RoleDefinition"
        }
        $PimRoles = Send-GraphRequest -AccessToken $GLOBALPIMsGraphAccessToken.access_token -Method GET -Uri "/roleManagement/directory/roleEligibilitySchedules" -QueryParameters $QueryParameters -BetaAPI  -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop

    } catch {
        write-host "[!] Failed to get PIM role assignments. Tenant might be not be licenced for PIM. Details:"
        write-host $($_.Exception.Message)
        Return
    }

    $PimRoles | ForEach-Object {
        $ScopeResolved = $null

        # Resolve the DirectoryScopeId
        if ($_.DirectoryScopeId -eq "/") {
            $ScopeResolved = [PSCustomObject]@{
                DisplayName = "/"
                Type        = "Tenant"
            }
        } elseif ($($_.DirectoryScopeId).Contains("administrativeUnits")) {
            $ObjectID = $_.DirectoryScopeId.Replace("/administrativeUnits/", "")
            $ScopeResolved = Get-ObjectInfo $ObjectID AdministrativeUnit
        } else {
            $ObjectID = $_.DirectoryScopeId.Replace("/", "")
            $ScopeResolved = Get-ObjectInfo $ObjectID
        }

        if ($GLOBALEntraRoleRating.ContainsKey($_.RoleDefinition.Id)) {
            # If the RoleDefinition ID is found, return it's Tier-Level
            $RoleTier = $GLOBALEntraRoleRating[$_.RoleDefinition.Id]
        } else {
            # Set to ? if not assigned to a tier level
            $RoleTier = "?"
        }


        # Add the role assignment to the array
        $TenantPIMRoleAssignments += [PSCustomObject]@{
            PrincipalId     = $_.PrincipalId
            AssignmentType  = "Eligible"
            DirectoryScopeId = $_.DirectoryScopeId
            RoleDefinitionId  = $_.RoleDefinition.Id
            DisplayName      = $_.RoleDefinition.DisplayName
            IsPrivileged     = $EntraroleDefinitions[$_.RoleDefinition.Id]
            RoleTier         = $RoleTier
            IsEnabled        = $_.RoleDefinition.IsEnabled
            IsBuiltIn        = $_.RoleDefinition.IsBuiltIn
            StartTime        = $_.ScheduleInfo.StartDateTime
            ExpiryDate       = if ($_.ScheduleInfo.Expiration.EndDateTime) {$_.ScheduleInfo.Expiration.EndDateTime} else {"noExpiration"}
            ScopeResolved    = ($ScopeResolved | select-object DisplayName,Type)
        }

    }
    Write-Host "[+] Got $($TenantPIMRoleAssignments.Count) PIM eligible Entra role assignments"
    Return $TenantPIMRoleAssignments
}

#Get all active Entra role assignments
function Get-EntraRoleAssignments {
    param (
        [Parameter(Mandatory = $false)]
        [array]$TenantPimRoleAssignments
    )

    Write-Host "[*] Get Entra role assignments"

    # Create a array to store the role assignments
    $TenantRoleAssignments = @()

    # Get all roleassignments
    $QueryParameters = @{
        '$select' = "PrincipalId,DirectoryScopeId,RoleDefinitionId"
        '$expand' = "RoleDefinition"
    }
    $TenantRoleAssignmentsRaw = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/roleManagement/directory/roleAssignments" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    foreach ($role in $TenantRoleAssignmentsRaw) {
        $ScopeResolved = $null

        # Resolve the DirectoryScopeId
        if ($role.DirectoryScopeId -eq "/") {
            $ScopeResolved = [PSCustomObject]@{
                DisplayName = "/"
                Type        = "Tenant"
            }
        } elseif ($($role.DirectoryScopeId).Contains("administrativeUnits")) {
            $ObjectID = $role.DirectoryScopeId.Replace("/administrativeUnits/", "")
            $ScopeResolved = Get-ObjectInfo $ObjectID AdministrativeUnit
        } else {
            $ObjectID = $role.DirectoryScopeId.Replace("/", "")
            $ScopeResolved = Get-ObjectInfo $ObjectID
        }

        if ($GLOBALEntraRoleRating.ContainsKey($role.RoleDefinition.Id)) {
            # If the RoleDefinition ID is found, return it's Tier-Level
            $RoleTier = $GLOBALEntraRoleRating[$role.RoleDefinition.Id]
        } else {
            # Set to ? if not assigned to a tier level
            $RoleTier = "?"
        }

        # Add the role assignment to the array
        $TenantRoleAssignments += [PSCustomObject]@{
            PrincipalId      = $role.PrincipalId
            AssignmentType   = "Active"
            DirectoryScopeId  = $role.DirectoryScopeId
            RoleDefinitionId = $role.RoleDefinition.Id
            DisplayName      = $role.RoleDefinition.DisplayName
            IsPrivileged     = $role.RoleDefinition.IsPrivileged
            RoleTier         = $RoleTier
            IsEnabled        = $role.RoleDefinition.IsEnabled
            IsBuiltIn        = $role.RoleDefinition.IsBuiltIn
            ScopeResolved    = ($ScopeResolved | select-object DisplayName,Type)
        }
    }

    Write-Host "[+] Retrieved $($TenantRoleAssignments.Count) role assignments"

    if ($TenantPimRoleAssignments.count -ge 1) {
        Write-Host "[+] Merge with PIM role assignments"
        # Combine both arrays into one
        $TenantRoleAssignments = $TenantRoleAssignments + $TenantPimRoleAssignments
    }

    # Build the hashtable
    $TenantRoleAssignmentsHT = @{}

    foreach ($assignment in $TenantRoleAssignments) {
        $principalId = $assignment.PrincipalId

        if (-not $TenantRoleAssignmentsHT.ContainsKey($principalId)) {
            $TenantRoleAssignmentsHT[$principalId] = @()
        }
        $TenantRoleAssignmentsHT[$principalId] += $assignment
    }
    Return $TenantRoleAssignmentsHT
}


#Get all active Entra role assignments
function Get-PimforGroupsAssignments {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][String]$AuthMethod
    )
    $ResultAuthCheck = $true

    Write-Host "[*] Trigger interactive authentication for PIM for Groups assessment (skip with -SkipPimForGroups)"
    if ($AuthMethod -eq "AuthCode") {
        $tokens = Invoke-Auth -ClientID '1b730954-1685-4b74-9bfd-dac224a7b894' -RedirectUrl 'https://login.microsoftonline.com/common/oauth2/nativeclient' -DisableJwtParsing @GLOBALAuthParameters
    } elseif ($AuthMethod -eq "DeviceCode"){
        $tokens = Invoke-DeviceCodeFlow -ClientID '1b730954-1685-4b74-9bfd-dac224a7b894' -DisableJwtParsing @GLOBALAuthParameters
    } elseif ($AuthMethod -eq "ManualCode"){
        $tokens = Invoke-Auth -ManualCode -ClientID '1b730954-1685-4b74-9bfd-dac224a7b894' -RedirectUrl 'https://login.microsoftonline.com/common/oauth2/nativeclient' -DisableJwtParsing @GLOBALAuthParameters
    } else {
        Write-host "[!] Invalid AuthMethod provided"
    }

    try {
        $AuthCheck = Send-GraphRequest -AccessToken $tokens.access_token -Method GET -Uri '/me?$select=id' -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -erroraction Stop
    } catch {
        write-host "[!] Auth error: $($_.Exception.Message -split '\n')"
        $ResultAuthCheck = $false
        $global:GLOBALPimForGroupsChecked = $false
    }

    if ($ResultAuthCheck) {
        $global:GLOBALPimForGroupsChecked = $true
        $proceed = $true

        #Retrieve Pim Enabled groups. If HTTP 400 assuing error message is "The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID Governance license.",
        try {
            $PimEnabledGroupsRaw = Send-GraphRequest -AccessToken $tokens.access_token -Method GET -Uri "/privilegedAccess/aadGroups/resources" -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -erroraction Stop
        } catch {
            if ($($_.Exception.Message) -match "Status: 400") {
                write-host "[!] HTTP 400 Error: Most likely due to missing Entra ID premium licence. Assuming no PIM for Groups is used."
            } else {
                write-host "[!] Auth error: $($_.Exception.Message -split '\n'). Assuming no PIM for Groups is used."
            }
            $PIMforGroupsAssignments = ""
            $proceed = $false
        }

        if ($proceed) {
            $PimEnabledGroups = $PimEnabledGroupsRaw | ForEach-Object {
                [PSCustomObject]@{
                    Id          = $_.Id
                    displayName  = $_.displayName
                }
            }

            #Stored groups in global HT var to use in groups module
            $global:GLOBALPimForGroupsHT = @{}
            foreach ($item in $PimEnabledGroups) {
                $GLOBALPimForGroupsHT[$item.Id] = $item.displayName
            }

            $PimEnabledGroupsCount = ($PimEnabledGroups | Measure-Object).count
            if ($PimEnabledGroupsCount -ge 1) {
                Write-Host "[+] Got $PimEnabledGroupsCount PIM enabled groups"

                $Requests = @()
                $RequestID = 0
                # Loop through each group and create a request entry
                $PimEnabledGroups | ForEach-Object {
                    $RequestID++
                    $Requests += @{
                        "id"     = $RequestID  # Unique request ID
                        "method" = "GET"
                        "url"    =   "/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$select=accessId,groupId,principalId&`$filter=groupId eq '$($_.id)'"
                    }
                }

                # Send Batch request
                $PIMforGroupsAssignments = (Send-GraphBatchRequest -AccessToken $tokens.access_token -Requests $Requests -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)).response.value
                Write-Host "[+] Got $($PIMforGroupsAssignments.Count) objects eligible for a PIM-enabled group"

            } else {
                Write-Host "[!] No PIM enabled groups found"
                $PIMforGroupsAssignments = ""
            }
        }
    }

    Return $PIMforGroupsAssignments
}

#Function to check the API permission for known Dangerous or high
function Get-APIPermissionCategory{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][string]$InputPermission,
        [Parameter(Mandatory=$true)][string]$PermissionType
    )

    if ($PermissionType -eq "application") {
            # Check if the input permission ID exists in the hashtable
        if ($GLOBALApiPermissionCategorizationList.ContainsKey($InputPermission)) {
            # If the permission ID is found, return its categorization
            return $GLOBALApiPermissionCategorizationList[$inputPermission]
        } else {
            # If the permission ID is not found, return a message indicating that
            return "Uncategorized"
        }

    } elseif ($PermissionType -eq "delegated") {
        # Check if the input permission ID exists in the hashtable
        if ($GLOBALDelegatedApiPermissionCategorizationList.ContainsKey($InputPermission)) {
            # If the permission ID is found, return its categorization
            return $GLOBALDelegatedApiPermissionCategorizationList[$inputPermission]
        } else {
            # If the permission ID is not found, return a message indicating that
            return "Uncategorized"
        }
    } else {
        return "ApiPermissionLookupError"
    }
}

#Function to provide detailed info about an object. Since the object type is not always known (Get-MgBetaRoleManagementDirectoryRoleAssignment) the type has to be determined first.
#The type can specified to save some GraphAPI calls
function Get-ObjectInfo($ObjectID,$type="unknown"){

    if ($type -eq "unknown" -or $type -eq "ServicePrincipal" ) {
        $QueryParameters = @{
            '$select' = "Id,DisplayName"
        }
        $EnterpriseApp = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/servicePrincipals/$ObjectID" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        if ($EnterpriseApp) {
            $object = [PSCustomObject]@{
                DisplayName = $EnterpriseApp.DisplayName
                Type = "Enterprise Application"
            }
            Return $object
        }
    }

    if ($type -eq "unknown" -or $type -eq "AppRegistration" ) {
        $QueryParameters = @{
            '$select' = "Id,DisplayName"
        }
        $AppRegistration = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/applications/$ObjectID" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        if ($AppRegistration) {
            $object = [PSCustomObject]@{
                DisplayName = $AppRegistration.DisplayName
                Type = "App Registration"
            }
            Return $object
        }
    }

    if ($type -eq "unknown" -or $type -eq "AdministrativeUnit" ) {
        $QueryParameters = @{
            '$select' = "DisplayName"
        }
        $AdministrativeUnit = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/directory/administrativeUnits/$ObjectID" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        if ($AdministrativeUnit) {
            $object = [PSCustomObject]@{
                DisplayName = $AdministrativeUnit.DisplayName
                Type = "Administrative Unit"
            }
            Return $object
        }
    }

    if ($type -eq "unknown" -or $type -eq "user" ) {
        $QueryParameters = @{
            '$select' = "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,OnPremisesSyncEnabled,JobTitle,Department"
        }
        $user = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/users/$ObjectID" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)
        if ($user) {
            $object = [PSCustomObject]@{
                DisplayName = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                Type = "User"
                AccountEnabled = $user.AccountEnabled
                UserType = $user.UserType
                OnPremisesSyncEnabled = $user.OnPremisesSyncEnabled
                JobTitle = $user.JobTitle
                Department = $user.Department
            }
            Return $object
        }
    }

    if ($type -eq "unknown" -or $type -eq "group" ) {
        $QueryParameters = @{
            '$select' = "Id,DisplayName,SecurityEnabled,IsAssignableToRole"
        }
        $group = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/groups/$ObjectID" -QueryParameters $QueryParameters -BetaAPI -Suppress404 -UserAgent $($GlobalAuditSummary.UserAgent.Name)

        if ($group) {
            $IsAssignabletoRole = if ($null -ne $group.IsAssignableToRole) { $group.IsAssignableToRole } else { $false }
            $object = [PSCustomObject]@{
                DisplayName = $group.DisplayName
                Type = "Group"
                SecurityEnabled = $group.SecurityEnabled
                IsAssignableToRole = $isAssignabletoRole
            }
            Return $object
        }
    }

    if ($type -eq "unknown") {
        $object = [PSCustomObject]@{
            DisplayName = $ObjectID
            Type = "Unknown"
        }
    }
}

#Function to define global summary variable
function start-InitTasks {
    Param (
        [Parameter(Mandatory=$false)][string]$UserAgent = "EntraFalcon",
        [Parameter(Mandatory=$true)][string]$EntraFalconVersion
    )

    $Global:GlobalAuditSummary = @{
        Time                   = @{ Start = Get-Date -Format "yyyyMMdd HH:mm"; End = ""}
        Tenant                 = @{ Name = "" ; Id = "" }
        EntraFalcon            = @{ Version = "$EntraFalconVersion"; Source = "https://github.com/CompassSecurity/EntraFalcon" }
        Subscriptions          = @{ Count = 0 }
        UserAgent              = @{ Name = $UserAgent}
        Users                  = @{ Count = 0; Guests = 0; Inactive = 0; Enabled=0; OnPrem=0; MfaCapable=0; SignInActivity = @{ '0-1 month' = 0; '1-2 months' = 0; '2-3 months' = 0; '4-5 months' = 0; '5-6 months' = 0; '6+ months' = 0; 'Never' = 0 }}
        Groups                 = @{ Count = 0; M365 = 0; PublicM365 = 0; PimOnboarded = 0; OnPrem = 0}
        AppRegistrations       = @{ Count = 0; AppLock = 0; Credentials = @{ 'AppsSecrets' = 0; 'AppsCerts' = 0; 'AppsNoCreds' = 0}; Audience = @{ 'SingleTenant' = 0; 'MultiTenant' = 0; 'MultiTenantPersonal' = 0} }
        EnterpriseApps         = @{ Count = 0; Foreign = 0; IncludeMsApps = $false; Credentials = 0; ApiCategorization = @{ 'Dangerous' = 0; 'High' = 0; 'Medium' = 0; 'Low' = 0; 'Misc' = 0}}
        ManagedIdentities      = @{ Count = 0; IsExplicit = 0; ApiCategorization = @{ 'Dangerous' = 0; 'High' = 0; 'Medium' = 0; 'Low' = 0; 'Misc' = 0} }
        AdministrativeUnits    = @{ Count = 0 }
        ConditionalAccess      = @{ Count = 0; Enabled = 0 }
        EntraRoleAssignments   = @{ Count = 0; Eligible = 0; BuiltIn = 0; PrincipalType = @{ 'User' = 0; 'Group' = 0; 'App' = 0; 'MI' = 0; 'Unknown' = 0}; Tiers = @{ 'Tier-0' = 0; 'Tier-1' = 0; 'Tier-2' = 0; 'Uncategorized' = 0} }
        AzureRoleAssignments   = @{ Count = 0; Eligible = 0; BuiltIn = 0; PrincipalType = @{ 'User' = 0; 'Group' = 0; 'SP' = 0; 'Unknown' = 0}; }
        Errors                 = @()
    }
}

# Remove global variables
function start-CleanUp {
    remove-variable -Scope Global GLOBALMsGraphAccessToken -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALApiPermissionCategorizationList -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALGraphExtendedChecks -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALArmAccessToken -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALUserAppRoles -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPimForGroupsHT -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAuditSummary -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALMainTableDetailsHEAD -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALJavaScript -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALCss -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALDelegatedApiPermissionCategorizationList -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALMsTenantIds -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPermissionForCaps -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPimForGroupsChecked -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAzurePsChecks -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAuthParameters -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALEntraRoleRating -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALAzureRoleRating -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALImpactScore -ErrorAction SilentlyContinue
    remove-variable -Scope Global GLOBALPIMsGraphAccessToken -ErrorAction SilentlyContinue
}

function Write-LogVerbose {
    param (
        [string]$Message,
        [System.Management.Automation.PSCmdlet]$CallerPSCmdlet
    )

    if ($CallerPSCmdlet -and $CallerPSCmdlet.MyInvocation.BoundParameters["Verbose"]) {
        $timestamp = Get-Date -Format "HH:mm:ss"
        $CallerPSCmdlet.WriteVerbose("[$timestamp] $Message")
    } elseif (-not $CallerPSCmdlet) { #Edge case for manual execution
        Write-Verbose "[$(Get-Date -Format 'HH:mm:ss')] $Message"
    }
}

function Show-EntraFalconBanner {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$EntraFalconVersion
    )
    $banner = @'

    ______      __                ______      __
   / ____/___  / /__________ _   / ____/___ _/ /________  ____
  / __/ / __ \/ __/ ___/ __ `/  / /_  / __ `/ / ___/ __ \/ __ \
 / /___/ / / / /_/ /  / /_/ /  / __/ / /_/ / / /__/ /_/ / / / /
/_____/_/ /_/\__/_/   \__,_/  /_/    \__,_/_/\___/\____/_/ /_/

'@

    # Show Banner with color
    Write-Host $banner -ForegroundColor Cyan
    If ($EntraFalconVersion) {Write-Host $EntraFalconVersion -ForegroundColor Cyan}
    Write-Host ""
}

Export-ModuleMember -Function Show-EntraFalconBanner,AuthenticationMSGraph,Get-Devices,start-CleanUp,Get-OrgInfo,Write-LogVerbose,Invoke-AzureRoleProcessing,Get-RegisterAuthMethodsUsers,Invoke-EntraRoleProcessing,Get-EntraPIMRoleAssignments,AuthCheckMSGraph,RefreshAuthenticationMsGraph,Get-PimforGroupsAssignments,Invoke-CheckTokenExpiration,Invoke-MsGraphAuthPIM,EnsureAuthMsGraph,Get-AzureRoleDetails,Get-AdministrativeUnitsWithMembers,Get-ConditionalAccessPolicies,Get-EntraRoleAssignments,Get-APIPermissionCategory,Get-ObjectInfo,EnsureAuthAzurePsNative,checkSubscriptionNative,Get-AllAzureIAMAssignmentsNative,Get-PIMForGroupsAssignmentsDetails,Show-EnumerationSummary,start-InitTasks
