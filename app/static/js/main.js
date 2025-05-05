$(document).ready(() => {
  // Form submission handler
  $("#rulesForm").on("submit", (e) => {
    e.preventDefault()
    submitRules()
  })

  // Clear button handler
  $("#clearBtn").on("click", () => {
    $("#rulesInput").val("")
    $("#resultsContainer").addClass("d-none")
    $("#errorAlert").addClass("d-none")
  })

  // Sample button handler
  $("#sampleBtn").on("click", () => {
    loadSampleRules()
  })

  // Filter input handler
  $("#rulesFilter").on("keyup", () => {
    filterRules()
  })

  // Initialize tooltips
  $('[data-bs-toggle="tooltip"]').tooltip()
})

/**
 * Submit rules to the API for parsing
 */
function submitRules() {
  const rules = $("#rulesInput").val().trim()

  if (!rules) {
    showError("Please enter iptables rules")
    return
  }

  // Show loading spinner
  $("#loadingSpinner").removeClass("d-none")
  $("#errorAlert").addClass("d-none")
  $("#resultsContainer").addClass("d-none")

  // Send AJAX request
  $.ajax({
    url: "/api/parse_rules",
    type: "POST",
    contentType: "application/json",
    data: JSON.stringify({ rules: rules }),
    success: (response) => {
      $("#loadingSpinner").addClass("d-none")

      if (response.status === "success") {
        renderRules(response.rules)
        renderGroupedRules(response.grouped_rules)
        $("#resultsContainer").removeClass("d-none")
      } else {
        showError(response.message || "Unknown error occurred")
      }
    },
    error: (xhr) => {
      $("#loadingSpinner").addClass("d-none")

      let errorMessage = "Error parsing rules"
      if (xhr.responseJSON && xhr.responseJSON.message) {
        errorMessage = xhr.responseJSON.message
      }

      showError(errorMessage)
    },
  })
}

/**
 * Render parsed rules in the table
 */
function renderRules(rules) {
  const tableBody = $("#rulesTableBody")
  tableBody.empty()

  if (!rules || rules.length === 0) {
    tableBody.append('<tr><td colspan="9" class="text-center">No rules found</td></tr>')
    return
  }

  rules.forEach((rule, index) => {
    const row = $("<tr>")
    row.attr("data-rule-index", index)
    row.attr("data-bs-toggle", "modal")
    row.attr("data-bs-target", "#ruleDetailModal")
    row.attr("data-rule", JSON.stringify(rule))

    // Add class based on action
    if (rule.action.toLowerCase() === "accept") {
      row.addClass("rule-accept")
    } else if (rule.action.toLowerCase() === "drop") {
      row.addClass("rule-drop")
    } else if (rule.action.toLowerCase() === "reject") {
      row.addClass("rule-reject")
    }

    // Add table cells
    row.append(`<td>${rule.table}</td>`)
    row.append(`<td>${rule.chain}</td>`)
    row.append(`<td>${rule.source}</td>`)
    row.append(`<td>${rule.destination}</td>`)
    row.append(`<td>${rule.protocol}</td>`)
    row.append(`<td>${rule.dport || "-"}</td>`)

    // Interface (in or out)
    const interfaceText = rule.in_interface
      ? `in: ${rule.in_interface}`
      : rule.out_interface
        ? `out: ${rule.out_interface}`
        : "-"
    row.append(`<td>${interfaceText}</td>`)

    // Action with badge
    const actionClass = getActionBadgeClass(rule.action)
    row.append(`<td><span class="badge ${actionClass}">${rule.action}</span></td>`)

    // Comment (truncated)
    const comment = rule.comment ? `<span class="truncate" title="${rule.comment}">${rule.comment}</span>` : "-"
    row.append(`<td>${comment}</td>`)

    tableBody.append(row)
  })

  // Add click handler for rule details
  $("tr[data-rule-index]").on("click", function () {
    const rule = JSON.parse($(this).attr("data-rule"))
    showRuleDetails(rule)
  })
}

/**
 * Render grouped rules in accordions
 */
function renderGroupedRules(groupedRules) {
  // Render by chain
  renderGroupAccordion("byChainContainer", "chain", groupedRules.by_chain)

  // Render by action
  renderGroupAccordion("byActionContainer", "action", groupedRules.by_action)

  // Render by protocol
  renderGroupAccordion("byProtocolContainer", "protocol", groupedRules.by_protocol)

  // Render by interface
  renderGroupAccordion("byInterfaceContainer", "interface", groupedRules.by_interface)
}

/**
 * Render a group accordion
 */
function renderGroupAccordion(containerId, groupType, groups) {
  const container = $(`#${containerId}`)
  container.empty()

  if (!groups || Object.keys(groups).length === 0) {
    container.append('<div class="alert alert-info">No groups found</div>')
    return
  }

  // Sort group keys
  const sortedKeys = Object.keys(groups).sort()

  sortedKeys.forEach((key, index) => {
    const rules = groups[key]
    const accordionId = `${groupType}-${key.replace(/[^a-zA-Z0-9]/g, "")}`
    const headerId = `heading-${accordionId}`
    const collapseId = `collapse-${accordionId}`

    // Create accordion item
    const item = $('<div class="accordion-item">')

    // Create header
    const header = $(`
            <h2 class="accordion-header" id="${headerId}">
                <button class="accordion-button ${index === 0 ? "" : "collapsed"}" 
                        type="button" 
                        data-bs-toggle="collapse" 
                        data-bs-target="#${collapseId}" 
                        aria-expanded="${index === 0 ? "true" : "false"}" 
                        aria-controls="${collapseId}">
                    ${getBadgeForGroup(groupType, key)} ${key} <span class="ms-2 badge bg-secondary">${rules.length}</span>
                </button>
            </h2>
        `)

    // Create collapse body
    const body = $(`
            <div id="${collapseId}" 
                 class="accordion-collapse collapse ${index === 0 ? "show" : ""}" 
                 aria-labelledby="${headerId}" 
                 data-bs-parent="#${containerId}">
                <div class="accordion-body">
                    <div class="table-responsive">
                        <table class="table table-striped table-hover">
                            <thead>
                                <tr>
                                    <th>Table</th>
                                    <th>Chain</th>
                                    <th>Source</th>
                                    <th>Destination</th>
                                    <th>Protocol</th>
                                    <th>Port</th>
                                    <th>Interface</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody id="tbody-${accordionId}">
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `)

    // Add to container
    item.append(header)
    item.append(body)
    container.append(item)

    // Add rules to table
    const tbody = $(`#tbody-${accordionId}`)
    rules.forEach((rule, ruleIndex) => {
      const row = $("<tr>")
      row.attr("data-rule", JSON.stringify(rule))
      row.attr("data-bs-toggle", "modal")
      row.attr("data-bs-target", "#ruleDetailModal")

      // Add class based on action
      if (rule.action.toLowerCase() === "accept") {
        row.addClass("rule-accept")
      } else if (rule.action.toLowerCase() === "drop") {
        row.addClass("rule-drop")
      } else if (rule.action.toLowerCase() === "reject") {
        row.addClass("rule-reject")
      }

      // Add table cells
      row.append(`<td>${rule.table}</td>`)
      row.append(`<td>${rule.chain}</td>`)
      row.append(`<td>${rule.source}</td>`)
      row.append(`<td>${rule.destination}</td>`)
      row.append(`<td>${rule.protocol}</td>`)
      row.append(`<td>${rule.dport || "-"}</td>`)

      // Interface (in or out)
      const interfaceText = rule.in_interface
        ? `in: ${rule.in_interface}`
        : rule.out_interface
          ? `out: ${rule.out_interface}`
          : "-"
      row.append(`<td>${interfaceText}</td>`)

      // Action with badge
      const actionClass = getActionBadgeClass(rule.action)
      row.append(`<td><span class="badge ${actionClass}">${rule.action}</span></td>`)

      tbody.append(row)
    })
  })

  // Add click handler for rule details
  $("tr[data-rule]").on("click", function () {
    const rule = JSON.parse($(this).attr("data-rule"))
    showRuleDetails(rule)
  })
}

/**
 * Show rule details in modal
 */
function showRuleDetails(rule) {
  const modalBody = $("#ruleDetailBody")
  modalBody.empty()

  // Create detail table
  const table = $('<table class="table table-bordered">')

  // Add all rule properties
  for (const [key, value] of Object.entries(rule)) {
    if (key === "raw") {
      // Add raw rule in a code block
      const row = $("<tr>")
      row.append(`<th>Raw Rule</th>`)
      row.append(`<td><pre class="mb-0"><code>${value}</code></pre></td>`)
      table.append(row)
    } else {
      const row = $("<tr>")
      row.append(`<th>${formatPropertyName(key)}</th>`)
      row.append(`<td>${value || "-"}</td>`)
      table.append(row)
    }
  }

  modalBody.append(table)

  // Update modal title
  $("#ruleDetailModalLabel").text(`Rule Details: ${rule.chain} - ${rule.action}`)
}

/**
 * Filter rules in the table
 */
function filterRules() {
  const filterText = $("#rulesFilter").val().toLowerCase()

  if (!filterText) {
    // Show all rows if filter is empty
    $("#rulesTableBody tr").show()
    return
  }

  // Filter rows
  $("#rulesTableBody tr").each(function () {
    const rowText = $(this).text().toLowerCase()
    if (rowText.includes(filterText)) {
      $(this).show()
    } else {
      $(this).hide()
    }
  })
}

/**
 * Show error message
 */
function showError(message) {
  $("#errorAlert").text(message)
  $("#errorAlert").removeClass("d-none")
}

/**
 * Load sample iptables rules
 */
function loadSampleRules() {
  const sampleRules = `# Generated by iptables-save v1.8.4 on Mon May 5 10:00:00 2025
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -s 192.168.1.0/24 -j ACCEPT
-A INPUT -j DROP
-A FORWARD -j DROP
COMMIT
# Completed on Mon May 5 10:00:00 2025`

  $("#rulesInput").val(sampleRules)
}

/**
 * Get badge class for action
 */
function getActionBadgeClass(action) {
  action = action.toLowerCase()

  if (action === "accept") {
    return "badge-accept"
  } else if (action === "drop") {
    return "badge-drop"
  } else if (action === "reject") {
    return "badge-reject"
  } else {
    return "bg-secondary"
  }
}

/**
 * Get badge for group
 */
function getBadgeForGroup(groupType, key) {
  let badgeClass = "bg-secondary"
  const keyLower = key.toLowerCase()

  if (groupType === "chain") {
    if (keyLower === "input") {
      badgeClass = "badge-input"
    } else if (keyLower === "output") {
      badgeClass = "badge-output"
    } else if (keyLower === "forward") {
      badgeClass = "badge-forward"
    }
  } else if (groupType === "action") {
    if (keyLower === "accept") {
      badgeClass = "badge-accept"
    } else if (keyLower === "drop") {
      badgeClass = "badge-drop"
    } else if (keyLower === "reject") {
      badgeClass = "badge-reject"
    }
  } else if (groupType === "protocol") {
    if (keyLower === "tcp") {
      badgeClass = "badge-tcp"
    } else if (keyLower === "udp") {
      badgeClass = "badge-udp"
    } else if (keyLower === "icmp") {
      badgeClass = "badge-icmp"
    }
  }

  return `<span class="badge ${badgeClass}">${key}</span>`
}

/**
 * Format property name for display
 */
function formatPropertyName(name) {
  // Convert camelCase or snake_case to Title Case with spaces
  return name
    .replace(/_/g, " ")
    .replace(/([A-Z])/g, " $1")
    .replace(/^./, (str) => str.toUpperCase())
}
