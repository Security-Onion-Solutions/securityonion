Security Onion Productivity Report
==================================

{{ if .Error }}
**NOTE: This report encountered a problem extracting the relevant data and may not be complete.**

**Error:** {{.Error}}
{{ end }}


Records must have been created or updated during the following time frame in order to be reflected in this report.

**Report Start Date:** {{formatDateTime "Mon Jan 02 15:04:05 -0700 2006" .BeginDate}}

**Report End Date:** {{formatDateTime "Mon Jan 02 15:04:05 -0700 2006" .EndDate}}

## Ingested Events

**Total Events:** {{ formatNumber "%d" "en" .TotalEvents}}

### Events By Module

| Count | Proportion | Module |
| ----- | ---------- | ------ |
{{ range sortMetrics "Value" "desc" .TotalEventsByModule -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0}} |
{{end}}

### Events By Module and Severity Label

| Count | Proportion | Module | Severity |
| ----- | ---------- | ------ | -------- |
{{ range sortMetrics "Value" "desc" .TotalEventsByModuleDataset -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0}} | {{index .Keys 1}} |
{{end}}

## Alerts

**Total Alerts:** {{ formatNumber "%d" "en" .TotalAlerts}}

{{ range sortMetrics "Value" "desc" .TotalAlertsByAcknowledged -}}
  {{ if index .Keys 0 | eq "true" }}
**Acknowledged Alerts:** {{ formatNumber "%.0f" "en" .Value}} ({{ formatNumber "%.1f" "en" .Percentage}}%)
  {{ end }}
{{end}}

{{ range sortMetrics "Value" "desc" .TotalAlertsByEscalated -}}
  {{ if index .Keys 0 | eq "true" }}
**Escalated Alerts:** {{ formatNumber "%.0f" "en" .Value}} ({{ formatNumber "%.1f" "en" .Percentage}}%)
  {{ end }}
{{end}}

### Alerts By Severity

| Count | Proportion | Severity |
| ----- | ---------- | -------- |
{{ range sortMetrics "Value" "desc" .TotalAlertsBySeverityLabel -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0}} |
{{end}}

### Alerts By Module

| Count | Proportion | Module |
| ----- | ---------- | ------ |
{{ range sortMetrics "Value" "desc" .TotalAlertsByModule -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0}} |
{{end}}

### Alerts By Module and Severity Label

| Count | Proportion | Module | Severity |
| ----- | ---------- | ------ | -------- |
{{ range sortMetrics "Value" "desc" .TotalAlertsByModuleSeverityLabel -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0}} | {{index .Keys 1}} |
{{end}}

### Alerts By Ruleset

| Count | Proportion | Ruleset |
| ----- | ---------- | ------- |
{{ range sortMetrics "Value" "desc" .TotalAlertsByRuleset -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0}} |
{{end}}

### Alerts By Rule Category

| Count | Proportion | Category |
| ----- | ---------- | -------- |
{{ range sortMetrics "Value" "desc" .TotalAlertsByCategory -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0}} |
{{end}}

## Cases

**Total Cases:** {{ formatNumber "%d" "en" .TotalCases}}

**Average Elapsed Time To Complete:** {{ formatNumber "%.1f" "en" .AverageHoursToComplete }} hours

### Cases By Status

| Count | Proportion | Status |
| ----- | ---------- | ------ |
{{ range sortMetrics "Value" "desc" .TotalCasesByStatus -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0}} |
{{end}}

### Cases By Assignee

| Count | Proportion | Assignee |
| ----- | ---------- | -------- |
{{ range sortMetrics "Value" "desc" .TotalCasesByAssignee -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0 | getUserDetail "email"}} |
{{end}}

### Cases By Status and Assignee

| Count | Proportion | Status | Assignee |
| ----- | ---------- | ------ | -------- |
{{ range sortMetrics "Value" "desc" .TotalCasesByStatusAssignee -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0}} | {{index .Keys 1 | getUserDetail "email"}} |
{{end}}

### Cases By Severity

| Count | Proportion | Severity |
| ----- | ---------- | -------- |
{{ range sortMetrics "Value" "desc" .TotalCasesBySeverity -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0}} |
{{end}}

### Cases By Priority

| Count | Proportion | Priority |
| ----- | ---------- | -------- |
{{ range sortMetrics "Value" "desc" .TotalCasesByPriority -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0}} |
{{end}}

### Cases By Traffic Light Protocol (TLP)

| Count | Proportion | TLP |
| ----- | ---------- | ----|
{{ range sortMetrics "Value" "desc" .TotalCasesByTlp -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0}} |
{{end}}

### Cases By Permissible Actions Protocol (PAP)

| Count | Proportion | PAP |
| ----- | ---------- | --- |
{{ range sortMetrics "Value" "desc" .TotalCasesByPap -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0}} |
{{end}}

### Cases By Category

| Count | Proportion | Category |
| ----- | ---------- | -------- |
{{ range sortMetrics "Value" "desc" .TotalCasesByCategory -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0}} |
{{end}}

### Cases By Tags

| Count | Proportion | Tags |
| ----- | ---------- | ---- |
{{ range sortMetrics "Value" "desc" .TotalCasesByTags -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0}} |
{{end}}

### Comments By User

| Count | Proportion | User |
| ----- | ---------- | ---- |
{{ range sortMetrics "Value" "desc" .TotalCommentsByUserId -}}
| {{ formatNumber "%.0f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0 | getUserDetail "email"}} |
{{end}}

## Time Tracking

**Total Hours:** {{ formatNumber "%.2f" "en" .TotalHours}}

### Hours By User

| Hours | Proportion | User |
| ----- | ---------- | ---- |
{{ range sortMetrics "Value" "desc" .TotalHoursByUserId -}}
| {{ formatNumber "%.2f" "en" .Value}} | {{ formatNumber "%.1f" "en" .Percentage}}% | {{index .Keys 0 | getUserDetail "email"}} |
{{end}}