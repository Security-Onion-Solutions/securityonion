Security Onion Case Report
==========================

## Case Details

**Case ID:** {{.Case.Id}}

**Title:** {{.Case.Title}}

## Description

{{.Case.Description}}

## Details

**Created:** {{formatDateTime "Mon Jan 02 15:04:05 -0700 2006" .Case.CreateTime}}

**Updated:** {{formatDateTime "Mon Jan 02 15:04:05 -0700 2006" .Case.UpdateTime}}

**Author:** {{getUserDetail "email" .Case.UserId}}

**Status:** {{.Case.Status}}

**TLP:** {{.Case.Tlp}}

**PAP:** {{.Case.Pap}}

**Severity:** {{.Case.Severity}}

**Priority:** {{.Case.Priority}}

**Category:** {{.Case.Category}}

**Tags:** {{join .Case.Tags ", " }}

**Assignee:** {{getUserDetail "email" .Case.AssigneeId}}

**Hours Logged:** {{ formatNumber "%.2f" "en" .TotalHours}}

## Comments

{{ range sortComments "CreateTime" "asc" .Comments }}
**Created:** {{formatDateTime "Mon Jan 02 15:04:05 -0700 2006" .CreateTime}}

**Updated:** {{formatDateTime "Mon Jan 02 15:04:05 -0700 2006" .UpdateTime}}

**Author:** {{getUserDetail "email" .UserId}}

**Hours Logged:** {{ formatNumber "%.2f" "en" .Hours}}

{{.Description}}

---

{{end}}

## Detections

{{ range sortDetections "Title" "asc" .Detections }}
**Title:** {{.Title}}

**Description:** {{.Description}}

**Severity:** {{.Severity}}

**Rule Engine:** {{.Engine}}

**Rule Set:** {{.Ruleset}}

**Community Rule:** {{.IsCommunity}}

**Tags:** {{.Tags}}

{{.Content}}

---

{{end}}

## Attachments

{{ range sortArtifacts "CreateTime" "asc" .Attachments }}
**Added:** {{formatDateTime "Mon Jan 02 15:04:05 -0700 2006" .CreateTime}}

**Updated:** {{formatDateTime "Mon Jan 02 15:04:05 -0700 2006" .UpdateTime}}

**Added By:** {{getUserDetail "email" .UserId}}

**TLP:** {{.Tlp}}

**Filename:** {{.Value}}

**Size:** {{ formatNumber "%.0d" "en" .StreamLen}} bytes

**SHA256:** {{.Sha256}}

**SHA1:** {{.Sha1}}

**MD5:** {{.Md5}}

**Tags:** {{.Tags}}

**Protected (Zipped):** {{.Protected}}

{{.Description}}

---

{{end}}

## Observables

| Date Added | Tlp | Type | IOC | Value | Description |
| ---------- | --- | ---- | --- | ----- | ----------- |
{{ range sortArtifacts "CreateTime" "asc" .Observables -}}
| {{formatDateTime "Mon Jan 02 15:04:05 -0700 2006" .CreateTime}} | {{.Tlp}} | {{.ArtifactType}} | {{.Ioc}} | {{.Value}} | {{.Description}} |
{{end}}

## Related Events

| Event Time | Log ID | Source IP | Destination IP |
| ---------- | ------ | --------- | -------------- |
{{ range sortRelatedEvents "fields:soc_timestamp" "asc" .RelatedEvents -}}
| {{.Fields.soc_timestamp}} | {{.Fields.log_id_uid}} | {{.Fields.source_ip}} | {{.Fields.destination_ip}} |
{{end}}

## Case History

| Date | User | Object | Operation |
| ---- | ---- | ------ | --------- |
{{ range sortHistory "CreateTime" "asc" .History -}}
| {{formatDateTime "Mon Jan 02 15:04:05 -0700 2006" .CreateTime}} | {{getUserDetail "email" .UserId}} | {{.Kind}} | {{.Operation}} |
{{end}}