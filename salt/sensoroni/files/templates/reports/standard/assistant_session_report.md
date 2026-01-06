Onion AI Session Report
==========================

## Session Details

**Session ID:** {{.Session.SessionId}}

**Title:** {{.Session.Title}}

**Created:** {{formatDateTime "Mon Jan 02 15:04:05 -0700 2006" .Session.CreateTime}}

**Updated:** {{formatDateTime "Mon Jan 02 15:04:05 -0700 2006" .Session.UpdateTime}}

{{ if .Session.DeleteTime }}
**Deleted:** {{ formatDateTime "Mon Jan 02 15:04:05 -0700 2006" .Session.DeleteTime}}
{{ end }}

**User ID:** {{getUserDetail "email" .Session.UserId}}

## Session Usage

**Total Input Tokens** {{.Session.Usage.TotalInputTokens}}

**Total Output Tokens** {{.Session.Usage.TotalOutputTokens}}

**Total Credits:** {{.Session.Usage.TotalCredits}}

**Total Messages:** {{.Session.Usage.TotalMessages}}

## Messages

{{ range $index, $msg := sortAssistantMessages "CreateTime" "asc" .History }}
#### Message {{ add $index 1 }}

**Created:** {{formatDateTime "Mon Jan 02 15:04:05 -0700 2006" $msg.CreateTime}}

**User ID:** {{getUserDetail "email" $msg.UserId}}

**Role:** {{$msg.Message.Role}}

{{ range $i, $block := $msg.Message.ContentBlocks }}

---

{{ if eq $block.Type "text" }}
**Text:** {{ stripEmoji $block.Text }}
{{ else if eq $block.Type "tool_use" }}
**Tool:** {{ $block.Name }}
{{ if $block.Input }}
**Parameters:**
{{ range $key, $value := parseJSON $block.Input }}
{{ if eq $key "limit" }}- {{ $key }}: {{ $value }}
{{ else }}- {{ $key }}: "{{ $value }}"
{{ end }}{{ end }}{{ end }}
{{ else if $block.ToolResult }}
**Tool Result:**
{{ if $block.ToolResult.Content }}
{{ range $j, $contentBlock := $block.ToolResult.Content }}
{{ if gt $j 0 }}

---

{{ end }}
{{ if $contentBlock.Text }}
{{ if $block.ToolResult.IsError }}
**Error:** {{ $contentBlock.Text }}
{{ else }}
{{ $contentBlock.Text }}
{{ end }}
{{ else if $contentBlock.Json }}
```json
{{ toJSON $contentBlock.Json }}
```
{{ end }}{{ end }}
{{ end }}{{ end }}{{ end }}

{{ if eq $msg.Message.Role "assistant" }}{{ if $msg.Message.Usage }}

---

**Message Usage:**

- Input Tokens: {{$msg.Message.Usage.InputTokens}}
- Output Tokens: {{$msg.Message.Usage.OutputTokens}}
- Credits: {{$msg.Message.Usage.Credits}}

{{end}}{{end}}

---

{{end}}