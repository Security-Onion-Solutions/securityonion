## Getting Started

New to Security Onion? Click the menu in the upper-right corner and you'll find links for [Help](/docs/) and a [Cheat Sheet](/docs/cheatsheet.pdf) that will help you best utilize Security Onion to hunt for evil! In addition, check out our free Security Onion Essentials online course, available on our [Training](https://securityonion.com/training) website.

If you're ready to dive in, take a look at the [Alerts](/#/alerts) interface to see what Security Onion has detected so far. If you find any false positives, then you can tune those in [Detections](/#/detections).

Next, go to the [Dashboards](/#/dashboards) interface for a general overview of all logs collected. Here are a few overview dashboards to get you started:

[Overview Dashboard](/#/dashboards) | [Elastic Agent Overview](/#/dashboards?q=event.module%3Aendpoint%20%7C%20groupby%20event.dataset%20%7C%20groupby%20host.name%20%7C%20groupby%20-sankey%20host.name%20user.name%20%7C%20groupby%20user.name%20%7C%20groupby%20-sankey%20user.name%20process.name%20%7C%20groupby%20process.name) | [Network Connection Overview](/#/dashboards?q=tags%3Aconn%20%7C%20groupby%20source.ip%20%7C%20groupby%20destination.ip%20%7C%20groupby%20destination.port%20%7C%20groupby%20-sankey%20destination.port%20network.protocol%20%7C%20groupby%20network.protocol%20%7C%20groupby%20network.transport%20%7C%20groupby%20connection.history%20%7C%20groupby%20connection.state%20%7C%20groupby%20connection.state_description%20%7C%20groupby%20source.geo.country_name%20%7C%20groupby%20destination.geo.country_name%20%7C%20groupby%20client.ip_bytes%20%7C%20groupby%20server.ip_bytes%20%7C%20groupby%20client.oui) | [DNS](/#/dashboards?q=tags%3Adns%20%7C%20groupby%20dns.query.name%20%7C%20groupby%20source.ip%20%7C%20groupby%20-sankey%20source.ip%20destination.ip%20%7C%20groupby%20destination.ip%20%7C%20groupby%20destination.port%20%7C%20groupby%20dns.highest_registered_domain%20%7C%20groupby%20dns.parent_domain%20%7C%20groupby%20dns.query.type_name%20%7C%20groupby%20dns.response.code_name%20%7C%20groupby%20dns.answers.name%20%7C%20groupby%20destination_geo.organization_name) | [Files](/#/dashboards?q=tags%3Afile%20%7C%20groupby%20file.mime_type%20%7C%20groupby%20-sankey%20file.mime_type%20file.source%20%7C%20groupby%20file.source%20%7C%20groupby%20file.bytes.total%20%7C%20groupby%20source.ip%20%7C%20groupby%20destination.ip%20%7C%20groupby%20destination_geo.organization_name) | [HTTP](/#/dashboards?q=tags%3Ahttp%20%7C%20groupby%20http.method%20%7C%20groupby%20-sankey%20http.method%20http.virtual_host%20%7C%20groupby%20http.virtual_host%20%7C%20groupby%20http.uri%20%7C%20groupby%20http.useragent%20%7C%20groupby%20http.status_code%20%7C%20groupby%20http.status_message%20%7C%20groupby%20file.resp_mime_types%20%7C%20groupby%20source.ip%20%7C%20groupby%20destination.ip%20%7C%20groupby%20destination.port%20%7C%20groupby%20destination_geo.organization_name) | [SSL](/#/dashboards?q=tags%3Assl%20%7C%20groupby%20ssl.version%20%7C%20groupby%20-sankey%20ssl.version%20ssl.server_name%20%7C%20groupby%20ssl.server_name%20%7C%20groupby%20source.ip%20%7C%20groupby%20destination.ip%20%7C%20groupby%20destination.port%20%7C%20groupby%20destination_geo.organization_name)

Click the drop-down menu in Dashboards to find many more dashboards. You might also want to explore the [Hunt](/#/hunt) interface for more focused threat hunting. 

Once you've found something of interest, escalate it to [Cases](/#/cases) to then collect evidence and analyze observables as you work towards closing the case.

If you want to check the health of your deployment, check out the [Grid](/#/grid) interface.

For more coverage of your enterprise, you can deploy the Elastic Agent to endpoints by going to the [Downloads](/#/downloads) page.

## What's New 

To see all the latest features and fixes in this version of Security Onion, click the upper-right menu and then click the [What's New](/docs/release-notes.html) link.

## Security Onion Pro

Need enterprise features and premium support? Check out [Security Onion Pro](https://securityonion.com/pro/)!

## Enterprise Appliances

Want the best hardware for your enterprise deployment? Check out our [enterprise appliances](https://securityonion.com/hardware/)!

## Premium Support

Experiencing difficulties and need priority support or remote assistance? We offer a [premium support plan](https://securityonion.com/support/) to assist corporate, educational, and government organizations.

## Customize This Space

Make this area your own by customizing the content in the [Config](/#/config?s=soc.files.soc.motd__md) interface.
