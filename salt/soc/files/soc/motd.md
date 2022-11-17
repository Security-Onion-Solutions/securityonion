## Getting Started

New to Security Onion 2? Click the menu in the upper-right corner and you'll find links for [Help](/docs/) and a [Cheatsheet](/docs/cheatsheet.pdf) that will help you best utilize Security Onion to hunt for evil! In addition, check out our free Security Onion 2 Essentials online course, available on our [Training](https://securityonionsolutions.com/training) website.

If you're ready to dive in, take a look at the [Alerts](/#/alerts) interface to see what Security Onion has detected so far. Then go to the [Dashboards](/#/dashboards) interface for a general overview of all logs collected or go to the [Hunt](/#/hunt) interface for more focused threat hunting. Once you've found something of interest, escalate it to [Cases](/#/cases) to then collect evidence and analyze observables as you work towards closing the case.

## What's New 

To see all the latest features and fixes in this version of Security Onion, click the upper-right menu and then click the [What's New](/docs/release-notes.html) link.

## Customize This Space

Make this area your own by customizing the content. The content is stored in the `motd.md` file, which uses the common Markdown (.md) format. To learn more about the format, please see [markdownguide.org](https://www.markdownguide.org/).

To customize this content, login to the manager via SSH and execute the following command:

```bash
sudo cp /opt/so/saltstack/default/salt/soc/files/soc/motd.md /opt/so/saltstack/local/salt/soc/files/soc/
```

Then edit the new file as desired using your favorite text editor. 

Finally, restart SOC to make the changes take effect:

```bash
sudo so-soc-restart
```
