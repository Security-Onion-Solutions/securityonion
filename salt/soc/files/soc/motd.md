## Getting Started

New to Security Onion 2? Check out the [Online Help](/docs/) and [Cheatsheet](/docs/cheatsheet.pdf) to learn how to best utilize Security Onion to hunt for evil! Find them in the upper-right menu.

If you're ready to dive-in, take a look at the [Alerts](/#/alerts) interface to see what Security Onion has detected so far. Or navigate to the [Hunt](/#/hunt) interface to hunt for evil that the alerts might have missed!

## What's New 

The release notes have moved to the upper-right menu. Click on the [What's New](/docs/#document-release-notes) menu option to find all the latest fixes and features in this version of Security Onion!

## Customize This Space

Make this area your own by customizing the content. The content is stored in the `motd.md` file, which uses the common Markdown (.md) format. Visit [mardownguide.org](https://www.markdownguide.org/) to learn more about the simple Markdown format.

To customize this content, login to the manager via SSH and execute the following command:

```bash
cp -f /opt/so/saltstack/default/salt/soc/files/soc/motd.md /opt/so/saltstack/local/salt/soc/files/soc/motd.md
```

Now, edit the new file as desired. Finally, run this command:

```bash
salt-call state.apply soc queue=True
```
