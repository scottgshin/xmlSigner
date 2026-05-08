**xmlSigner** is [free software](https://www.fsf.org/) & an open source project. It was writen to meet [Notepad++](https://notepad-plus-plus.org/)'s need for signing XML files in order to secure its auto-updater ([WinGUp](https://wingup.org/)).

To use xmlSigner for signing your XML files, you need the following:

1. A code-signing certificate installed in the Windows certificate store.
2. The "xmlSigner.exe" binary - compile it & sign it with your trusted certificate to prevent the block comes from Smart App Control.
3. A configuration file named "[xmlSigner.ini](https://github.com/donho/xmlSigner/blob/master/xmlSigner/xmlSigner.ini)". Place it next to "xmlSigner.exe" and adjust the parameters according your needs.
