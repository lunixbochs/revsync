revsync
=======

Realtime IDA Pro and Binary Ninja sync plugin

Reliably syncs symbol names and comments, and that's it!

IDA Pro Installation
--------------------

First, clone to IDA Data Dir:

- Windows: `%APPDATA%\Hex-Rays\IDA Pro`
- Mac/Linux: `~/.idapro`

Now:

- Make a file in your data dir called `idapythonrc.py` and append `import revsync`.
- Copy _myconfig.py.template_ to _myconfig.py_ and fill out.
- Restart IDA and look for revsync messages in the console.

Expected data directory layout is this (Mac/Linux):

```
~/.idapro/idapythonrc.py
~/.idapro/revsync/
```

Binary Ninja Installation
-------------------------

- Clone to [your plugin folder](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples#loading-plugins).
- Copy _myconfig.py.template_ to _myconfig.py_ and fill out.
- Restart Binary Ninja, and look for revsync messages in the console.
- Load your binary, and let Binary Ninja finish analysis.
- Right click and select 'revsync: load'
- Done!
