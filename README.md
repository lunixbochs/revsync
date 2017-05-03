revsync
-------

Realtime IDA Pro and Binary Ninja sync plugin

Reliably syncs symbol names and comments, and that's it!

IDA Pro Installation
--------

First, clone to IDA Data Dir:

- Windows: `%APPDATA%\Hex-Rays\IDA Pro`
- Mac/Linux: `~/.idapro`

Now:

- Make a file in your data dir called `idapythonrc.py` and append `import revsync`.
- Put your nickname in `config.py`.
- Restart IDA and look for revsync messages in the console.

Expected data directory layout is this (Mac/Linux):
```
~/.idapro/idapythonrc.py
~/.idapro/revsync/
```

Binary Ninja installation
--------

- Clone to your plugin dir (`Tools` menu -> `Open Plugin Folder`).
- Put your nickname in `config.py`.
- Restart Binary Ninja, and look for revsync messages in the console.
