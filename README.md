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

- Make a file in your dir above named _idapythonrc.py_ and append `import revsync`.
- Copy _config.json.template_ to _config.json_ and fill out.
- Restart IDA and look for revsync messages in the console.
  - In the Python console, typing `import revsync` should work without issue.

Expected data directory layout is this (Mac/Linux):

```
~/.idapro/idapythonrc.py
~/.idapro/revsync/
```

Binary Ninja Installation
-------------------------

- Clone to [your plugin folder](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples#loading-plugins).
- Restart Binary Ninja, and fill in config when prompted.
- Load your binary, and let Binary Ninja finish analysis.
- Right click and select 'revsync: load'
- Done!
