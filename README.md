revsync
=======

Realtime IDA Pro and Binary Ninja sync plugin

Syncs:

- Comments
- Symbol names
- Stack var names
- Structs
- Code coverage (how much time was spent looking at a block)

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

- Install via the Plugin Manager (CMD/CTL-SHIFT-M)

or:

- Clone to [your plugin folder](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples#loading-plugins).

Then:

- Restart if required.
- Fill in config when prompted.
- Load your binary, wait for analysis to finish
- Use the Tools Menu, Right-Click or command-palette (CMD/CTL-P) to trigger revsync/Load
-Done!
