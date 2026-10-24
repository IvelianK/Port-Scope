# PyInstaller entry point: the package itself uses relative imports, so it cannot be the script.
from portscope.__main__ import main

raise SystemExit(main())
