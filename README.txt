Security Minetest Mod
=====================

Creates a transparent sandboxed Lua environment for Minetest, restricting other
mods' access to the OS, filesystem, and debug capabilities.

In order to use this mod, it MUST load before ALL OTHER MODS, including those
in the Minetest game being loaded.  To ensure this, make sure EVERY MOD has the
"depends.txt" file in its base directory and that one of the lines in the file
reads "security?".  If this isn't done, not only will it break the security
guarantees, but mods that load before this one may not be able to correctly
access global variables.

This mod has no dependencies and provides no external API.

Comments and criticisms are welcome and encouraged.  In fact, community support
is essential for improving security.  Try this with other mods and see if
anything crashes.  Report incompatibilities.  Review the code, try to find
holes and break the rules, and PLEASE report when you succeed.

Virtual Filesystem
------------------

This mod creates a virtual filesystem for all mod code.  This filesystem looks
like:

   /
   |- tmp/
   |- world/
   |- mods/
      |- mod1/
      |- mod2/
      |- mod3/
      .
      .

This filesystem is handled correctly by minetest.get_worldpath(),
minetest.get_modpath(), minetest.create_schematic(), and
minetest.place_schematic(), so as long as mods base their file access on those
paths, the filesystem change should be transparent to them.

The directory for the security mod is specifically NOT a part of this virtual
filesystem.  All other mod directories for enable mods are.

The special 'tmp' directory only holds files with names reserved by
os.tmpname().  These reserved names are only tracked while the server is
running, so they cannot be referenced in future incarnations, even if the are
not removed explicitly.  This MIGHT break some existing mods, but those mods
probably should be relying on persistence of temporary files anyway, as they
might be kept in locations that are not persisted by the operating system.

Escape characters are assumed to be backslash ('\') and percent ('%').
Backslashes are converted to forward slashes ('/') which will work portably on
all operating systems due to Lua's standard library.  Percent characters result
in invalid paths which cause all I/O functions to fail.

Attempts to access files outside the "/tmp", "/world", or "/mods/*" directories
will fail.  Attempts to access files in the "/tmp" directory not reserved by
os.tmpname() will fail.  Relative paths (starting with anything other than "/"
or "\") are resolved relative to "/world/".

Other Restrictions
------------------

Some other functionality normally available in Lua has been removed entirely or
limited in specific ways:

* The standard Lua debug API has been removed.

* The ability to execute outside programs (io.popen() and os.execute()) or load
  outside shared libraries (package.loadlib()) has been removed.

* Retrieving metatables (getmetatable()) and function environments (getfenv())
  return only the sandboxed environment table and any metatables and
  environments that have been explicitly set by the corresponding set functions
  (setmetable() and setfenv()).

* Lua modules using module(), require(), and the package API will work normally
  and custom loading will work from virtual filesystem locations.  There is
  also a special search function in package.loaders that will opaquely load
  modules using the standard mechanism, but the built-in loaders and module
  paths are hidden from the sandboxed environment (package.cpath and
  package.path are initialized to an empty string, and changing either will
  have no effect, though custom mod loaders are free to use them).

Open Issues
-----------

* Obviously the cumbersome part of using the mod is having to ensure it loads
  first by adding it as a dependency to all other mods (even game mods).
  Unfortunately fixing this probably requires moving this functionality from a
  mod to the builtin Lua code, or providing some kind of engine support for
  specifying an initial list of modules that must be loaded first regardless of
  dependencies.

* Globals added by builtin code in future versions of Minetest will have to be
  whitelisted.  Functions that require file names/paths will have to be
  wrapped.

Change History
--------------

Version 1.0

* Released 2015-04-11
* First working version, tested against luacmd, minetest_game, moretrees, and
  the plantslife modpack.

Copyright and Licensing
-----------------------

All contents, including documentation and source code, are original content
created by the mod author and are licensed under WTFPL.

Author: prestidigitator (as registered on forum.minetest.net)
License: WTFPL
