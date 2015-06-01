local security = select(1, ...);
local std = security.std;
local sandboxEnv = security.sandboxEnv;


-- Utility Functions

local stdError = std.error;
local stdSetFEnv = std.setfenv;
local stdToString = std.tostring;
local stdType = std.type;
local stdStrFind = std.string.find;
local stdTabConcat = std.table.concat;
local stdTabInsert = std.table.insert;
local stdTabRemove = std.table.remove;

local split;
do
   local stdStrSub = std.string.sub;

   split = function(str, sep, plain)
      local comps = {};
      if #str <= 0 then return comps; end;

      local p = 1;
      while true do
         local s, e = stdStrFind(str, sep, p, plain);
         if s then
            stdTabInsert(comps, stdStrSub(str, p, s - 1));
            p = e + 1;
         else
            stdTabInsert(comps, stdStrSub(str, p));
            break;
         end;
      end;

      return comps;
   end;
end;


-- Top-Level Whitelist

local TOP_LEVEL_WHITELIST =
   {
      _G             = false,  -- Replaced by environment itself
      _VERSION       = true,
      assert         = true,
         bit         = true,   -- (luajit)
      collectgarbage = true,
      dofile         = false,  -- Wrapped below
      error          = true,
         gcinfo      = true,   -- Deprecated, but okay
      getfenv        = false,  -- Wrapped below
      getmetatable   = false,  -- Wrapped below
      ipairs         = true,
         jit         = false,  -- Removed completely (luajit)
      load           = false,  -- Wrapped below
      loadfile       = false,  -- Wrapped below
      loadstring     = false,  -- Wrapped below
      module         = false,  -- Wrapped below
         newproxy    = false,  -- Short-lived, deprecated; probably unused.
      next           = true,
      pairs          = true,
      pcall          = true,
      print          = true,
      rawequal       = true,
      rawget         = true,
      rawset         = true,
      require        = false,  -- Wrapped below
      select         = true,
      setfenv        = false,  -- Wrapped below
      setmetatable   = false,  -- Wrapped below
      tonumber       = true,
      tostring       = true,
      type           = true,
      unpack         = true,
      xpcall         = true,
   };
for symbol, whitelisted in pairs(TOP_LEVEL_WHITELIST) do
   if whitelisted then
      sandboxEnv[symbol] = std[symbol];
   end;
end;


-- Standard Package Whitelist

sandboxEnv.coroutine = std.coroutine;
sandboxEnv.debug     = nil;            -- Removed completely
sandboxEnv.io        = {};             -- Wrapped below
sandboxEnv.math      = std.math;
sandboxEnv.os        = {};             -- Wrapped below
sandboxEnv.package   = {};             -- Wrapped below
sandboxEnv.string    = std.string;
sandboxEnv.table     = std.table;


-- Virtual Filesystem

local toRealPath;
local wrappedOsTmpName;
do
   local MOD_NAME = security.MOD_NAME;
   local WORLD_PATH = security.WORLD_PATH;
   local mtGetModPath = security.mtGetModPath;

   local stdOsTmpName = std.os.tmpname;
   local stdStrGsub = std.string.gsub;

   local tmpPathsCounter = 1;
   local tmpPaths = {};

   local function sanitizeAndSplitFilePath(path)
      -- Escape characters and Windows path separators
      if stdStrFind(path, "%", 1, true) then return nil; end;
      path = stdStrGsub(path, "\\", "/");

      local segs = split(path, "/", true);
      local filteredSegs = {};

      for i, seg in ipairs(segs) do
         if seg and #seg > 0 and seg ~= "." then
            stdTabInsert(filteredSegs, seg);
         elseif i >= #segs then
            return nil;
         elseif seg == ".." then
            if #filteredSegs > 0 then
               stdTabRemove(filteredSegs);
            else
               return nil;
            end;
         end;
      end;

      return (#filteredSegs > 0 and filteredSegs) or nil;
   end;

   toRealPath = function(path)
      local tmpPath = tmpPaths[path];
      if tmpPath then return tmpPath; end;

      if path and
         (stdStrFind(path, "^%.[/\\]") or not stdStrFind(path, "^[/\\]"))
      then
         path = "/world/" .. path;
      end;

      local segs = sanitizeAndSplitFilePath(path);
      if segs and #segs >= 2 then
         if segs[1] == "world" then
            return WORLD_PATH .. "/" .. stdTabConcat(segs, "/", 2);
         elseif segs[1] == "mods" and #segs >= 3 then
            local modName = segs[2];
            if modName ~= MOD_NAME then
               local modPath = mtGetModPath(modName);
               if modPath and #modPath > 0 then
                  return modPath .. "/" .. stdTabConcat(segs, "/", 3);
               end;
            end;
         end;
      end;

      return nil, "Bad virtual filesystem location '"..path.."'";
   end;

   wrappedOsTmpName = function()
      local p = "/tmp/tmp" .. tmpPathsCounter;
      tmpPathsCounter = tmpPathsCounter + 1;
      tmpPaths[p] = stdOsTmpName();
      return p;
   end;
end;

local wrappedIoOpen;
do
   local stdIoOpen = std.io.open;

   wrappedIoOpen = function(filePath, mode)
      local realPath, err = toRealPath(filePath);
      if not realPath then return nil, err; end;

      local file = stdIoOpen(realPath, mode);
      if file then
         return file;
      else
         return nil, "Error opening file '"..filePath.."'";
      end;
   end;
end;

local wrappedIoInput;
local wrappedIoLines;
local wrappedIoOutput;
local wrappedIoRead;
local wrappedIoWrite;
local wrappedOsRemove;
local wrappedOsRename;
do
   local stdOsRemove = std.os.remove;
   local stdOsRename = std.os.rename;
   local stdIoInput = std.io.input;
   local stdIoLines = std.io.lines;
   local stdIoOutput = std.io.output;
   local stdIoType = std.io.type;

   wrappedIoInput = function(file)
      if file == nil then
         return stdIoInput();
      elseif stdIoType(file) then
         return stdIoInput(file);
      else
         local fileName = stdToString(file);
         if not fileName then
            return stdError("Not a file handle or file name string");
         end;
         local realPath, err = toRealPath(fileName);
         if not realPath then return stdError(err); end;
         return stdIoInput(realPath);
      end;
   end;

   wrappedIoLines = function(fileName)
      if fileName == nil then
         return stdIoInput():lines();
      end;

      fileName = stdToString(fileName);
      if not fileName then return stdError("Not a file name string"); end;

      local realPath, err = toRealPath(fileName);
      if not realPath then return stdError(err); end;

      return stdIoLines(realPath);
   end;

   wrappedIoOutput = function(file)
      if file == nil then
         return stdIoOutput();
      elseif stdIoType(file) then
         return stdIoOutput(file);
      else
         local fileName = stdToString(file);
         if not fileName then
            return stdError("Not a file handle or file name string");
         end;
         local realPath, err = toRealPath(fileName);
         if not realPath then return stdError(err); end;
         return stdIoOutput(realPath);
      end;
   end;

   wrappedIoRead = function(...)
      return wrappedIoInput():read(...);
   end;

   wrappedIoWrite = function(...)
      return wrappedIoOutput():write(...);
   end;

   wrappedOsRemove = function(fileName)
      local realPath, err = toRealPath(fileName);
      if not realPath then return nil, err; end;

      local status = stdOsRemove(fileName);
      if status then
         return true;
      else
         return nil, "Error removing file '"..fileName.."'";
      end;
   end;

   wrappedOsRename = function(oldName, newName)
      oldName = stdToString(oldName);
      newName = stdToString(newName);
      if not oldName or not newName then
         return stdError("Not a file name string");
      end;

      local oldPath, newPath, err;
      oldPath, err = toRealPath(oldName);
      if not oldPath then return nil, err; end;
      newPath, err = toRealPath(newName);
      if not newPath then return nil, err; end;

      local status = stdOsRename(oldPath, newPath);
      if status then
         return true;
      else
         return nil, "Error renaming file '"..oldName.."' to '"..newName.."'";
      end;
   end;
end;

security.toRealPath = toRealPath;

sandboxEnv.io.close   = std.io.close;
sandboxEnv.io.flush   = std.io.flush;
sandboxEnv.io.input   = wrappedIoInput;
sandboxEnv.io.lines   = wrappedIoLines;
sandboxEnv.io.open    = wrappedIoOpen;
sandboxEnv.io.output  = wrappedIoOutput;
sandboxEnv.io.popen   = nil;              -- Removed completely
sandboxEnv.io.read    = wrappedIoRead;
sandboxEnv.io.stderr  = std.io.stderr;
sandboxEnv.io.stdin   = std.io.stdin;
sandboxEnv.io.stdout  = std.io.stdout;
sandboxEnv.io.tmpfile = std.io.tmpfile;
sandboxEnv.io.type    = std.io.type;
sandboxEnv.io.write   = wrappedIoWrite;

sandboxEnv.os.remove  = wrappedOsRemove;
sandboxEnv.os.rename  = wrappedOsRename;
sandboxEnv.os.tmpname = wrappedOsTmpName;


-- Code Generation

local wrappedDoFile;
local wrappedLoad;
local wrappedLoadFile;
local wrappedLoadString;
do
   local DO_FILE_READ_LIMIT = 4096;

   local stdDoFile = std.dofile;
   local stdLoad = std.load;
   local stdLoadFile = std.loadfile;
   local stdLoadString = std.loadstring;

   wrappedLoad = function(func, chunkName)
      local chunk, err = stdLoad(func, chunkName);
      if not chunk then return nil, err; end;
      return stdSetFEnv(chunk, sandboxEnv);
   end;

   wrappedLoadFile = function(fileName)
      if fileName == nil then
         local chunk, err = stdLoadFile();
         if not chunk then return nil, err; end;
         return stdSetFEnv(chunk, sandboxEnv);
      end;

      fileName = stdToString(fileName);
      if not fileName then return stdError("Not a file name string"); end;

      local file, err = wrappedIoOpen(fileName, "r");
      if not file then return nil, err; end;

      local reader = function() return file:read(DO_FILE_READ_LIMIT); end;
      local chunk, err = wrappedLoad(reader, fileName);

      file:close();

      return chunk, err;
   end;

   wrappedLoadString = function(str, chunkName)
      local chunk, err = stdLoadString(str, chunkName);
      if not chunk then return nil, err; end;
      return stdSetFEnv(chunk, sandboxEnv);
   end;

   wrappedDoFile = function(fileName)
      if fileName == nil then
         return stdDoFile();
      end;

      local chunk, err = wrappedLoadFile(fileName);
      if not chunk then return stdError(err); end;

      return chunk();
   end;
end;

sandboxEnv.dofile     = wrappedDoFile;
sandboxEnv.load       = wrappedLoad;
sandboxEnv.loadfile   = wrappedLoadFile;
sandboxEnv.loadstring = wrappedLoadString;


-- OS Functionality

sandboxEnv.os.clock      = std.os.clock;
sandboxEnv.os.date       = std.os.date;
sandboxEnv.os.difftime   = std.os.difftime;
sandboxEnv.os.execute    = nil;               -- Removed completely
sandboxEnv.os.exit       = std.os.exit;
sandboxEnv.os.getenv     = std.os.getenv;
-- sandboxEnv.os.remove                       -- Handled above
-- sandboxEnv.os.rename                       -- Handled above
sandboxEnv.os.setlocale  = std.os.setlocale;
sandboxEnv.os.time       = std.os.time;
-- sandboxEnv.os.tmpname                      -- Handled above


-- Metatables and Function Environments
--
-- Only metatables or function environments set in the sandboxed environment
-- will be returned to the sandboxed environment.

local wrappedGetMetatable;
local wrappedSetMetatable;
local wrappedGetFEnv;
local wrappedSetFEnv;
do
   local stdGetMetatable = std.getmetatable;
   local stdSetMetatable = std.setmetatable;
   local stdGetFEnv = std.getfenv;

   -- Weak keys
   local modMetas = stdSetMetatable({}, { __mode = 'k' });
   local modFEnvs = stdSetMetatable({}, { __mode = 'k' });

   wrappedGetMetatable = function(object)
      local meta = stdGetMetatable(object);
      return (modMetas[meta] and meta) or nil;
   end;

   wrappedSetMetatable = function(object, meta)
      local r = stdSetMetatable(object, meta);
      if meta then modMetas[meta] = true; end;
      return r;
   end;

   wrappedGetFEnv = function(f)
      local e = stdGetFEnv(f);
      return (modFEnvs[e] and e) or sandboxEnv;
   end;

   wrappedSetFEnv = function(f, env)
      if not env then return stdSetFEnv(f, sandboxEnv); end;
      local r = stdSetFEnv(f, env);
      modFEnvs[env] = true;
      return r;
   end;
end;

sandboxEnv.getmetatable = wrappedGetMetatable;
sandboxEnv.setmetatable = wrappedSetMetatable;
sandboxEnv.getfenv      = wrappedGetFEnv;
sandboxEnv.setfenv      = wrappedSetFEnv;


-- Packages/Modules

local wrappedModule;
local wrappedRequire;
local wrappedSeeAll;
local sandboxSearcher;
local builinSearcher;
do
   local function isName(str)
      return str and #str > 0 and stdStrFind(str, "^[_%a][_%a%d]*$");
   end;

   local function packageModNameSplit(modName)
      local pkgComps = split(modName, ".", true);
      for _, nc in ipairs(pkgComps) do
         if not isName(nc) then return nil, nil, modName; end;
      end;
      if #comps > 1 then
         local pkgName = stdTabConcat(pkgComps, ".", 1, #comps - 1);
         local simpleName = stdTabRemove(pkgComps);
         return pkgName, pkgComps, simpleName;
      else
         return nil, comps, modName;
      end;
   end;

   local function findPackage(loaded, pkgComps)
      local p = loaded;
      for _, n in ipairs(pkgComps) do
         p = p[n];
         if not p then break; end;
      end;
      return p;
   end;

   local function findOrCreatePackage(loaded, pkgComps)
      local p = loaded;
      for _, n in ipairs(pkgComps) do
         local c = p[n];
         if not c then c = {}; p[n] = c; end;
         p = c;
      end;
      return p;
   end;

   local function findModule(loaded, modName, pkgComps, simpleName)
      local mod = loaded[modName];
      if mod or not pkgComps then return mod; end;

      local pkg = findPackage(loaded, pkgComps);
      return pkg and pkg[simpleName];
   end;

   local function storeModule(loaded, modName, pkgComps, simpleName, mod)
      loaded[modName] = mod;
      if pkgComps then
         local pkg = findOrCreatePackage(loaded, pkgComps);
         pkg[simpleName] = mod;
      end;
   end;

   wrappedModule = function(modName, ...)
      local loaded = sandboxEnv.package.loaded;
      local pkgName, pkgComps, simpleName = packageModNameSplit(modName);

      local mod = findModule(loaded, modName, pkgComps, simpleName);
      if not mod then
         mod = (isName(modName) and sandboxEnv[modName]) or {};
         storeModule(loaded, modName, pkgComps, simpleName, mod);
      end;

      mod._NAME = modName;
      mod._M = mod;
      mod._PACKAGE = pkgName;

      wrappedSetFEnv(2, mod);

      for func in ipairs({ ... }) do func(mod); end;
   end;

   wrappedRequire = function(modName)
      local loaded = sandboxEnv.package.loaded;
      local pkgName, pkgComps, simpleName = packageModNameSplit(modName);

      local mod = findModule(loaded, modName, pkgComps, simpleName);
      if mod then return mod; end;

      local loader = nil;
      local reasons = {};
      for _, searcher in ipairs(sandboxEnv.package.loaders) do
         local result = searcher(modName);
         local resultType = stdType(result);
         if resultType == 'function' then
            loader = result;
            break;
         elseif resultType == 'string' then
            stdTabInsert(reasons, result);
         end;
      end;
      if not loader then
         local err = "Couldn't load module '" .. modName .. "'";
         if #reasons > 0 then
            err = err .. "\n" .. stdTabConcat(reasons, "\n");
         end;
         return stdError(err);
      end;

      mod = loader(modName);

      if mod then
         storeModule(loaded, modName, pkgComps, simpleName, mod);
      else
         mod = findModule(loaded, modName, pkgComps, simpleName);
         if not mod then
            mod = true;
            storeModule(loaded, modName, pkgComps, simpleName, mod);
         end;
      end;

      return mod;
   end;

   wrappedSeeAll = function(mod)
      wrappedSetMetatable(mod, { __index = sandboxEnv });
   end;

   sandboxSearcher = function(modName)
      return sandboxEnv.package.preload[modName];
   end;

   builinSearcher = function(modName)
      local pkgName, pkgComps, simpleName = packageModNameSplit(modName);

      local mod =
         findModule(std.package.loaded, modName, pkgComps, simpleName);
      if mod then
         return function(name) return (name == modName and mod) or nil; end;
      end;

      local loader = nil;
      local reasons = {};
      for _, searcher in ipairs(std.package.loaders) do
         local result = searcher(modName);
         local resultType = stdType(result);
         if resultType == 'function' then
            loader = result;
            break;
         elseif resultType == 'string' then
            stdTabInsert(reasons, result);
         end;
      end;
      return loader or (#reasons > 0 and stdTabConcat(reasons, "\n")) or nil;
   end;
end;

sandboxEnv.module = wrappedModule;
sandboxEnv.require = wrappedRequire;

sandboxEnv.package.config     = std.package.config;
sandboxEnv.package.cpath      = nil;
sandboxEnv.package.loaded     = {};
sandboxEnv.package.loaders    = { sandboxSearcher, builinSearcher };
sandboxEnv.package.loadlib    = nil;  -- Removed completely
sandboxEnv.package.path       = "";
sandboxEnv.package.preload    = {};
sandboxEnv.package.searchpath = nil;  -- (luajit)
sandboxEnv.package.seeall     = wrappedSeeAll;

sandboxEnv.package.loaded._G        = sandboxEnv;
sandboxEnv.package.loaded.coroutine = sandboxEnv.coroutine;
sandboxEnv.package.loaded.io        = sandboxEnv.io;
sandboxEnv.package.loaded.math      = sandboxEnv.math;
sandboxEnv.package.loaded.os        = sandboxEnv.os;
sandboxEnv.package.loaded.package   = sandboxEnv.package;
sandboxEnv.package.loaded.string    = sandboxEnv.string;
sandboxEnv.package.loaded.table     = sandboxEnv.table;
