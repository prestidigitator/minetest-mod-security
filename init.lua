-- Query basic environment

local function getLuaVersion()
   local v = _VERSION;
   if type(v) == 'string' and #v > 4 then
      local prefix = string.sub(v, 1, 4);
      local suffix = string.sub(v, 5);
      if prefix == "Lua " then return suffix; end;
   end;

   local err = "Lua version '".._VERSION.."' is not a recognized format and "..
               "is not supported by the security mod.";
   minetest.log('error', err);
   error(err);
end;

local LUA_VERSION = getLuaVersion();
local MOD_NAME = minetest.get_current_modname();
local MOD_PATH = minetest.get_modpath(MOD_NAME);
local WORLD_PATH = minetest.get_worldpath();
local mtGetModPath = minetest.get_modpath;
local std = _G;

---- REVISIT: WON'T WORK
-- This mod MUST be the first one loaded (including the game's "default" mod)
-- local mods = std.minetest.get_modnames();
-- if #mods > 1 or (#mods == 1 and mods[1] ~= MOD_NAME) then
--    local message =
--       MOD_NAME..": ERROR!  Other mods loaded before security mod.  This is "..
--       "a CRITICAL SECURITY PROBLEM and might result in system corruption.  "..
--       "Make sure to add '"..MOD_NAME.."' to all other mods' 'depends.txt' "..
--       "files.";
--
--    std.minetest.log('error', message);
--    std.print(message);
--    std.os.exit();
--    std.error(message);  -- Should never reach here, but just in case
-- end;

-- Create (local!) environments and namespaces

local sandboxEnv = {};
sandboxEnv._G = sandboxEnv;

local security = {};
security.LUA_VERSION = LUA_VERSION;
security.MOD_NAME = MOD_NAME;
security.MOD_PATH = MOD_PATH;
security.WORLD_PATH = WORLD_PATH;
security.mtGetModPath = mtGetModPath;
security.std = std;
security.sandboxEnv = sandboxEnv;

local function callModChunk(fileName, ...)
   local chunk, err = std.loadfile(MOD_PATH .. "/" .. fileName .. ".lua");
   if not chunk then std.error(err); end;
   return chunk(security, ...);
end;
security.callModChunk = callModChunk;

-- Do sandboxing

callModChunk("sandboxLuaStdlib-" ..  LUA_VERSION);
callModChunk("sandboxMinetestApi");

-- Final installation of the sandbox environment

std.setfenv(0, security.sandboxEnv);
