local security = select(1, ...);
local std = security.std;
local sandboxEnv = security.sandboxEnv;


-- Top-Level Whitelist

local TOP_LEVEL_WHITELIST =
   {
      basic_dump          = true,
      check_attached_node = true,
      cleanup_path        = true,
      core                = true,
      digprop_err         = true,
      DIR_DELIM           = true,
      drop_attached_node  = true,
      dump                = true,
      dump2               = true,
      file_exists         = true,
      get_last_folder     = true,
      INIT                = true,
      ItemStack           = true,
      minetest            = true,
      nodeupdate          = true,
      nodeupdate_single   = true,
      on_dignode          = true,
      on_placenode        = true,
      PerlinNoise         = true,
      PerlinNoiseMap      = true,
      PLATFORM            = true,
      PseudoRandom        = true,
      Settings            = true,
      spawn_falling_node  = true,
      vector              = true,
      VoxelArea           = true,
      VoxelManip          = true,
   };
for symbol, whitelisted in pairs(TOP_LEVEL_WHITELIST) do
   if whitelisted then
      sandboxEnv[symbol] = std[symbol];
   end;
end;


-- Mod and World Paths
--
-- Uses virtual filesystem.

local wrappedGetWorldPath;
local wrappedGetModPath;
local wrappedSettings;
local wrappedCreateSchematic;
local wrappedPlaceSchematic;
do
   local mtGetModPath = security.mtGetModPath;
   local toRealPath = security.toRealPath;
   local stdError = std.error;
   local stdStrFind = std.string.find;
   local stdType = std.type;
   local mtSettings = std.Settings;
   local mtCreateSchematic = std.minetest.create_schematic;
   local mtPlaceSchematic = std.minetest.place_schematic;

   wrappedGetWorldPath = function()
      return "/world";
   end;

   wrappedGetModPath = function(modName)
      if mtGetModPath(modName) then
         return "/mods/" .. modName;
      else
         return nil;
      end;
   end;

   wrappedSettings = function(fileName)
      local realPath, err = toRealPath(fileName);
      if not realPath then return stdError(err); end;
      return mtSettings(realPath);
   end;

   wrappedCreateSchematic = function(p1, p2, probList, fileName, sliceProbList)
      local realPath, err = toRealPath(fileName);
      if not realPath then return stdError(err); end;
      return mtCreateSchematic(p1, p2, realPath, sliceProbList);
   end;

   wrappedPlaceSchematic = function(pos, schematic, rot, repl, forcePlace)
      if stdType(schematic) == 'table' then
         return mtPlaceSchematic(pos, schematic, rot, repl, forcePlace);
      elseif stdType(schematic) == 'string' then
         local realPath, err = toRealPath(fileName);
         if not realPath then return stdError(err); end;
         return mtPlaceSchematic(pos, realPath, rot, repl, forcePlace);
      else
         return stdError("Schematic specifier neither a string or table");
      end;
   end;
end;


sandboxEnv.minetest.get_worldpath    = wrappedGetWorldPath;
sandboxEnv.minetest.get_modpath      = wrappedGetModPath;
sandboxEnv.minetest.create_schematic = wrappedCreateSchematic;
sandboxEnv.minetest.place_schematic  = wrappedPlaceSchematic;

sandboxEnv.string.split = std.string.split;
sandboxEnv.string.trim  = std.string.trim;
sandboxEnv.table.copy   = std.table.copy;
sandboxEnv.Settings     = wrappedSettings;
