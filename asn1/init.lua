--[[
ASN.1 Framework for Lua
Copyright (c) 2015-2025 Kaarle Ritvanen
See LICENSE file for license details
--]]

local bit32 = require('bit32')

local M = {}

local function split(data)
   local meta = {tag=data:byte(), len=data:byte(2)}
   local ml = 2

   -- high tag numbers not supported
   assert(bit32.band(meta.tag, 0x1F) ~= 0x1F)

   if bit32.band(meta.len, 0x80) == 0x80 then
      ml = 2 + bit32.band(meta.len, 0x7F)
      if ml < 3 then error('Invalid long length encoding') end

      meta.len = 0
      for _, b in ipairs{data:byte(3, ml)} do
	 meta.len = bit32.bor(bit32.lshift(8, meta.len), b)
      end
   end

   meta.total_len = ml + meta.len
   return meta, data:sub(ml + 1, -1)
end

local function check_type(v, t)
   local vt = type(v)
   if vt ~= t then error('Invalid value ('..t..' expected, got '..vt..')') end
end

local function define(decoder, encoder, params)
   if not params then params = {} end

   local function decode(data) return decoder(data, params) end
   local function encode(value) return encoder(value, params) end

   return setmetatable(
      {
	 _decode=decode,
	 decode=function(data)
	    local value = decode(data)
	    if value ~= nil then return value end
	    error('DER data does not conform to type definition')
	 end,
	 encode=encode,
	 extend=function(dec, enc)
	    return define(
	       function(data) return dec(decode(data)) end,
	       function(value) return encode(enc(value)) end,
	       params
	    )
	 end
      },
      {
	 __call=function(t, p)
	    if p then
	       if p.tag and not p.class then p.class = 'context' end
	       setmetatable(p, {__index=params})
	    else p = params end
	    return define(decoder, encoder, p)
	 end
      }
   )
end

local function define_type(decoder, encoder)

   local function tag(params)
      -- high tag numbers not supported
      assert(params.tag < 0x1F)

      local res = bit32.bor(
	 ({universal=0x00, context=0x80})[params.class], params.tag
      )
      if params.constructed then res = bit32.bor(res, 0x20) end
      return res
   end

   local function check_range(value, bounds)
      return (not bounds.min or value >= bounds.min) and
	 (not bounds.max or value <= bounds.max)
   end

   local function check_size(value, params)
      return not params.size or check_range(#value, params.size)
   end

   return define(
      function(data, params)
	 local meta, data = split(data)
	 if #data ~= meta.len then
	    error(
	       'Data length ('..#data..
		  ' does not match with the DER-encoded length ('..meta.len..
		  ')'
	    )
	 end
	 if meta.tag ~= tag(params) then return end

	 local value = decoder(data, params)
	 if check_size(value, params) and check_range(value, params) then
	    return value
	 end
      end,
      function(value, params)
	 if params.value_type then check_type(value, params.value_type) end
	 if not check_size(value, params) then
	    error('Value to be encoded is of invalid length ('..#value..')')
	 end
	 if not check_range(value, params) then
	    error(
	       'Value to be encoded is outside the allowed range ('..value..')'
	    )
	 end

	 local data = encoder(value, params)
	 local len = #data
	 local enc_len = {}

	 if len < 0x80 then enc_len[1] = len
	 else
	    while len > 0 do
	       table.insert(enc_len, 1, bit32.band(len, 0xFF))
	       len = bit32.rshift(8, len)
	    end
	    table.insert(enc_len, 1, bit32.bor(0x80, #enc_len))
	 end

	 return string.char(tag(params), table.unpack(enc_len))..data
      end
   )
end

local function define_str(tag)
   local function identity(s) return s end
   return define_type(identity, identity){
      class='universal', constructed=false, tag=tag, value_type='string'
   }
end

local function define_seq(decoder, encoder)
   return define_type(decoder, encoder){
      class='universal', constructed=true, tag=0x10, value_type='table'
   }
end


function M.choice(alts)
   return define(
      function(data)
	 for _, alt in ipairs(alts) do
	    local value = alt[2]._decode(data)
	    if value then return {[alt[1]]=value} end
	 end
      end,
      function(value)
	 local data
	 for _, alt in ipairs(alts) do
	    local v = value[alt[1]]
	    if v then
	       if data then error('Ambiguous choice definition') end
	       data = alt[2].encode(v)
	    end
	 end
	 if data then return data end
	 error('Value to be encoded does not conform to any choice alternative')
      end
   )
end

M.boolean = define_type(
   function(data) return string.byte(data) ~= 0x00 end,
   function(value) return string.char(value and 0xFF or 0x00) end
){class='universal', constructed=false, tag=0x01, value_type='boolean'}

M.integer = define_type(
   function(data)
      local value = string.byte(data)

      -- negative integers not supported
      assert(bit32.band(value, 0x80) == 0x00)

      for _, b in ipairs{string.byte(data, 2, -1)} do
	 value = value * 256 + b
      end
      return value
   end,
   function(value)
      if value ~= math.floor(value) then
	 error('Not an integer: '..value)
      end

      -- negative integers not supported
      assert(value > -1)

      local octs = {}
      while value > 0 do
	 table.insert(octs, 1, value % 256)
	 value = math.floor(value / 256)
      end
      if bit32.band(octs[1], 0x80) == 0x80 then table.insert(octs, 1, 0) end
      return string.char(table.unpack(octs))
   end
){class='universal', constructed=false, tag=0x02, value_type='number'}

M.bit_string = define_type(
   function(data, params)
      local unused = data:byte()
      if unused > 7 then error('Invalid DER encoding for unused bits') end

      local value = ''
      while #data > 1 do
	 data = data:sub(2, -1)
	 local oct = data:byte()
	 for i=7,#data == 1 and unused or 0,-1 do
	    local mask = bit32.lshift(1, i)
	    value = value..(bit32.band(oct, mask) == mask and '1' or '0')
	 end
      end

      if not params.enum then return value end

      local m = {}
      for i = 1,#value do m[params.enum[i]] = value:sub(i, i) == '1' end
      return m
   end,
   function(value, params)
      if params.enum then
	 check_type(value, 'table')
	 local s = ''
	 for _, k in ipairs(params.enum) do
	    s = s..(value[k] and '1' or '0')
	 end
	 value = s
      else check_type(value, 'string') end

      local octs = {}
      local unused = 0
      while value > '' do
	 local oct = 0
	 unused = 8
	 while value > '' and unused > 0 do
	    unused = unused - 1
	    oct = bit32.bor(
	       oct, bit32.lshift(tonumber(value:sub(1, 1), 2), unused)
	    )
	    value = value:sub(2, -1)
	 end
	 table.insert(octs, oct)
      end
      table.insert(octs, 1, unused)
      return string.char(table.unpack(octs))
   end
){class='universal', constructed=false, tag=0x03}

M.octet_string = define_str(0x04)

M.ia5string = define_str(0x16)

function M.explicit(tag, syntax)
   return define_type(
      function(data) return syntax.decode(data) end,
      function(value) return syntax.encode(value) end
   ){class='context', constructed=true, tag=tag}
end

function M.sequence(comps)
   return define_seq(
      function(data)
	 local value = {}
	 for _, comp in ipairs(comps) do
	    local meta = split(data)
	    value[comp[1]] = comp[2].decode(data:sub(1, meta.total_len))
	    data = data:sub(meta.total_len + 1, -1)
	 end
	 if data > '' then
	    error('Excess data after a DER-encoded sequence')
	 end
	 return value
      end,
      function(value)
	 local data = ''
	 for _, comp in ipairs(comps) do
	    data = data..comp[2].encode(value[comp[1]])
	 end
	 return data
      end
   )
end

function M.sequence_of(comps)
   return define_seq(
      function(data)
	 local value = {}
	 while data > '' do
	    local meta = split(data)
	    table.insert(value, comps.decode(data:sub(1, meta.total_len)))
	    data = data:sub(meta.total_len + 1, -1)
	 end
	 return value
      end,
      function(value)
	 local data = ''
	 for _, comp in ipairs(value) do data = data..comps.encode(comp) end
	 return data
      end
   )
end


return M
