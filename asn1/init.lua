--[[
ASN.1 Framework for Lua
Copyright (c) 2015 Kaarle Ritvanen
See LICENSE file for license details
--]]

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

local function factory(params, defaults, decoder, encoder)
   if not params then params = {} end
   for k, v in pairs(defaults or {}) do
      if not params[k] then params[k] = v end
   end
   return {
      _decode=decoder,
      decode=function(data)
	 local value = decoder(data)
	 if value then return value end
	 error('DER data does not conform to type definition')
      end,
      encode=encoder,
      extend=function(dec, enc)
	 return function(par)
	    return factory(
	       par,
	       params,
	       function(data) return dec(decoder(data)) end,
	       function(value) return encoder(enc(value)) end
	    )
	 end
      end
   }
end

local function type_factory(params, defaults, decoder, encoder)
   if not params then params = {} end
   if params.tag and not params.class then params.class = 'context' end

   local function tag()
      -- high tag numbers not supported
      assert(params.tag < 0x1F)

      local res = bit32.bor(
	 ({universal=0x00, context=0x80})[params.class], params.tag
      )
      if params.constructed then res = bit32.bor(res, 0x20) end
      return res
   end

   local function check_length(value)
      return (not params.min or #value >= params.min) and
	 (not params.max or #value <= params.max)
   end

   return factory(
      params,
      defaults,
      function(data)
	 local meta, data = split(data)
	 if #data ~= meta.len then
	    error(
	       'Data length ('..#data..
		  ' does not match with the DER-encoded length ('..meta.len..
		  ')'
	    )
	 end
	 if meta.tag ~= tag() then return end

	 local value = decoder(data)
	 if check_length(value) then return value end
      end,
      function(value)
	 if params.value_type and type(value) ~= params.value_type then
	    error(
	       'Invalid value ('..params.value_type..' expeted, got '..
		  type(value)..')'
	    )
	 end
	 if not check_length(value) then
	    error('Value to be encoded is of invalid length ('..#value..')')
	 end

	 local data = encoder(value)
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

	 return string.char(tag(), table.unpack(enc_len))..data
      end
   )
end

local function str_factory(params, tag)
   local function identity(s) return s end

   return type_factory(
      params,
      {class='universal', constructed=false, tag=tag, value_type='string'},
      identity,
      identity
   )
end

local function seq_factory(params, decoder, encoder)
   return type_factory(
      params,
      {class='universal', constructed=true, tag=0x10, value_type='table'},
      decoder,
      encoder
   )
end


function M.choice(alts)
   return factory(
      nil,
      nil,
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

function M.integer(params)
   return type_factory(
      params,
      {class='universal', constructed=false, tag=0x02, value_type='number'},
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
   )
end

function M.bit_string(params)
   return type_factory(
      params,
      {class='universal', constructed=false, tag=0x03, value_type='string'},
      function(data)
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
	 return value
      end,
      function(value)
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
   )
end

function M.octet_string(params) return str_factory(params, 0x04) end

function M.ia5string(params) return str_factory(params, 0x16) end

function M.explicit(tag, syntax)
   return type_factory(
      {class='context', constructed=true, tag=tag},
      nil,
      function(data) return syntax.decode(data) end,
      function(value) return syntax.encode(value) end
   )
end

function M.sequence(comps, params)
   return seq_factory(
      params,
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

function M.sequence_of(comps, params)
   if not params then params = {} end

   return seq_factory(
      params,
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
