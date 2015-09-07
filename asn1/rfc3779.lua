--[[
Copyright (c) 2015 Kaarle Ritvanen
See LICENSE file for license details
--]]

local asn1 = require('asn1')
local stringy = require('stringy')

local M = {}

M.IPAddrBlocks = asn1.sequence_of(
   asn1.sequence{
      {
	 'addressFamily',
	 asn1.octet_string{size={min=2, max=2}}.extend(
	    function(data)
	       return {
		  afi=bit32.bor(bit32.lshift(data:byte(), 8), data:byte(2, 2)),
		  safi=data:byte(3, 3)
	       }
	    end,
	    function(value)
	       local afi = value.afi
	       afi = string.char(bit32.rshift(afi, 8), bit32.band(afi, 0xFF))
	       return afi..(value.safi and string.char(value.safi) or '')
	    end
         )
      },
      {
	 'ipAddressChoice',
	 asn1.choice{
	    {
	       'addressesOrRanges',
	       asn1.sequence_of(
		  asn1.choice{{'addressPrefix', asn1.bit_string()}}
	       )
	    }
	 }
      }
   }.extend(
      function(data)
	 local params = (
	    {
	       {bits=8, blocks=4, format=function(b) return b end, sep='.'},
	       {
		  bits=16,
		  blocks=8,
		  format=function(b) return ('%04x'):format(b) end,
		  sep=':'
	       }
	    }
         )[data.addressFamily.afi]
	 local max_len = params.blocks * params.bits

	 local addrs = {}
	 for _, addr in ipairs(data.ipAddressChoice.addressesOrRanges) do
	    local bits = addr.addressPrefix
	    local len = #bits
	    while #bits < max_len do bits = bits..'0' end

	    local blocks = {}
	    for i=1,params.blocks do
	       table.insert(
		  blocks,
		  params.format(
		     tonumber(
			bits:sub((i - 1) * params.bits + 1, i * params.bits), 2
		     )
		  )
	       )
	    end

	    table.insert(
	       addrs,
	       {addressPrefix=table.concat(blocks, params.sep)..'/'..len}
	    )
	 end
	 return {
	    addressFamily=data.addressFamily,
	    ipAddressChoice={addressesOrRanges=addrs}
	 }
      end,
      function(value)

	 local function toint(s, max, base)
	    local i = tonumber(s, base)
	    if i and i == math.floor(i) and i >= 0 and i <= max then return i end
	 end

	 local afi = value.addressFamily.afi
	 local addrs = {}

	 for _, addr in ipairs(value.ipAddressChoice.addressesOrRanges) do
	    local function fail() error('Invalid network address: '..addr) end

	    local comps = stringy.split(addr.addressPrefix, '/')
	    if #comps ~= 2 then fail() end

	    local octets = ''
	    local len

	    if afi == 1 then
	       len = toint(comps[2], 32)

	       local octs = {comps[1]:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$')}

	       for i, octet in ipairs(octs) do
		  local oct = toint(octet, 255)
		  if not oct then fail() end
		  octets = octets..string.char(oct)
	       end

	    elseif afi == 2 then
	       len = toint(comps[2], 128)

	       comps = stringy.split(comps[1], ':')
	       if #comps < 3 then fail() end

	       local function collapse(i, ofs)
		  if comps[i] > '' then return end
		  if comps[i + ofs] > '' then return end
		  table.remove(comps, i)
	       end
	       collapse(1, 1)
	       collapse(#comps, -1)
	       if #comps > 8 then fail() end

	       local short
	       for i, comp in ipairs(comps) do
		  if comp == '' then
		     if short then fail() end
		     short = i
		  else
		     local j = toint(comp, 65535, 16)
		     if not j then fail() end
		     comps[i] = string.char(bit32.rshift(j, 8), bit32.band(j, 0xFF))
		  end
	       end

	       if short then
		  table.remove(comps, short)
		  while #comps < 8 do
		     table.insert(comps, short, string.char(0, 0))
		  end

	       elseif #comps < 8 then fail() end

	       octets = table.concat(comps, '')

	    else fail() end


	    local bits = ''

	    repeat
	       local octet = octets:byte()
	       local pos = 7

	       repeat
		  local bit = bit32.rshift(octet, pos)
		  if bits:len() < len then bits = bits..bit
		  elseif bit == 1 then fail() end

		  octet = bit32.band(octet, bit32.rshift(0xFF, 8 - pos))
		  pos = pos - 1
	       until pos == -1

	       octets = octets:sub(2, -1)
	    until octets:len() == 0

	    table.insert(addrs, {addressPrefix=bits})
	 end
	 return {
	    addressFamily=value.addressFamily,
	    ipAddressChoice={addressesOrRanges=addrs}
	 }
      end
   )
)

M.ASIdentifiers = asn1.sequence{
   {
      'asnum',
      asn1.explicit(
	 0,
	 asn1.choice{
	    {
	       'asIdsOrRanges',
	       asn1.sequence_of(asn1.choice{{'id', asn1.integer}})
	    }
	 }
      )
   }
}

return M
