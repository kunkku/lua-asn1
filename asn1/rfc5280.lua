--[[
Copyright (c) 2015 Kaarle Ritvanen
See LICENSE file for license details
--]]

local asn1 = require('asn1')

local M = {}

M.KeyIdentifier = asn1.octet_string

M.AuthorityKeyIdentifier = asn1.sequence{
   {'keyIdentifier', M.KeyIdentifier{tag=0}}
}

M.CRLDistributionPoints = asn1.sequence_of(
   asn1.sequence{
      {
	 'distributionPoint',
	 asn1.explicit(
	    0,
	    asn1.choice{
	       {
		  'fullName',
		  asn1.sequence_of(
		     asn1.choice{
			{'uniformResourceIdentifier', asn1.ia5string{tag=6}}
		     }
		  ){tag=0, size={min=1}}
	       }
	    }
	 )
      }
   }
){size={min=1}}

M.CRLNumber = asn1.integer{min=0}

return M
