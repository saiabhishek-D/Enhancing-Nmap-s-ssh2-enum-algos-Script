local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"

local openssl = stdnse.silent_require "openssl"
local ssh2 = stdnse.silent_require "ssh2"

description = [[
Reports the number of algorithms (for encryption, compression, etc.) that
the target SSH2 server offers. If verbosity is set, the offered algorithms
are each listed by type.

If the "client to server" and "server to client" algorithm lists are identical
(order specifies preference) then the list is shown only once under a combined
type.

This script enhances the original ssh2-enum-algos.nse with per-algorithm
strength grading in the style of ssl-enum-ciphers. Each algorithm in the
kex, host key, encryption and MAC lists is labelled STRONG, ACCEPTABLE or
WEAK. Compression algorithms are not graded. An extra "least strength"
entry shows the lowest grade found across all graded algorithms.
]]

---
-- @usage
-- nmap --script ssh2-enum-algos-enhanced2 target
--
-- @output
-- PORT   STATE SERVICE
-- 22/tcp open  ssh
-- | ssh2-enum-algos-enhanced2:
-- |   kex_algorithms (4)
-- |       curve25519-sha256 [STRONG]
-- |       diffie-hellman-group-exchange-sha256 [ACCEPTABLE]
-- |       diffie-hellman-group14-sha256 [ACCEPTABLE]
-- |       diffie-hellman-group14-sha1 [WEAK]
-- |   server_host_key_algorithms (3)
-- |       ssh-ed25519 [STRONG]
-- |       rsa-sha2-256 [STRONG]
-- |       ssh-rsa [WEAK]
-- |   encryption_algorithms (5)
-- |       chacha20-poly1305@openssh.com [STRONG]
-- |       aes256-gcm@openssh.com [STRONG]
-- |       aes128-ctr [ACCEPTABLE]
-- |       aes256-ctr [ACCEPTABLE]
-- |       aes128-cbc [WEAK]
-- |   mac_algorithms (3)
-- |       hmac-sha2-256-etm@openssh.com [STRONG]
-- |       hmac-sha2-256 [ACCEPTABLE]
-- |       hmac-md5 [WEAK]
-- |   compression_algorithms (2)
-- |       none
-- |       zlib@openssh.com
-- |_  least strength: WEAK
--
-- @xmloutput
-- <table key="kex_algorithms">
--   <elem>curve25519-sha256 [STRONG]</elem>
--   <elem>diffie-hellman-group-exchange-sha256 [ACCEPTABLE]</elem>
--   <elem>diffie-hellman-group14-sha256 [ACCEPTABLE]</elem>
--   <elem>diffie-hellman-group14-sha1 [WEAK]</elem>
-- </table>
-- <table key="server_host_key_algorithms">
--   <elem>ssh-ed25519 [STRONG]</elem>
--   <elem>rsa-sha2-256 [STRONG]</elem>
--   <elem>ssh-rsa [WEAK]</elem>
-- </table>
-- <table key="encryption_algorithms">
--   <elem>chacha20-poly1305@openssh.com [STRONG]</elem>
--   <elem>aes256-gcm@openssh.com [STRONG]</elem>
--   <elem>aes128-ctr [ACCEPTABLE]</elem>
--   <elem>aes256-ctr [ACCEPTABLE]</elem>
--   <elem>aes128-cbc [WEAK]</elem>
-- </table>
-- <table key="mac_algorithms">
--   <elem>hmac-sha2-256-etm@openssh.com [STRONG]</elem>
--   <elem>hmac-sha2-256 [ACCEPTABLE]</elem>
--   <elem>hmac-md5 [WEAK]</elem>
-- </table>
-- <table key="compression_algorithms">
--   <elem>none</elem>
--   <elem>zlib@openssh.com</elem>
-- </table>
-- <elem key="least strength">WEAK</elem>

-- ENHANCEMENT START
-- added Sai Abhishek as an additional author for the strength-grading enhancement
author = {"Kris Katterjohn", "Sai Abhishek"}
-- ENHANCEMENT END

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


portrule = shortport.ssh

-- ENHANCEMENT START
-- ============================================================
-- Strength grading helpers
-- ============================================================
-- We use simple numbers so we can compare grades easily.
-- Lower number = weaker.  We track the minimum across all
-- graded algorithms to produce the "least strength" result.
-- ============================================================

local GRADE_WEAK       = 1
local GRADE_ACCEPTABLE = 2
local GRADE_STRONG     = 3

-- turn a numeric grade back into a human-readable label
local grade_label = function(num)
  if num == GRADE_STRONG     then return "STRONG"     end
  if num == GRADE_ACCEPTABLE then return "ACCEPTABLE" end
  return "WEAK"
end

-- -----------------------------------------------
-- grade_kex: grade a single key-exchange algorithm
-- returns nil for marker entries that should not be graded
-- -----------------------------------------------
local grade_kex = function(name)
  local lower = name:lower()

  -- skip marker entries -- these are not real algorithms
  if lower == "ext-info-s" or lower == "ext-info-c" then
    return nil
  end
  if lower:sub(1, 10) == "kex-strict" then
    return nil
  end

  -- WEAK: anything that uses sha1 (e.g. diffie-hellman-group14-sha1)
  if lower:find("sha1", 1, true) then
    return GRADE_WEAK
  end

  -- STRONG: curve25519-sha256 and its variants (e.g. curve25519-sha256@libssh.org)
  if lower:find("curve25519-sha256", 1, true) then
    return GRADE_STRONG
  end

  -- STRONG: sntrup761x25519 post-quantum hybrid
  if lower:find("sntrup761x25519", 1, true) then
    return GRADE_STRONG
  end

  -- STRONG: mlkem post-quantum hybrids (e.g. mlkem768x25519-sha256)
  if lower:find("mlkem", 1, true) then
    return GRADE_STRONG
  end

  -- STRONG: diffie-hellman-group16-sha512 and group18-sha512
  if lower:find("group16-sha512", 1, true) then
    return GRADE_STRONG
  end
  if lower:find("group18-sha512", 1, true) then
    return GRADE_STRONG
  end

  -- everything else is acceptable
  return GRADE_ACCEPTABLE
end

-- -----------------------------------------------
-- grade_hostkey: grade a single host-key algorithm
-- -----------------------------------------------
local grade_hostkey = function(name)
  local lower = name:lower()

  -- WEAK: ssh-dss and ssh-rsa
  if lower == "ssh-dss" or lower == "ssh-rsa" then
    return GRADE_WEAK
  end

  -- STRONG: ssh-ed25519, rsa-sha2-256, rsa-sha2-512
  if lower == "ssh-ed25519"  then return GRADE_STRONG end
  if lower == "rsa-sha2-256" then return GRADE_STRONG end
  if lower == "rsa-sha2-512" then return GRADE_STRONG end

  -- ACCEPTABLE: ecdsa-sha2-* and everything else
  return GRADE_ACCEPTABLE
end

-- -----------------------------------------------
-- grade_encryption: grade a single encryption algorithm
-- -----------------------------------------------
local grade_encryption = function(name)
  local lower = name:lower()

  -- WEAK: "none" (exact match)
  if lower == "none" then return GRADE_WEAK end

  -- WEAK: anything containing cbc, arcfour, des, or blowfish
  if lower:find("cbc",      1, true) then return GRADE_WEAK end
  if lower:find("arcfour",  1, true) then return GRADE_WEAK end
  if lower:find("des",      1, true) then return GRADE_WEAK end
  if lower:find("blowfish", 1, true) then return GRADE_WEAK end

  -- STRONG: chacha20-poly1305@openssh.com
  if lower == "chacha20-poly1305@openssh.com" then
    return GRADE_STRONG
  end

  -- STRONG: the -gcm@openssh.com ciphers (e.g. aes128-gcm@openssh.com)
  if lower:find("-gcm@openssh.com", 1, true) then
    return GRADE_STRONG
  end

  -- ACCEPTABLE: the -ctr ciphers and anything else
  return GRADE_ACCEPTABLE
end

-- -----------------------------------------------
-- grade_mac: grade a single MAC algorithm
-- -----------------------------------------------
local grade_mac = function(name)
  local lower = name:lower()

  -- WEAK: "none" (exact match)
  if lower == "none" then return GRADE_WEAK end

  -- WEAK: anything containing md5, ripemd160, or the "-96" suffix
  if lower:find("md5",       1, true) then return GRADE_WEAK end
  if lower:find("ripemd160", 1, true) then return GRADE_WEAK end
  if lower:find("-96",       1, true) then return GRADE_WEAK end

  -- STRONG: hmac-sha2-*-etm@openssh.com (e.g. hmac-sha2-256-etm@openssh.com)
  if lower:find("hmac-sha2-", 1, true) and lower:find("-etm@openssh.com", 1, true) then
    return GRADE_STRONG
  end

  -- STRONG: umac-128-etm@openssh.com
  if lower == "umac-128-etm@openssh.com" then
    return GRADE_STRONG
  end

  -- everything else is acceptable
  return GRADE_ACCEPTABLE
end

-- -----------------------------------------------
-- get_grader: pick the right grading function for a list name
-- returns nil for compression (we don't grade compression)
-- -----------------------------------------------
local get_grader = function(list_name)
  if list_name:find("kex",        1, true) then return grade_kex        end
  if list_name:find("host_key",   1, true) then return grade_hostkey    end
  if list_name:find("encryption", 1, true) then return grade_encryption end
  if list_name:find("mac_",       1, true) then return grade_mac        end
  -- compression or anything unknown → no grading
  return nil
end
-- ENHANCEMENT END

-- Build onto lists{} and possibly modify parsed{} based on whether the
-- algorithm name-lists are identical between the server-to-client and
-- client-to-server types.  Note that this simply modifies the passed tables.
local combine_types = function(parsed, lists)
  local doubles = {
    "encryption_algorithms",
    "mac_algorithms",
    "compression_algorithms"
  }

  for _, i in ipairs(doubles) do
    local c2s = i .. "_client_to_server"
    local s2c = i .. "_server_to_client"

    if parsed[c2s] == parsed[s2c] then
      parsed[i] = parsed[c2s]
      parsed[c2s] = nil
      parsed[s2c] = nil
      table.insert(lists, i)
    else
      table.insert(lists, c2s)
      table.insert(lists, s2c)
    end
  end
end

-- Build and return the output table
local output = function(parsed, lists)
  local out = stdnse.output_table()

  -- ENHANCEMENT START
  -- start with the highest grade; we'll lower it as we find weaker ones
  local least = GRADE_STRONG
  -- ENHANCEMENT END

  for _, l in ipairs(lists) do
    local v = parsed[l]
    local a = v:len() > 0 and stringaux.strsplit(",", v) or {}

    -- ENHANCEMENT START
    -- grade each algorithm and append a label like " [STRONG]"
    -- compression lists get grader == nil, so they are skipped
    local grader = get_grader(l)
    if grader then
      for i = 1, #a do
        local grade = grader(a[i])
        -- grade is nil for marker entries like ext-info-s (we skip those)
        if grade then
          a[i] = a[i] .. " [" .. grade_label(grade) .. "]"
          -- update the overall weakest grade
          if grade < least then
            least = grade
          end
        end
      end
    end
    -- ENHANCEMENT END

    if nmap.verbosity() > 0 then
      setmetatable(a, {
        __tostring = function(t)
          return string.format("(%d)\n      %s", #t, table.concat(t, "\n      "))
        end
      })
    else
      setmetatable(a, {
        __tostring = function(t)
          return string.format("(%d)", #t)
        end
      })
    end
    out[l] = a
  end

  -- ENHANCEMENT START
  -- return the output table and the overall least strength label
  return out, grade_label(least)
  -- ENHANCEMENT END
end

action = function(host, port)
  local sock = nmap.new_socket()
  local status = sock:connect(host, port)
  if not status then
    return
  end

  -- send the client banner
  -- NB: The protocol does not prescribe which side sends the banner first
  status = sock:send("SSH-2.0-Nmap_SSH2_Enum_Algos\r\n")
  if not status then
    sock:close()
    return
  end

  -- slurp the server banner
  status = sock:receive_buf("\r?\n", false)
  if not status then
    sock:close()
    return
  end

  local ssh = ssh2.transport

  -- send the client key exchange
  -- NB: The protocol does not prescribe which side sends the kex init first
  status = sock:send(ssh.build(ssh.kex_init()))
  if not status then
    sock:close()
    return
  end

  local response
  status, response = ssh.receive_packet(sock)
  sock:close()
  if not status then
    return
  end

  local parsed = ssh.parse_kex_init(ssh.payload(response))

  local lists = {
    "kex_algorithms",
    "server_host_key_algorithms"
    -- Other types will be added below in combine_types()
  }

  -- Modifies tables
  combine_types(parsed, lists)

  -- ENHANCEMENT START
  -- capture both the output table and the weakest grade found
  local out, least_str = output(parsed, lists)

  -- add the "least strength" entry at the very end of the output
  -- a plain string makes Nmap print "least strength: WEAK" with the colon
  out["least strength"] = least_str

  return out
  -- ENHANCEMENT END
end
