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

This is an enhanced version of ssh2-enum-algos.nse by Kris Katterjohn.
It adds a Terrapin attack check (CVE-2023-48795). The server is flagged
VULNERABLE if it offers chacha20-poly1305@openssh.com, or any CBC cipher
together with an -etm MAC, and does NOT advertise kex-strict-s-v00@openssh.com
in its kex_algorithms list.
]]

---
-- @usage
-- nmap --script ssh2-enum-algos-enhanced1 target
--
-- @output
-- PORT   STATE SERVICE
-- 22/tcp open  ssh
-- | ssh2-enum-algos-enhanced1:
-- |   kex_algorithms (4)
-- |       diffie-hellman-group-exchange-sha256
-- |       diffie-hellman-group-exchange-sha1
-- |       diffie-hellman-group14-sha1
-- |       diffie-hellman-group1-sha1
-- |   server_host_key_algorithms (2)
-- |       ssh-rsa
-- |       ssh-dss
-- |   encryption_algorithms (13)
-- |       aes128-ctr
-- |       aes192-ctr
-- |       aes256-ctr
-- |       arcfour256
-- |       arcfour128
-- |       aes128-cbc
-- |       3des-cbc
-- |       blowfish-cbc
-- |       cast128-cbc
-- |       aes192-cbc
-- |       aes256-cbc
-- |       arcfour
-- |       rijndael-cbc@lysator.liu.se
-- |   mac_algorithms (6)
-- |       hmac-md5
-- |       hmac-sha1
-- |       hmac-ripemd160
-- |       hmac-ripemd160@openssh.com
-- |       hmac-sha1-96
-- |       hmac-md5-96
-- |   compression_algorithms (2)
-- |       none
-- |       zlib@openssh.com
-- |   terrapin (CVE-2023-48795):
-- |_      NOT VULNERABLE - no chacha20-poly1305 or CBC+ETM combination found
--
-- @xmloutput
-- <table key="kex_algorithms">
--   <elem>ecdh-sha2-nistp256</elem>
--   <elem>ecdh-sha2-nistp384</elem>
--   <elem>ecdh-sha2-nistp521</elem>
--   <elem>diffie-hellman-group-exchange-sha256</elem>
--   <elem>diffie-hellman-group-exchange-sha1</elem>
--   <elem>diffie-hellman-group14-sha1</elem>
--   <elem>diffie-hellman-group1-sha1</elem>
-- </table>
-- <table key="server_host_key_algorithms">
--   <elem>ssh-rsa</elem>
--   <elem>ecdsa-sha2-nistp256</elem>
-- </table>
-- <table key="encryption_algorithms">
--   <elem>aes128-ctr</elem>
--   <elem>aes192-ctr</elem>
--   <elem>aes256-ctr</elem>
--   <elem>aes128-cbc</elem>
--   <elem>3des-cbc</elem>
--   <elem>blowfish-cbc</elem>
--   <elem>cast128-cbc</elem>
--   <elem>aes192-cbc</elem>
--   <elem>aes256-cbc</elem>
-- </table>
-- <table key="mac_algorithms">
--   <elem>hmac-sha1</elem>
--   <elem>umac-64@openssh.com</elem>
--   <elem>hmac-ripemd160</elem>
--   <elem>hmac-sha2-256</elem>
--   <elem>hmac-sha2-512</elem>
-- </table>
-- <table key="compression_algorithms">
--   <elem>none</elem>
--   <elem>zlib@openssh.com</elem>
-- </table>
-- <table key="terrapin (CVE-2023-48795)">
--   <elem>NOT VULNERABLE - no chacha20-poly1305 or CBC+ETM combination found</elem>
-- </table>

author = {"Kris Katterjohn", "Sai Abhishek"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


portrule = shortport.ssh

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

  for _, l in ipairs(lists) do
    local v = parsed[l]
    local a = v:len() > 0 and stringaux.strsplit(",", v) or {}
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

  return out
end

-- ENHANCEMENT START
-- helper: split a comma-separated string into a plain table of strings.
-- returns an empty table if the input is nil or empty, so we never crash.
local split_algos = function(csv)
  if not csv or csv == "" then
    return {}
  end
  return stringaux.strsplit(",", csv)
end

-- helper: check if a table (list) contains a specific string value.
-- just loops through each item — nothing fancy.
local list_has = function(tbl, value)
  for _, item in ipairs(tbl) do
    if item == value then
      return true
    end
  end
  return false
end

-- helper: check if any item in the table ends with the given suffix.
-- we use this to look for "-etm@openssh.com" MACs.
local any_ends_with = function(tbl, suffix)
  for _, item in ipairs(tbl) do
    -- string.sub with a negative index grabs the last N characters
    if string.sub(item, -#suffix) == suffix then
      return true
    end
  end
  return false
end

-- helper: check if any item in the table contains the given substring.
-- we use this to look for "-cbc" ciphers.
local any_contains = function(tbl, substring)
  for _, item in ipairs(tbl) do
    if string.find(item, substring, 1, true) then
      return true
    end
  end
  return false
end

-- Terrapin check (CVE-2023-48795).
-- Takes the parsed kex_init fields and returns two strings:
--   result  : "VULNERABLE" or "NOT VULNERABLE"
--   reason  : a short human-readable explanation
local check_terrapin = function(parsed)
  -- split each relevant algorithm list into a real table
  local kex_list = split_algos(parsed["kex_algorithms"])

  -- encryption can be combined or split; handle both cases
  local enc_combined = parsed["encryption_algorithms"]
  local enc_c2s     = parsed["encryption_algorithms_client_to_server"]
  local enc_s2c     = parsed["encryption_algorithms_server_to_client"]

  -- merge all encryption entries into one list for checking
  local enc_list = {}
  if enc_combined and enc_combined ~= "" then
    for _, a in ipairs(split_algos(enc_combined)) do
      table.insert(enc_list, a)
    end
  end
  if enc_c2s and enc_c2s ~= "" then
    for _, a in ipairs(split_algos(enc_c2s)) do
      table.insert(enc_list, a)
    end
  end
  if enc_s2c and enc_s2c ~= "" then
    for _, a in ipairs(split_algos(enc_s2c)) do
      table.insert(enc_list, a)
    end
  end

  -- same idea for MAC lists
  local mac_combined = parsed["mac_algorithms"]
  local mac_c2s      = parsed["mac_algorithms_client_to_server"]
  local mac_s2c      = parsed["mac_algorithms_server_to_client"]

  local mac_list = {}
  if mac_combined and mac_combined ~= "" then
    for _, a in ipairs(split_algos(mac_combined)) do
      table.insert(mac_list, a)
    end
  end
  if mac_c2s and mac_c2s ~= "" then
    for _, a in ipairs(split_algos(mac_c2s)) do
      table.insert(mac_list, a)
    end
  end
  if mac_s2c and mac_s2c ~= "" then
    for _, a in ipairs(split_algos(mac_s2c)) do
      table.insert(mac_list, a)
    end
  end

  -- does the server advertise the strict-kex countermeasure?
  local has_strict_kex = list_has(kex_list, "kex-strict-s-v00@openssh.com")

  -- does the server offer chacha20-poly1305?
  local has_chacha = list_has(enc_list, "chacha20-poly1305@openssh.com")

  -- does the server offer any CBC cipher AND any encrypt-then-mac MAC?
  local has_cbc = any_contains(enc_list, "-cbc")
  local has_etm = any_ends_with(mac_list, "-etm@openssh.com")
  local has_cbc_with_etm = has_cbc and has_etm

  -- decide vulnerable or not
  if has_strict_kex then
    -- strict kex is present, so terrapin is mitigated
    return "NOT VULNERABLE", "server advertises strict kex (countermeasure present)"
  end

  -- no strict kex — check for the dangerous algorithm combos
  if has_chacha and has_cbc_with_etm then
    return "VULNERABLE", "offers chacha20-poly1305 and CBC cipher with ETM MAC, no strict kex"
  elseif has_chacha then
    return "VULNERABLE", "offers chacha20-poly1305 and no strict kex"
  elseif has_cbc_with_etm then
    return "VULNERABLE", "offers CBC cipher with ETM MAC and no strict kex"
  end

  -- no dangerous combos found
  return "NOT VULNERABLE", "no chacha20-poly1305 or CBC+ETM combination found"
end
-- ENHANCEMENT END

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

  -- ENHANCEMENT START
  -- run the terrapin check BEFORE combine_types, because combine_types
  -- may nil-out the _client_to_server / _server_to_client keys.
  -- we want access to all raw parsed fields for a thorough check.
  local terrapin_result, terrapin_reason = check_terrapin(parsed)
  -- ENHANCEMENT END

  -- Modifies tables
  combine_types(parsed, lists)

  local out = output(parsed, lists)

  -- ENHANCEMENT START
  -- add the terrapin result as the last entry in the output table
  local terrapin_line = terrapin_result .. " - " .. terrapin_reason
  local terrapin_display = { terrapin_line }
  setmetatable(terrapin_display, {
    __tostring = function(t)
      return "\n      " .. t[1]
    end
  })
  out["terrapin (CVE-2023-48795)"] = terrapin_display
  -- ENHANCEMENT END

  return out
end
