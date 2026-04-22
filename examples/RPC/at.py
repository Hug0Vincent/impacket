#!/usr/bin/env python3
from impacket.dcerpc.v5 import transport, atsvc
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException

def main(target, username, password, domain="", command=r"cmd.exe /c whoami"):
    # ncacn_np over \pipe\atsvc
    stringbinding = r"ncacn_np:%s[\pipe\atsvc]" % target
    rpctransport = transport.DCERPCTransportFactory(stringbinding)

    if hasattr(rpctransport, 'set_credentials'):
        rpctransport.set_credentials(username, password, domain)

    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(atsvc.MSRPC_UUID_ATSVC)

    # ---- Build AT_INFO struct ----
    request = atsvc.NetrJobAdd()
    request['ServerName'] = NULL
    request['pAtInfo']['JobTime'] = NULL
    request['pAtInfo']['DaysOfMonth'] = 0
    request['pAtInfo']['DaysOfWeek'] = 0
    request['pAtInfo']['Flags'] = 0
    request['pAtInfo']['Command'] = command

    at_info = atsvc.AT_INFO()
    at_info['JobTime']      = 60  # minutes after midnight (01:00)
    at_info['DaysOfMonth']  = 0   # use DaysOfWeek instead
    at_info['DaysOfWeek']   = 0x7F  # every day (bits 0–6 = Sun–Sat)
    at_info['Flags']        = atsvc.TASK_FLAG_INTERACTIVE
    at_info['Command']      = command

    try:
        #resp = atsvc.hNetrJobAdd(dce, NULL, request)
        resp = dce.request(request)
        resp.dump()
        job_id = resp['pJobId']
        print(f"[+] Job created successfully with JobId: {job_id}")
    except DCERPCException as e:
        print(f"[!] RPC Error: {e}")
    finally:
        dce.disconnect()


if __name__ == "__main__":
    # EDIT these or wrap with argparse
    target   = "10.13.37.102"
    username = "test"
    password = "Azerty1234!"
    domain = "LAB.LOCAL"
    cmd = "cmd.exe /c whoami \x00"
    main(target, username, password, domain, cmd)