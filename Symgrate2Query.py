#Quick symgrate.com client script for Thumb2 symbol recovery.
#@author Travis Goodspeed & evm
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


## This is an IDA script that queries the Symgrate2
## database, in order to recognize standard functions from a variety
## of embedded ARM development kits.

## By default it scans for both processor matches (based on register accesses)
## and function matches

import idc
import ida_idaapi
import ida_segment

import json
import symgrate2

def ida_renamefunctions(j):
    x=json.loads(j)
    for f in x:
        fnameu=x[f]["Name"]
        fname=fnameu.encode('utf-8')
        print("renaming %s to %s" % (f,fname))
        fadr=int(f,16)
        ida_name.set_name(fadr,fnameu,ida_name.SN_NOCHECK)
       

def ida_functionprefix(fun):
    """Returns the first eighteen bytes of a function as ASCII."""
    B=bytearray(ida_bytes.get_bytes(fun, symgrate2.SEARCHLEN));
    bstr="";
    for b in B: bstr+="%02x"%(0x00FF&b)
    return bstr;
    
def do_periph_regs_query():
    qlist=[]
    
    #Build a list of all accesses in the Cortex M peripheral range
    for x in range(0x40000000,0x40500000):
        if not next(DataRefsTo(x),None) is None:
            read=False
            write=False
            for r in XrefsTo(x, ida_xref.XREF_DATA):
               if r.type == 3:
                 read=True
               if r.type == 2:
                 write=True
            astr=""
            if (read):
              astr+="r"
            if (write):
              astr+="w"
            if (astr == ""):
              astr="u"
            #print("0x%x=%s" % (x,astr))
            qlist.append((x,astr))
    
    srv = symgrate2.symgrate()
    res=srv.queryjregs(qlist)

    if res!=None:
        print("Possible processor matches:")
        srv.jprint(res)
    else:
        print("no response")
    

def do_full_binary_func_query():
    # Iterate over all the functions, querying from the database and printing them.
    fnhandled=0;

    qstr="";
    qlist=[];

    srv = symgrate2.symgrate()

    start=0
    end=0
    t = ida_segment.get_segm_by_name(".text")
    if (t and t.start_ea != ida_idaapi.BADADDR):
        start = t.start_ea
        end = t.end_ea
    else:
        start = idc.get_next_func(0)
        end = ida_idaapi.BADADDR

    f=start

    while (f != ida_idaapi.BADADDR) and (f <= end):
        iname=idc.get_func_name(f)
        adr=f
        adrstr="%x"%f
        res=None

        bstr = ida_functionprefix(f)
        # We query the server in batches of 64 functions to reduce HTTP overhead.

        qlist.append((adrstr,bstr))
        #qstr+="%s=%s&"%(adrstr,bstr)
        f = idc.get_next_func(f)

        if fnhandled&0x3F==0 or f is None:
            res=srv.queryjfns(qlist)
            qstr=""
            if res!=None:
                srv.jprint(res)
                #optionally rename functions to the values found in the query
                ida_renamefunctions(res)
        
        fnhandled+=1

    res=srv.queryjfns(qlist)
    if res!=None: 
        srv.jprint(res)
        #optionally rename functions
        ida_renamefunctions(res)

if __name__ == "__main__":
    do_periph_regs_query()
    do_full_binary_func_query()
