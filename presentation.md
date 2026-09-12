## TL-WR741ND Router
### `RCE`


![alt text](static/wr741nd.png)

---

### Target választás

- TP-Link WR741ND
- EOL (Elég régi, már akkor)
- Éveket nem volt használva
- Olcsó (~3k JMF), gagyi
- Publikus, *nem* encrypted FW

---

### Target megismerése

- Firmware vizsgálat
- Webes felület nézegetése
- Reverse engineering

---

### Firmware vizsgálat

Firmware "kibontása" (`binwalk` / `unblob`), majd az `init` folyamat vizsgálata

```bash
➜ cat etc/inittab
::sysinit:/etc/rc.d/rcS
::respawn:/sbin/getty ttyS0 115200
::shutdown:/bin/umount -a

➜ cat etc/rc.d/rcS
#!/bin/sh
# This script runs when init it run during the boot process.
# Mounts everything in the fstab
...
/usr/bin/httpd &
...
```

---

### Webes felület vizsgálata

"beszédes" végpont nevek, meylekre rá lehet kereseni a binárisban

![alt text](static/userrpm.png)

---

### Reverse engineering

A `string` parancs kimenetében megkerestem ami érdekelt

```bash
➜ strings httpd | grep '/userRpm/'

/userRpm/DMZRpm.htm
/userRpm/UpnpCfgRpm.htm
/userRpm/AccessCtrlAccessRulesRpm.htm
/userRpm/AccessCtrlAccessRuleModifyRpm.htm
/userRpm/AccessCtrlAccessRulesAdvRpm.htm
...
```

---v

### Reverse engineering

Cross ref-ek alapján megnéztem ezek hogy vannak használva

![alt text](static/endpoints.png)

---v

### Reverse engineering

Ghidra script:
- Összegyűjti a végpontokat
- Kattintható label a handler-ekre

```python
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

import collections

NAME_PATTERN = "ConfAdd"

# Contains the name of functions and which parameters are interesting for us
FUNC_TYPES = {
    "httpAliasConfAdd": [0, 1],
    "httpPwdConfAdd": [0],
    "httpCtrlConfAdd": [0, 1, 2],
    "httpFsConfAdd": [0, 1],
    "httpUploadConfAdd": [0, 1],
    "httpRpmConfAdd": [0],
}

def getString(addr):
	mem = currentProgram.getMemory()
	core_name_str = ""
	while True:
		byte = mem.getByte(addr.add(len(core_name_str)))
		if byte == 0:
			return core_name_str
		core_name_str += chr(byte)

def find_functions_by_name(fm):
    functions = []
    funcs = fm.getFunctions(True) # True means 'forward'
    for func in funcs:
        name =  func.getName()
        if NAME_PATTERN in name:
            if name != "httpSysRpmConfAdd" and name != 'httpMimeParseFnConfAdd':
                functions.append(func)
    return functions

def check_xrefs(func, address):
    for ref in getReferencesTo(func.getEntryPoint()):
        if ref.getFromAddress() == address:
            return True
    return False

# This is honestly a bit hacky, I'd probably need to look at this more
def get_call_args(func, decompiled_caller, caller):
    high_func = decompiled_caller.getHighFunction()
    opiter = high_func.getPcodeOps()
    ops = collections.deque([], 5)
    res = []
    called = 0
    while opiter.hasNext():
        op = opiter.next()
        mnemonic = str(op.getMnemonic())
        if "COPY" in mnemonic:
            ops.appendleft(op)
        elif "CAST" in mnemonic:
            called = op.getInput(0).getAddress()
        elif "CALL" in mnemonic:
            if called != 0:
                if type(called) == int:
                    called = func.getEntryPoint().getAddress(str(called)).getAddress()
                if check_xrefs(func, called):
                    for idx in FUNC_TYPES[func.getName()]:
                        val = toAddr(ops[idx].getInput(0).getOffset())
                        print "\t\t" + getString(val) + " - ",
                    print(" ")
    return res
                                                


def main():
    monitor = ConsoleTaskMonitor()
    program = getCurrentProgram()
    fm = program.getFunctionManager()
    di = DecompInterface()
    di.openProgram(program)

    functions = find_functions_by_name(fm)
    for func in functions:
        print("{} >> ".format(func.getName()))
        callers = func.getCallingFunctions(monitor)
        for caller in callers:
            print("\t{} >>".format(caller.getName()))
            decomp_caller = di.decompileFunction(caller, 100, monitor)
            args = get_call_args(func, decomp_caller, caller)

main()
```

---v

### Reverse engineering

Egyesével végignéztem a handler-eket és bumm

![alt text](static/civuln.png)

> ~3 nap munka

---v

### Reverse engineering

Alternatíva: az `execFormatCmd` alapján bejárni a hívási láncokat

![alt text](static/callchain.png)

---

### Overview

<div class="mermaid">
  <pre>
    flowchart LR
      A[Attacker]
      subgraph Router
          B[Web Interface]
          subgraph httpd
            C[Handler1]
            D[WlanEnable]
            E[...]
          end
      end
      A --> B
      B --> D
      D --Shell--> A
  </pre>
</div>

---

### Tanulságok

- Ghidra használat
- Reversing flow gyakorlás (feedback miatt)
- Validáció gyors teszttel (PoC helyett)
- Ghidra scripting

---

## YuNoHost
### **Fail?**

TODO

---

## TL-Archer AX23 Router
### **Fail**

---

### Target választás

- A kamrában találtam :)
- Elég drága (~30k JMF)
- Nem EOL!
- Publikus, *nem* encrypted FW

---

### Target választás

Végül nem is a router lett a fő célpont

![alt text](static/tether.png)

---

### Target megismerése

- Gyors ismerkedés
- Alkalmazása beállítása
- Reverse engineering
- Firmware vizsgálat

---

### Target megismerése

Lehallgattam a 

### Reverse engineering

