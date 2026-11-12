# Changelog

All notable changes to MaldocTrace are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Verdict and risk score**: every report carries `verdict` (`malicious`, `suspicious`, `clean` or `unknown`), `risk_score` (0-100) and `verdict_reasons`, derived from the evidence already collected: recovered commands, static findings by severity (a high-severity DDE field, remote template, linked object, Equation Editor exploit or `Auto_Open` macro sheet alone is malicious; QR-code and picture-hyperlink lures are suspicious), decoded payloads, executable files, auto-run macros, network indicators next to active content, Excel's default encryption password and the verdicts of embedded files. A partial analysis that found nothing is `unknown`, never `clean`. The text report starts with the verdict. Schema 1.6.0.
- **Embedded objects**: OLE objects are extracted from `.xls` `MBD` storages, `.doc` `ObjectPool` storages and the `word/`, `xl/` and `ppt/embeddings/` folders of OOXML packages:
  - the `\x01Ole` stream is parsed in all three, so a **linked object whose moniker is a URL** (fetched when the file opens, CVE-2017-0199 style) is a high-severity `external_ole` finding with the URL as an indicator;
  - OLE Packages (`\x01Ole10Native`) are decoded (label, original path, temp path, data);
  - the file each object carries (OLE Package data, an OOXML `Package`, a `CONTENTS` stream...) is listed as an artifact and described with the existing PE, shellcode and archive profiling, plus PDF (version, `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/URI`, `/EmbeddedFile`, `/XFA` markers, also inside Flate streams and behind `#xx` name escapes, and the link targets) and scripts (HTA, WSF, VBScript, JScript, batch, PowerShell: findings, indicators and the lines that start programs);
  - embedded Office documents are analysed recursively (depth limit `MaxNestedDepth`, the same resource limits) and reported under `children`, each with its own verdict; the parent verdict takes the worst one.
- `--dump-payloads` also writes the files of embedded documents.
- **Email input**: `.eml` (RFC 5322/MIME: nested multipart, base64, quoted-printable, encoded-word headers, attached `message/rfc822` messages) and Outlook `.msg` (attachment storages, long file names, attached messages). The report lists sender, recipient, subject, date and attachments (text section `Email`, JSON `document_properties` with kind `email`), takes URLs and other indicators from the text and HTML bodies, and analyses every attachment through the normal pipeline as `children`.
- **Archive input**: ZIP (plain, ZipCrypto and WinZip AES) and 7z (including encrypted headers) are opened in memory, never written to disk. The passwords `infected`, `malware` and `virus` are tried after any `--password`. Every member is listed with its hash and type, scripts and executables are reported, and documents (and nested archives) are analysed as `children`. Limits: 512 members, 64 MiB per member, 512 MiB in total, and the `MaxZipRatio` compression ratio. 7z support uses [github.com/bodgit/sevenzip](https://github.com/bodgit/sevenzip) (BSD-3-Clause) v1.6.1, the last release that builds with Go 1.23; since that version does not bound the counts it reads from the header, MaldocTrace validates the 7z header itself before handing it over.
- `--fail-on suspicious|malicious` makes `analyze` exit with code `3` when a file reaches that verdict; without it exit codes are unchanged.

## [0.3.1] - 2026-11-12

Document-variable droppers and the Word 97-2003 static checks.

### Downloads

| Platform | Archive |
|---|---|
| Windows x64 / ARM64 | `maldocTrace_0.3.1_windows_amd64.zip`, `maldocTrace_0.3.1_windows_arm64.zip` |
| Linux x64 / ARM64 | `maldocTrace_0.3.1_linux_amd64.tar.gz`, `maldocTrace_0.3.1_linux_arm64.tar.gz` |
| macOS Intel / Apple Silicon | `maldocTrace_0.3.1_darwin_amd64.tar.gz`, `maldocTrace_0.3.1_darwin_arm64.tar.gz` |

You can verify downloads against `checksums.txt` (SHA-256). The binaries are static and have no dependencies. The macOS builds are not notarized, so remove the quarantine flag before running them: `xattr -d com.apple.quarantine maldocTrace`.

### Added

- Word 97-2003 (`.doc`) documents get the static checks that `.docx` and RTF already had:
  - field codes (DDE/DDEAUTO, `INCLUDEPICTURE`, `INCLUDETEXT`, `LINK`...) in every story, not only the main text: headers, footnotes, comments, endnotes and text boxes;
  - the attached template (`SttbfAssoc` in the table stream), reported as remote template injection when it is a URL or UNC path;
  - embedded and linked OLE objects in the `ObjectPool` storage: class and ProgID (`\x01CompObj`), OLE Packages (`\x01Ole10Native`: label, original path, temp path, size), URL and file monikers of linked objects (`\x01Ole`, CVE-2017-0199 pattern) and the Equation Editor checks used for RTF (`Equation Native`).
- When nothing is found, the text report lists what was checked; the JSON report carries the same list in `checks` (schema 1.5.0).
- Document variables of Word 97-2003 files (`StwUser` in the table stream) are read, so `ThisDocument.Variables("x").Value` returns what droppers stored there.
- `MSXML2.DOMDocument` / `Microsoft.XMLDOM` elements with `DataType` `bin.base64` or `bin.hex`: `NodeTypedValue` decodes `Text` (and encodes in the other direction).
- `ADODB.Stream` is modelled as a positioned stream: `Type`, `Charset` (utf-8 and unicode with their BOM, us-ascii...), `Position`, `Read`, `ReadText`, `SetEOS`. The usual "string to bytes" and "bytes to string" conversions now work.
- Commands that JScript or VBScript code runs through a `WScript.Shell` handed to `ScriptControl.AddObject` (`oShell.run("...")`) are recovered as commands.
- Files the macro writes are identified: JAR files (main class, class and package count), ZIP and OOXML archives, PE files and shellcode.

### Fixed

- `.Member` inside `With` blocks was not parsed, so `With CreateObject(...)` blocks lost every property assignment and method call.
- `ReDim` and `ReDim Preserve` were ignored, so arrays sized at run time stayed empty.
- Function return types such as `As Byte()` broke the parsing of the procedure.
- `ThisDocument.<member>` resolved to the code module only; document members such as `Variables` are now reached when the module defines no procedure of that name.
- Text output lists at most 12 document properties and variables (the rest are in the JSON).

## [0.3.0] - 2026-11-12

Encrypted Office documents, shellcode and PE profiling.

### Downloads

| Platform | Archive |
|---|---|
| Windows x64 / ARM64 | `maldocTrace_0.3.0_windows_amd64.zip`, `maldocTrace_0.3.0_windows_arm64.zip` |
| Linux x64 / ARM64 | `maldocTrace_0.3.0_linux_amd64.tar.gz`, `maldocTrace_0.3.0_linux_arm64.tar.gz` |
| macOS Intel / Apple Silicon | `maldocTrace_0.3.0_darwin_amd64.tar.gz`, `maldocTrace_0.3.0_darwin_arm64.tar.gz` |

You can verify downloads against `checksums.txt` (SHA-256). The binaries are static and have no dependencies. The macOS builds are not notarized, so remove the quarantine flag before running them: `xattr -d com.apple.quarantine maldocTrace`.

### Added

- **Encrypted documents**: Excel's default password `VelvetSweatshop`, common passwords and any `--password` are tried against:
  - `.xls` workbooks with RC4 or RC4 CryptoAPI `FILEPASS` encryption; cells and Excel 4.0 macro sheets are decrypted and analysed;
  - OOXML files in an `EncryptionInfo`/`EncryptedPackage` container with ECMA-376 Standard (AES) or Agile encryption.

  The new `decryption` section reports the scheme and the password that worked. Key-derivation work is bounded against hostile `spinCount` values.
- **Shellcode profiling** for recovered binary payloads: classic and randomized (seeded) ROR13 `block_api` API hashes resolved to `module!function`; `reverse_http(s)` host, port, URI, `User-Agent` and `Host` header, and `reverse_tcp` IP and port, reported as indicators; XOR decoder stubs and single-byte XOR keys that reveal URLs.
- **PE profiling**: subsystem, entry point, sections with entropy and RWX flags, imports grouped by behaviour, .NET and UPX markers, overlay size and PDB path.
- Binary payloads stored as hex text across string literals are recovered statically, even when emulation cannot rebuild the buffer.
- `--password` option for `analyze` (repeatable).

### Fixed

- CFB directories with unused entries between live ones lost every entry after the first gap, so some `.docm` VBA projects were reported as "no VBA storage found".
- `extract` no longer refuses an encrypted `.xls` whose VBA project was read.

### Changed

- JSON schema bumped to `1.4.0` (additive: `decryption`).

## [0.2.1] - 2026-11-11

Licensing and packaging release. The analysis is unchanged from 0.2.0.

### Downloads

| Platform | Archive |
|---|---|
| Windows x64 / ARM64 | `maldocTrace_0.2.1_windows_amd64.zip`, `maldocTrace_0.2.1_windows_arm64.zip` |
| Linux x64 / ARM64 | `maldocTrace_0.2.1_linux_amd64.tar.gz`, `maldocTrace_0.2.1_linux_arm64.tar.gz` |
| macOS Intel / Apple Silicon | `maldocTrace_0.2.1_darwin_amd64.tar.gz`, `maldocTrace_0.2.1_darwin_arm64.tar.gz` |

You can verify downloads against `checksums.txt` (SHA-256).

### Added

- MaldocTrace is now licensed under the Apache License 2.0 (`LICENSE`).

### Changed

- The Go module path is now `github.com/debugactiveprocess/MaldocTrace`, so `go install github.com/debugactiveprocess/MaldocTrace/cmd/maldoctrace@v0.2.1` works and the import path matches the repository (needed for Debian/Kali packaging).

## [0.2.0] - 2026-11-11

Excel 4.0 macros, static detection of macro-less attacks (template injection, DDE, OLE, Equation Editor exploits in RTF), payloads hidden in cells and document properties, and VBA stomping detection.

### Downloads

| Platform | Archive |
|---|---|
| Windows x64 / ARM64 | `maldocTrace_0.2.0_windows_amd64.zip`, `maldocTrace_0.2.0_windows_arm64.zip` |
| Linux x64 / ARM64 | `maldocTrace_0.2.0_linux_amd64.tar.gz`, `maldocTrace_0.2.0_linux_arm64.tar.gz` |
| macOS Intel / Apple Silicon | `maldocTrace_0.2.0_darwin_amd64.tar.gz`, `maldocTrace_0.2.0_darwin_arm64.tar.gz` |

You can verify downloads against `checksums.txt` (SHA-256). The binaries are static and have no dependencies. The macOS builds are not notarized, so remove the quarantine flag before running them: `xattr -d com.apple.quarantine maldocTrace`.

### Added

- **Excel 4.0 (XLM) macros**:
  - macro sheets are read from `.xls` (BIFF8 formulas decompiled from parsed tokens with the MS-XLS Ftab/Cetab tables) and from `.xlsm`, including hidden and very hidden sheets;
  - an XLM interpreter runs from `Auto_Open` with `GOTO`/`RUN`/`IF`/`WHILE`/`FOR`/`NEXT`/`ON.TIME`/`RETURN`, `FORMULA`/`FORMULA.FILL`/`SET.VALUE`/`SET.NAME`, and simulated `EXEC`, `CALL`, `REGISTER` (and aliases), `FOPEN`/`FWRITE`/`FCLOSE`;
  - formulas written at run time are reported as the deobfuscated macro;
  - VBA can reach XLM through `ExecuteExcel4Macro` and `Application.Run "Sheet!Cell"`.
- **Static findings** (new `static_findings` section):
  - remote template injection (`attachedTemplate`, RTF `\*\template`);
  - external OLE objects, with MHTML (CVE-2021-40444) and `ms-msdt` (Follina) monikers flagged;
  - DDE/DDEAUTO fields, including `QUOTE`-encoded and nested fields, in `.docx`, `.doc` and RTF, plus Excel DDE formulas and `ddeLink`s;
  - `INCLUDEPICTURE`/`INCLUDETEXT`/`LINK` fields with remote targets;
  - hidden macro sheets and XLM `Auto_Open` names;
  - hyperlinks on pictures and cells (phishing workbooks), and QR-code lures.
- **RTF support**: format detection (`{\rt`), `\objdata` decoded the way Word reads it (parameters on control words, ignorable groups, junk characters, `\bin`), OLE1 header parsing with a fallback for corrupted headers, and Equation Editor exploit detection: MTEF `FONT` overflow (CVE-2017-11882 / CVE-2018-0802) and `MATRIX` overflow (CVE-2018-0798). The bytes that follow the malformed record are extracted.
- **VBA stomping detection**: string literals compiled into a module's p-code but absent from its source are reported (with the literals as evidence) and scanned for indicators.
- **Payload hiding places available to the emulator**:
  - Excel cells: `Sheets(...)`, `Worksheets(...)`, `Range(...)`, `Cells(r, c)`, `Offset`, and assignment through the default member;
  - document properties (`BuiltInDocumentProperties`, `CustomDocumentProperties`), from OLE property sets and `docProps/*.xml`;
  - document variables (`ActiveDocument.Variables`, from `word/settings.xml`);
  - `TextBox.Text` / `Caption` aliases on UserForm controls.
- New JSON sections `macro_sheets` and `document_properties`. The text report shows static findings, macro sheets, run-time XLM formulas and non-trivial properties.

### Changed

- JSON schema bumped to `1.3.0` (additive).
- Documents with Excel 4.0 macros now report `macros: present`.

## [0.1.0] - 2026-11-11

First public release.

### Downloads

| Platform | Archive |
|---|---|
| Windows x64 / ARM64 | `maldocTrace_0.1.0_windows_amd64.zip`, `maldocTrace_0.1.0_windows_arm64.zip` |
| Linux x64 / ARM64 | `maldocTrace_0.1.0_linux_amd64.tar.gz`, `maldocTrace_0.1.0_linux_arm64.tar.gz` |
| macOS Intel / Apple Silicon | `maldocTrace_0.1.0_darwin_amd64.tar.gz`, `maldocTrace_0.1.0_darwin_arm64.tar.gz` |

You can verify downloads against `checksums.txt` (SHA-256). The binaries are static and have no dependencies. The macOS builds are not notarized, so remove the quarantine flag before running them: `xattr -d com.apple.quarantine maldocTrace`.

### Added

- **Extraction**:
  - OLE/CFB (`.doc`, `.xls`, `.ppt`) and OOXML (`.docm`, `.xlsm`, `.pptm`) containers, plus raw VBA text input.
  - MS-OVBA decompression and UserForm control properties.
  - Resource limits against zip bombs and malformed containers.
- **Document body text** for Word 97-2003 (piece table) and `.docx`, so the emulator can follow macros that read their payload from `ActiveDocument.Paragraphs(n).Range.Text`.
- **VBA interpreter** with bounded execution:
  - procedures, `ByRef` parameters, named arguments (`Name:=value`) and conditional compilation;
  - loops, arrays and the string built-ins;
  - module-level declarations.
- **Static deobfuscation** with provenance and the reconstruction method of each string.
- **Simulated environment** (nothing is ever executed):
  - `WScript.Shell` and `Shell`;
  - WMI `Win32_Process.Create` through `GetObject` or `CreateObject("winmgmts:...")`;
  - `FileSystemObject`, `ADODB.Stream`, `XMLHTTP`/`WinHttp`;
  - `MSScriptControl.ScriptControl`;
  - Word `Paragraphs`/`Range`/`Delete`/`SaveAs2`;
  - declared APIs with simulated `VarPtr` pointers.
- **Payload recovery**:
  - PowerShell `-EncodedCommand`, with static folding of `'a'+'b'` concatenations before URL extraction;
  - UTF-7 shellcode buffers passed to `MultiByteToWideChar(CP_UTF7)`;
  - `certutil -decode`/`-decodehex` chains over a virtual file system;
  - scripts passed to `ScriptControl.AddCode`;
  - PE/ZIP/OLE/PDF identification.
- **Reports**:
  - text output and versioned JSON (schema `1.2.0`), with evidence IDs linking events, commands, payloads and indicators;
  - batch `jsonl` mode with `--recursive`.
- **CLI options**:
  - `--show-strings` for deduplicated reconstructed strings with their locations;
  - `--dump-payloads DIR` to write decoded payloads and dropped files with neutral extensions and a `manifest.json`.
- **Robustness**: each pipeline stage recovers from panics and records them as diagnostics. The VBA pipeline and container parsers are fuzzed.

[Unreleased]: https://github.com/debugactiveprocess/MaldocTrace/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/debugactiveprocess/MaldocTrace/releases/tag/v0.3.1
[0.3.0]: https://github.com/debugactiveprocess/MaldocTrace/releases/tag/v0.3.0
[0.2.1]: https://github.com/debugactiveprocess/MaldocTrace/releases/tag/v0.2.1
[0.2.0]: https://github.com/debugactiveprocess/MaldocTrace/releases/tag/v0.2.0
[0.1.0]: https://github.com/debugactiveprocess/MaldocTrace/releases/tag/v0.1.0
