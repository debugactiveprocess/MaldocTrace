# Changelog

All notable changes to MaldocTrace are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/debugactiveprocess/MaldocTrace/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/debugactiveprocess/MaldocTrace/releases/tag/v0.1.0
