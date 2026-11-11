# Changelog

All notable changes to MaldocTrace are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
