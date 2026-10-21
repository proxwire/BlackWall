# Third-party notices

BlackWall's optional analysis image aggregates independently licensed tools.
BlackWall's MIT license does not replace their terms. The release SBOMs are the
authoritative version inventory; the list below records the direct toolchain
review performed for the 0.1.0 image.

| Component | Upstream | License family / notice location |
|---|---|---|
| Ubuntu base and apt packages | <https://packages.ubuntu.com/> | Per-package notices under `/usr/share/doc/*/copyright` |
| Ghidra | <https://github.com/NationalSecurityAgency/ghidra> | Apache-2.0; upstream `LICENSE` remains in `/opt/ghidra` |
| radare2 / r2mcp | <https://github.com/radareorg/radare2>, <https://github.com/radareorg/radare2-mcp> | LGPL/GPL and component-specific terms; Debian notices remain under `/usr/share/doc` |
| Detect It Easy | <https://github.com/horsicq/DIE-engine> | MIT; Debian package notice remains under `/usr/share/doc` |
| capa | <https://github.com/mandiant/capa> | Apache-2.0; exact tagged license copied to `/opt/blackwall/licenses/capa-LICENSE.txt` |
| FLOSS | <https://github.com/mandiant/flare-floss> | Apache-2.0; exact tagged license copied to `/opt/blackwall/licenses/FLOSS-LICENSE.txt` |
| UPX / UCL | <https://github.com/upx/upx> | GPL-2.0-or-later with the UPX exception; exact notice copied to `/opt/blackwall/licenses/UPX-LICENSE` |
| cabextract / libmspack | <https://www.cabextract.org.uk/> | GPL-family cabextract terms and libmspack terms; exact source notice copied to `/opt/blackwall/licenses/cabextract-COPYING` |
| Node.js | <https://github.com/nodejs/node> | MIT plus bundled third-party notices under `/opt/node` |
| Reverse Engineering Assistant | <https://www.npmjs.com/package/rea-agents> | Package and transitive terms retained in `/opt/rea/runtime/node_modules` and enumerated by the npm SBOM |
| JADX bridge / JADX | <https://github.com/1013503897/jadx-headless-mcp>, <https://github.com/skylot/jadx> | Upstream project terms; pinned bridge JAR version is recorded in the image build |
| WABT | <https://github.com/WebAssembly/wabt> | Apache-2.0; exact tagged license copied to `/opt/blackwall/licenses/WABT-LICENSE` |
| .NET runtime | <https://github.com/dotnet/runtime> | MIT plus third-party notices retained under `/opt/dotnet` |
| ILSpy | <https://github.com/icsharpcode/ILSpy> | MIT; exact release license copied to `/opt/blackwall/licenses/ILSpy-LICENSE` |
| Python packages | Python package indexes linked by package metadata | Per-distribution `.dist-info` notices under `/opt/venv`; versions and hashes in the Python SBOM |

The prebuilt image is published only from a GitHub-verified signed release tag.
Each release attaches Python, npm, and complete runtime-image SBOMs. Maintainers
must repeat this notice/license review when adding a direct tool, changing its
distribution form, or changing a license. This inventory is not legal advice.
