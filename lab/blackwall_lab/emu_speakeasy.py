"""Run one Speakeasy emulation and write report.json + dumps/ to an output dir.

Invoked by the lab server in a separate process so a crashing or runaway
emulation can't take the MCP server down.

usage: emu_speakeasy.py <sample> <outdir> <timeout> <max_api> [shellcode_arch] [export]
"""

import json
import sys
from collections import Counter
from pathlib import Path

import speakeasy
from speakeasy.config import SpeakeasyConfig, get_default_config_dict

ARCH = {"x86": "x86", "i386": "x86", "x64": "amd64", "amd64": "amd64"}


def _fmt_args(args) -> str:
    out = []
    for a in args or []:
        out.append(str(a.get("display", a.get("value"))) if isinstance(a, dict) else str(a))
    return ", ".join(out)


def summarize(rep: dict) -> dict:
    eps = []
    all_apis = Counter()
    for ep in rep.get("entry_points", []):
        trace, last, other = [], None, {}
        n_api = 0
        for e in ep.get("events", []):
            kind = e.get("event")
            if kind == "api":
                n_api += 1
                all_apis[e.get("api_name")] += 1
                line = f"{e.get('api_name')}({_fmt_args(e.get('args'))}) -> {e.get('ret_val')}"
                if line != last:  # collapse loops
                    trace.append(line)
                last = line
            elif kind not in ("mem_read", "mem_write"):
                ev = {k: v for k, v in e.items() if k not in ("pos", "event", "data")}
                ev["pc"] = hex(e.get("pos", {}).get("pc", 0))
                other.setdefault(kind, []).append(ev)
        eps.append({
            "ep_type": ep.get("ep_type"), "start": ep.get("start_addr"),
            "ret_val": ep.get("ret_val"), "error": ep.get("error"),
            "api_trace": trace[:400], "api_calls_total": n_api,
            "events": {k: v[:50] for k, v in other.items()},
        })
    return {
        "arch": rep.get("arch"),
        "runtime_s": rep.get("emulation_total_runtime"),
        "errors": rep.get("errors"),
        "entry_points": eps,
        "api_counts": dict(all_apis.most_common(60)),
        "dynamic_strings": (rep.get("strings") or {}).get("in_memory"),
    }


SKIP_TAGS = ("emu.module", "emu.stack", "emu.gdt", "emu.segment", "emu.struct")


def _unmap(img: bytes) -> bytes:
    """Make a memory-layout PE image parseable: point each section's raw data
    at its virtual address so file offset == RVA."""
    import pefile
    try:
        pe = pefile.PE(data=img, fast_load=True)
        for s in pe.sections:
            s.PointerToRawData = s.VirtualAddress
            s.SizeOfRawData = max(s.Misc_VirtualSize, s.SizeOfRawData)
        return pe.write()
    except Exception:
        return img


def _module_regions(se, prefix: str) -> dict:
    return {base: data for tag, base, size, free, proc, data in se.get_memory_dumps()
            if str(tag or "").startswith(prefix)}


def main():
    sample, outdir, timeout, max_api = sys.argv[1], Path(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4])
    sc_arch = sys.argv[5] if len(sys.argv) > 5 else ""
    export = sys.argv[6] if len(sys.argv) > 6 else ""
    dumps = outdir / "dumps"
    dumps.mkdir(parents=True, exist_ok=True)

    cfg = get_default_config_dict()
    cfg["timeout"] = timeout
    cfg["max_api_count"] = max_api
    cfg["keep_memory_on_free"] = True
    cfg = SpeakeasyConfig.model_validate(cfg)

    se = speakeasy.Speakeasy(config=cfg)
    module = None
    before, mod_prefix = {}, None
    try:
        if sc_arch:
            addr = se.load_shellcode(sample, ARCH[sc_arch.lower()])
            se.run_shellcode(addr)
        else:
            module = se.load_module(sample)
            mod_prefix = f"emu.module.{Path(sample).name}."
            before = _module_regions(se, mod_prefix)
            if export:
                # Run only the requested export of a DLL.
                rva = next((e.address - module.get_base() for e in module.get_exports()
                            if e.name == export), None)
                if rva is None:
                    raise SystemExit(f"export not found: {export}")
                se.run_module(module, entry_point=rva)
            else:
                se.run_module(module, all_entrypoints=True)
    except Exception as e:  # keep whatever the emulator collected
        print(f"emulation stopped: {type(e).__name__}: {e}", file=sys.stderr)

    rep = json.loads(se.get_json_report())

    # Dump memory regions that now hold a PE image (unpacked/injected payloads),
    # skipping the loaded modules and emulator internals.
    seen = set()
    for tag, base, size, is_free, proc, data in se.get_memory_dumps():
        tag = str(tag or "")
        if not data or tag.startswith(SKIP_TAGS):
            continue
        idx = data.find(b"MZ")
        while idx != -1 and idx < len(data) - 0x40:
            lfanew = int.from_bytes(data[idx + 0x3C:idx + 0x40], "little")
            if lfanew < 0x1000 and data[idx + lfanew:idx + lfanew + 4] == b"PE\0\0":
                blob = data[idx:]
                key = hash(blob[:4096])
                if key not in seen:
                    seen.add(key)
                    (dumps / f"pe_{base + idx:#x}_{tag.replace('/', '_')[:40]}.bin").write_bytes(blob)
            idx = data.find(b"MZ", idx + 2)

    # In-place unpackers (UPX and friends) rewrite the module's own sections:
    # if they changed, dump the module as a memory-layout image.
    if before:
        after = _module_regions(se, mod_prefix)
        if any(after.get(b) != d for b, d in before.items()):
            lo = min(after)
            hi = max(b + len(d) for b, d in after.items())
            img = bytearray(hi - lo)
            for b, d in after.items():
                img[b - lo:b - lo + len(d)] = d
            (dumps / f"module_image_{lo:#x}_unmapped.bin").write_bytes(_unmap(bytes(img)))

    archive = se.create_file_archive()
    if archive:
        (dumps / "dropped_files.zip").write_bytes(archive)

    (outdir / "report.json").write_text(json.dumps({"summary": summarize(rep), "raw": rep}, default=str))


if __name__ == "__main__":
    main()
