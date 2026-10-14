// Starter rules. Drop more .yar files (e.g. signature-base, your own) anywhere
// under rules/yara/ and rebuild, or write case rules with the yara_test tool.

rule BW_UPX_Packed
{
    meta:
        description = "UPX section names or magic present"
    strings:
        $s1 = "UPX0"
        $s2 = "UPX1"
        $m  = "UPX!"
    condition:
        2 of them
}

rule BW_Embedded_PE
{
    meta:
        description = "Additional PE header after offset 0 (dropper/loader payload)"
    strings:
        $dos = "This program cannot be run in DOS mode"
    condition:
        uint16(0) == 0x5A4D and #dos > 1
}

rule BW_AntiDebug_Imports
{
    meta:
        description = "Common anti-debug / anti-analysis API names"
    strings:
        $a1 = "IsDebuggerPresent"
        $a2 = "CheckRemoteDebuggerPresent"
        $a3 = "NtQueryInformationProcess"
        $a4 = "OutputDebugString"
        $a5 = "GetTickCount"
        $a6 = "QueryPerformanceCounter"
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule BW_Injection_APIs
{
    meta:
        description = "Classic process injection API set"
    strings:
        $a1 = "VirtualAllocEx"
        $a2 = "WriteProcessMemory"
        $a3 = "CreateRemoteThread"
        $a4 = "NtUnmapViewOfSection"
        $a5 = "SetThreadContext"
        $a6 = "QueueUserAPC"
    condition:
        uint16(0) == 0x5A4D and 3 of them
}
