// ============================================================
// CAU EDR — bundled YARA rules
//
// Conventions:
//   * Text strings carry `ascii wide` so they match both the narrow strings in
//     scripts and the UTF-16LE strings in Windows binaries. The original rules
//     were ASCII-only and never fired on mimikatz.exe, whose command strings
//     are wide.
//   * Byte patterns are written as hex strings, not as the text "0x89,0x00".
//   * meta.threat_level 1-5, meta.family names the family the rule claims.
//   * meta.mitre_attack (optional) is the ATT&CK technique id; the fusion
//     lattice and the coverage reporting read it.

rule wannacry_ransomware
{
    meta:
        author = "CAU"
        description = "WannaCry / WanaCrypt0r dropper and payload strings"
        family = "wannacry"
        threat_level = 5
        in_the_wild = true

    strings:
        $b = "C:\\%s\\qeriuwjhrf" ascii wide
        $c = "WNcry@2017" ascii wide
        $d = "msg/m_bulgarian.wnry" ascii wide
        $e = "WanaCryptor" ascii wide
        $f = "tasksche.exe" ascii wide
        $g = "WanaCrypt0r" ascii wide

    condition:
        3 of them
}

rule mimikatz_strings
{
    meta:
        author = "CAU"
        description = "Mimikatz module and command strings (binary or script carrier)"
        family = "mimikatz"
        threat_level = 5
        in_the_wild = true

    strings:
        $m1 = "sekurlsa::logonpasswords" ascii wide nocase
        $m2 = "mimikatz" ascii wide nocase
        $m3 = "lsadump::sam" ascii wide nocase
        $m4 = "kerberos::tickets" ascii wide nocase
        $m5 = "privilege::debug" ascii wide nocase
        $m6 = "gentilkiwi" ascii wide nocase

    condition:
        2 of them
}

rule generic_ransomware_extensions
{
    meta:
        author = "CAU"
        description = "Ransomware: encrypted-file extensions together with ransom-note file names"
        family = "ransomware"
        threat_level = 3

    strings:
        // Extensions alone are useless: Go binaries alone carry ".crypt",
        // ".locked" and ".encrypted" as ordinary identifiers (measured: 18 false
        // positives in /usr/bin). They only count next to a ransom-note name.
        $ext1 = ".locked" ascii wide
        $ext2 = ".encrypted" ascii wide
        $ext3 = ".crypt" ascii wide
        $note1 = "restore_files" ascii wide nocase
        $note2 = "how_to_decrypt" ascii wide nocase
        $note3 = "decrypt_instructions" ascii wide nocase
        $note4 = "decrypt_my_files" ascii wide nocase
        $note5 = "files have been encrypted" ascii wide nocase
        $note6 = "recover_your_files" ascii wide nocase

    condition:
        2 of ($ext*) and 1 of ($note*)
}

rule highly_sus_shellcode
{
    meta:
        author = "CAU"
        description = "x86/x64 shellcode stubs: PEB walk and API-hashing prologues"
        family = "shellcode"
        threat_level = 3
        in_the_wild = true

    strings:
        // The previous version of this rule matched the *text* "0x89,0x00,..."
        // (a C array rendering) and could never fire on real bytes.
        $b = { 89 00 00 00 60 89 }
        $c = { 01 D0 50 8B }
        $d = { 93 31 C0 66 }
        $e = { 83 EC 04 EB CE }
        // mov eax, fs:[30h] / mov ebx, fs:[30h]  (x86 PEB access)
        $peb32a = { 64 A1 30 00 00 00 }
        $peb32b = { 64 8B ( 1D | 0D | 15 | 35 | 3D ) 30 00 00 00 }
        // mov rax, gs:[60h]  (x64 PEB access)
        $peb64 = { 65 48 8B 04 25 60 00 00 00 }
        // ror 0x0d API hashing loop
        $ror13 = { C1 C? 0D }

    condition:
        3 of them
}

rule lokibot_stealer
{
    meta:
        author = "CAU"
        description = "LokiBot credential-store file names"
        family = "lokibot"
        threat_level = 4

    strings:
        $l1 = "pass.txt" ascii wide nocase
        $l2 = "wallet.dat" ascii wide nocase
        $l3 = "cookies.sqlite" ascii wide nocase
        $l4 = "logins.json" ascii wide nocase
        $l5 = "FileZilla" ascii wide nocase

    condition:
        3 of them
}

rule obfuscated_powershell
{
    meta:
        author = "CAU"
        description = "PowerShell obfuscation and download-cradle markers"
        family = "powershell_cradle"
        threat_level = 3
        in_the_wild = true

    strings:
        // The previous version listed four base64 fragments of one specific
        // payload and was effectively a hash with extra steps.
        $ps = "powershell" ascii wide nocase
        // an -enc / -EncodedCommand switch followed by an actual base64 payload
        $enc_payload = /-e(nc|ncodedcommand)?[ \t]+[A-Za-z0-9+\/=]{40,}/ ascii wide nocase
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "FromBase64String(" ascii wide nocase
        $iex1 = "Invoke-Expression" ascii wide nocase
        $iex2 = "IEX(" ascii wide nocase
        $dl1  = "DownloadString(" ascii wide nocase
        $dl2  = "DownloadFile(" ascii wide nocase
        $dl3  = "Net.WebClient" ascii wide nocase
        $hid1 = "-WindowStyle Hidden" ascii wide nocase
        $hid2 = "-w hidden" ascii wide nocase
        $nop  = "-NoProfile" ascii wide nocase
        $byp  = "-ExecutionPolicy Bypass" ascii wide nocase

    condition:
        $ps and
        (
            $enc_payload or
            (1 of ($dl*) and (1 of ($iex*) or 1 of ($hid*) or $nop or $byp)) or
            (1 of ($enc*) and 1 of ($iex*) and (1 of ($hid*) or $nop or $byp))
        )
}
