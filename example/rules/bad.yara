
rule bad : log store delete {
	meta:
		created_at = 1493332105
		created_by = "Stephen Vickers"
		description = "Identify node binary"
		is_stable = true
	strings:
		$f1 = "_ZN2v812HeapProfiler11GetObjectIdENS_5LocalINS_5ValueEEE"
		$f2 = "ELF"
	condition:
		($f2 at 1) and $f1
}

import "magic"

rule binary {
	condition:
		magic.mime_type() == "application/x-object"
}

