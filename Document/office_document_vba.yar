rule office_document_vba
{
	meta:
		description = "MS document (.doc/.xls/.ppt) with embedded VBA"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-12-17"
		reference = "N/A"

	strings:
		$magic = { D0 CF 11 E0 A1 B1 1A E1 }

		$str1 = "_VBA_PROJECT" wide
		$str2 = "VBAProject"
		$str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F }

	condition:
		$magic at 0 and any of ($str*)
}
