package request

const (
	// Next release add feature to parse PGP messages
	// beginPGPMes = "-----BEGIN PGP SIGNED MESSAGE-----"
	// beginPGPSig = "-----BEGIN PGP SIGNATURE-----"
	// endPGPSig   = "-----END PGP SIGNATURE-----"

	// HTTP client fields
	securityTXTAlt = "/security.txt"
	securityTXTAlt2 = "/.well-known/security.txt"
	securityTXTAlt3 = "/contact-security"
	securityTXTAlt4 = "/responsible-disclosure"
	securityTXTAlt5 = "/security"
	securityTXTAlt6 = "/security/vdp"
	securityTXTAlt7 = "/infosec"
	securityTXTAlt8 = "/contact"
	securityTXTAlt9 = "/responsible-disclosure-policy"
	securityTXTAlt10 = "/security-responsible-disclosure"
	securityTXTAlt11 = "/security/report-vulnerability"
	securityTXTAlt12 = "/security-disclosure"
	securityTXTAlt13 = "/vulnerability-disclosure"
	securityTXTAlt14 = "/bug-bounty"
	securityTXTAlt15 = "/security/reports"
	securityTXTAlt16 = "/vdp"
	securityTXTAlt17 = "/security-team"
	securityTXTAlt18 = "/security/report"
	securityTXTAlt19 = "/security/vulnerability-report"
	securityTXTAlt20 = "/security/disclosure-policy"
	securityTXTAlt21 = "/responsible-security"
	securityTXTAlt22 = "/security/report-bug"
	securityTXTAlt23 = "/security/bug-report"
	securityTXTAlt24 = "/info/vulnerability-disclosure"
	securityTXTAlt25 = "/info/security-disclosure"
	securityTXTAlt26 = "/info/report-vulnerability"
	securityTXTAlt27 = "/infosec/vulnerabilities"
	securityTXTAlt28 = "/responsible-disclosure-program"
	securityTXTAlt29 = "/report-security-issue"
	securityTXTAlt30 = "/secure/report"
	
	userAgent      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
	cacheHeader    = "no-cache, private, max-age=0"
	statusOK       = 200
	statusIMUsed   = 226

	HTTPError       = "file may not exist - HTTP error code: "
	HTTPtimeoutSecs = 10
)
