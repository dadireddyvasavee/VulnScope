# Ethics & Safety
- AEGIS **never executes** samples; it only reads bytes and pre-generated reports.
- Do not upload live malware to shared or production machines. Handle samples only inside an isolated, authorized analysis VM with networking disabled or sinkholed.
- No malware binaries are stored in this repository. Tests use synthetic, non-functional PE files and synthetic sandbox reports.
- EICAR is used as the only "detection" test string; it is a harmless industry-standard test file.
- Verdicts are decision support for analysts, not automatic attribution or punishment.
- Respect dataset licenses (EMBER, BODMAS) and any sharing restrictions on samples.
