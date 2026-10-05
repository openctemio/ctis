### Added: CSAF 2.0 and OpenVEX importers

- `importer.Parse` reads CSAF 2.0 documents (the `csaf_vex` and `csaf_security_advisory` profiles) and OpenVEX documents (v0.2.0, and the v0.0.1 string forms). A VEX document describes products, not findings: the report has no assets or findings, and `Result.VEX` holds the statements, each with the vulnerability's typed ids, the products (PURL, CPE, or name and version) and the CTIS VEX status, justification, statement, source and date.
- CSAF: the product tree is resolved (branches at any depth, full product names, relationships, product groups); first/last affected, first fixed and recommended merge into the affected and fixed statements; a not_affected statement takes its justification from the flags and its text from the impact threats, an affected or fixed statement its text from the remediations.
- `Product.Subcomponents`: a statement about components inside a product only (an OpenVEX subcomponent, a CSAF relationship). A receiver must match those components only on that product.
- A mapping spec `**` segment matches any number of path segments, for formats that nest to any depth.

### Security

- VEX documents are hostile input. A `not_affected` statement with neither a recognized justification nor an impact statement is left out with an issue, so a bare claim never suppresses a finding. Undefined, circular and over-limit product references are refused or left out, and links in the documents (SBOM URLs, references) are never fetched.
