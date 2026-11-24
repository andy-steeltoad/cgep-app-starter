# CGE-P Capstone Write-Up

## Primary Framework

The primary framework chosen is **CMMC Level 2**. This framework was chosen because CMMC Level 2 is a requirement for an increasing number of federal contracts and the underlying framework, NIST SP 800-171, is the framework required in the upcoming FAR CUI rule, which will expand this compliance with NIST SP 800-171 to all federal contracting. By aligning with CMMC Level 2, the project is well positioned for federal contracts going forward.

Additionally, because NIST SP 800-171/CMMC is focused on the *Confidentiality* aspect of the CIA triad, it provides a good lead-in to the HIPAA requirements for protecting PHI. While not a straight one-to-one map, a CMMC foundation will implement many of the requirements for protecting PHI.

## Terraform baseline

The Terraform baseline was updated to address the following gaps:

- GAP-01: S3 uploads bucket relies on AWS-managed SSE-S3 
    - Added server-side encryption with customer-owned keys 
- GAP-03: S3 uploads bucket has no policy denying non-TLS requests (no `aws:SecureTransport` deny)
    - Added policy denying non-TLS requests
- GAP-04: S3 uploads bucket has no versioning. PHI overwrites are unrecoverable. 
    - Added versioning to the S3 uploads bucket

