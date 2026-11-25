# Acme Health: GRC Engineering Capstone Write-up

## Primary framework
The primary framework chosen is **CMMC Level 2**. This framework was chosen because CMMC Level 2 is a requirement for an increasing number of federal contracts and the underlying framework, NIST SP 800-171, is the framework required in the upcoming FAR CUI rule, which will expand this compliance with NIST SP 800-171 to all federal contracting. By aligning with CMMC Level 2, the project is well positioned for federal contracts going forward.

Additionally, because NIST SP 800-171/CMMC is focused on the *Confidentiality* aspect of the CIA triad, it provides a good lead-in to the HIPAA requirements for protecting PHI. While not a straight one-to-one map, a CMMC foundation will implement many of the requirements for protecting PHI.

## Control coverage
[For each gap from GAPS.md: which control it maps to, and whether you closed
it in Terraform, enforced it in policy, or both. A table works well here.]

## Design decisions
[Walk each decision from the brief: region, Object Lock mode, apply-on-merge
vs manual gate, single vs separate account, Terraform-vs-policy split.
For each, state what you chose and the trade-off you accepted.]

**Object Lock mode:** Governance was chosen to allow for cleanup after while still providing protection of the evidence.
**Apply-on-merge:** The deploy gate runs automatically on merge to main. This was chosen to keep main consistent with deployed resources. A manual gate could be missed and allow drift.
**Single Account:** A single account was used to facilitate cleanup after and to make management of resources easier.
**Terraform:** Terraform was chosen to address gaps to follow the IaC and PaC philosophies and keep the terraform code as the source of truth. The tradeoff is that changes made via console might not be detected until the next terraform apply.

## How the pipeline produces evidence
[Trace one run end to end: PR opened → gate → apply → sign → vault.
Name the run ID an assessor can verify.]

## Trade-offs and what I'd do with another sprint
[Be specific and honest. This section earns more than a padded "everything works."]

## What I didn't get to
[Name it plainly. This costs nothing and signals judgment.]

# CGE-P Capstone Write-Up


## Terraform baseline

The Terraform baseline was updated to address the following gaps:

- GAP-01: S3 uploads bucket relies on AWS-managed SSE-S3 
    - Added server-side encryption with customer-owned keys 
- GAP-03: S3 uploads bucket has no policy denying non-TLS requests (no `aws:SecureTransport` deny)
    - Added policy denying non-TLS requests
- GAP-04: S3 uploads bucket has no versioning. PHI overwrites are unrecoverable. 
    - Added versioning to the S3 uploads bucket

