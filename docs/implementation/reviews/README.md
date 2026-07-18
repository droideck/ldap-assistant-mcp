# Independent review records

Store one final frozen-bundle review per task at `<TASK_ID>.json`, based on `../templates/REVIEW_TEMPLATE.json`. Every acceptance criterion must be explicitly `approved`, the overall verdict must be `approve`, findings and inspected tests must be concrete, both bundle verification and at least one relevant test must be independently rerun successfully, the mechanically recomputed unresolved critical/high count must be zero, and the reviewed identity must equal the independently recomputed bundle SHA-256. Record the enforceably read-only reviewer task ID plus the original admission-contract SHA-256, admitted HEAD, and baseline SHA-256 receipts. Material product/test/contract changes after review require a new bundle and review.

Critical/high findings, an unproven acceptance criterion, or a reviewer whose write denial is not enforced outside local JSON block completion.
