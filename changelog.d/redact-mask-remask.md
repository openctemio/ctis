### Fixed: a secret whose text is part of the mask word is masked once

- `RedactSecretFinding` (and `FromSARIF` for secret findings) set the snippet and `secret.masked_value` to their mask before masking every other field, so a raw value such as `CTED` was masked again inside `REDACTED` and the snippet read `REDAREDACTED`. The mask is now set after the other fields. No raw value was exposed: the result was over-masked, not under-masked. Found by `FuzzFromSARIF`.
