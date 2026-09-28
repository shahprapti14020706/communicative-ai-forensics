# Synthetic test fixtures

Tests use temporary storage and randomly generated credentials. Contact details,
names, card numbers and identity-shaped strings in assertions are synthetic
masking inputs, never records copied from an investigation. Phone fixtures use
the fictional +1 202 555 0100 number; email fixtures use example or `.test` domains.
The fixed SHA-256 test vector is for the public string `abc`. The demonstration
checksum in `modules/demo_setup.py` identifies the bundled fictional sample.
Neither checksum is a password digest or a production evidence hash.

Do not add production evidence, credentials, sessions or exported test reports.
