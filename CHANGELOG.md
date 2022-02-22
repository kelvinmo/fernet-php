# Changelog

## Version 1.0.1

- Added: Support for 64-bit timestamps when using 64-bit version of PHP
- Changed: `encode()` now throws a `RuntimeException` if an error occurred
  during encryption

## Version 1.0.0

- Removed: Support for PHP 5

## Version 0.5.1

- Fixed: return null on decode() if an error occurred during decryption

## Version 0.5.0

- Fixes timing attack vulnerability (#1)

## Version 0.4.0

- Use native random bytes function under PHP 7

## Version 0.3.0

- Corrected system requirements (PHP 5.4 or later)
- Added Travis CI configuration

## Version 0.2.0

- Fixed namespace bug for `\Exception`

## Version 0.1.0

- Initial release
