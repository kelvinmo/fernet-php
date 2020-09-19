# Fernet-PHP

[![Latest Stable Version](https://poser.pugx.org/kelvinmo/fernet-php/v/stable)](https://packagist.org/packages/kelvinmo/fernet-php)
[![Build Status](https://travis-ci.org/kelvinmo/fernet-php.svg?branch=master)](https://travis-ci.org/kelvinmo/fernet-php)

Fernet-PHP is an implementation of the [Fernet token specification](https://github.com/fernet/spec/blob/master/Spec.md)
in PHP.

## Requirements

- PHP 7.0 or later
- `hash` extension
- `openssl` or `mcrypt` extension
- `mbstring.func_overload` needs to be switched **off** in `php.ini`

## Installation

You can install via [Composer](http://getcomposer.org/).

```sh
composer require kelvinmo/fernet-php
```

## Usage

```php
<?php
require 'vendor/autoload.php';

use Fernet\Fernet;

$key = '[Base64url encoded fernet key]';
$fernet = new Fernet($key);

$token = $fernet->encode('string message');

$message = $fernet->decode('fernet token');
if ($message === null) {
    echo 'Token is not valid';
}

?>
```

## License

BSD 3 clause
