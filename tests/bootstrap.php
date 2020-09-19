<?php

set_include_path(implode(PATH_SEPARATOR, array(
    dirname(__FILE__) . '/../src/',
    dirname(__FILE__) . '/',
    get_include_path(),
)));

chdir(dirname(__FILE__) . '/');

spl_autoload_register(function ($class) {
    $class = ltrim($class, '\\');

    if (strncmp('Fernet\\', $class, 7) === 0) {
        $relative_class = substr($class, 7);
        $file = dirname(__FILE__) . '/../src/' . $relative_class . '.php';
        if (file_exists($file)) {
            include_once $file;
        }
    }
    return;
});

?>
