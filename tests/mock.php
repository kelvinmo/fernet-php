<?php

namespace Fernet;

class FernetMock extends Fernet {
    private $time;

    public function __construct($key, $time) {
        parent::__construct($key);
        $this->time = $time;
    }

    protected function getTime() {
        return $this->time;
    }
}

class FernetGenerateMock extends FernetMock {
    private $iv;

    public function __construct($key, $time, $iv) {
        parent::__construct($key, $time);
        $this->iv = $iv;
    }

    protected function getIV() {
        return $this->iv;
    }
}

?>