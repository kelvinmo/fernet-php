<?php

namespace Fernet;

use PHPUnit\Framework\TestCase;

class FernetTest extends TestCase {

    public function __construct() {
        parent::__construct();
        date_default_timezone_set('UTC');
    }

    protected function getGenerateInstance($key, $time, $iv) {
        return new FernetGenerateMock($key, $time, $iv);
    }

    protected function getVerifyInstance($key, $time) {
        return new FernetMock($key, $time);
    }

    function testGenerate() {
        $tests = json_decode(file_get_contents('generate.json'));

        foreach ($tests as $test) {
            $iv = implode(array_map('chr', $test->iv));;
            $time = strtotime($test->now);
            $fernet = $this->getGenerateInstance($test->secret, $time, $iv);
            $this->assertEquals($test->token, $fernet->encode($test->src));
        }
    }

    function testVerify() {
        $tests = json_decode(file_get_contents('verify.json'));

        foreach ($tests as $test) {
            $time = strtotime($test->now);
            $fernet = $this->getVerifyInstance($test->secret, $time);
            $this->assertEquals($test->src, $fernet->decode($test->token, $test->ttl_sec));
        }
    }

    function testInvalid() {
        $tests = json_decode(file_get_contents('invalid.json'));

        foreach ($tests as $test) {
            $time = strtotime($test->now);
            $fernet = $this->getVerifyInstance($test->secret, $time);
            $this->assertEquals(null, $fernet->decode($test->token, $test->ttl_sec));
        }
    }
}

?>